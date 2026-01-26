"""
HopWatch — counterfactual routing.

Given a target IP / hostname, fetch other AS paths to the same destination
seen from different vantage points. We use:

- **RIPE Atlas** (``atlas.ripe.net``) — anonymous, no key required. Search
  recent traceroute measurements pointing at the same ``target`` IP and
  group the results by source ASN, so you see "if you had been a customer
  of ISP X, your packet would follow this path".
- **bgp.tools** (``bgp.tools/json``) — free read-only JSON endpoints. Used
  to look up AS names and immediate AS neighbours.
- **RIPE Stat looking glass** (``stat.ripe.net``) — BGP RIB views from RRC
  collectors spread around the world. Used for the ``why`` command.

All requests are best-effort with short timeouts; missing data degrades to
``None`` rather than crashing.
"""
from __future__ import annotations

import json
import socket
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

_VERBOSE = True


def _log(msg: str) -> None:
    if _VERBOSE:
        print(f"  [alt] {msg}", file=sys.stderr, flush=True)

UA = "HopWatch/0.1 (+https://github.com/Nandobez/HopWatch)"
TIMEOUT = 6.0


def _get_json(url: str) -> Optional[dict]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AlternativePath:
    source_asn: int
    source_name: str
    source_country: str
    as_path: list[int]
    as_names: list[str]
    probe_id: int
    seen_at: Optional[str] = None


# ---------------------------------------------------------------------------
# RIPE Atlas — public measurement search
# ---------------------------------------------------------------------------

def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def _atlas_search_measurements(target: str,
                                target_ip: str,
                                af: int = 4,
                                msm_type: str = "traceroute",
                                page_size: int = 80) -> list[dict]:
    """Find recent public Atlas measurements that target this destination.

    We try two queries in order: exact ``target_ip`` (cheap), and then
    ``target`` hostname (catches anycast deployments where each Atlas probe
    resolves the name to a different IP).
    """
    queries = [
        {"type": msm_type, "target_ip": target_ip, "af": af, "page_size": page_size},
        {"type": msm_type, "target": target,        "af": af, "page_size": page_size},
    ]
    seen: dict[int, dict] = {}
    for params in queries:
        qs = urllib.parse.urlencode(params)
        data = _get_json(f"https://atlas.ripe.net/api/v2/measurements/?{qs}")
        if not data:
            continue
        for m in (data.get("results") or []):
            seen.setdefault(m["id"], m)
        if len(seen) >= page_size:
            break
    # Prefer ongoing measurements but fall back to anything else.
    return sorted(seen.values(),
                  key=lambda m: 0 if m.get("status", {}).get("name") == "Ongoing" else 1)


def _atlas_latest_results(measurement_id: int, n: int = 20) -> list[dict]:
    qs = urllib.parse.urlencode({"latest": "true"})
    data = _get_json(f"https://atlas.ripe.net/api/v2/measurements/"
                     f"{measurement_id}/latest/?{qs}")
    if isinstance(data, list):
        return data[:n]
    return []


def _atlas_probe_info(probe_id: int) -> Optional[dict]:
    return _get_json(f"https://atlas.ripe.net/api/v2/probes/{probe_id}/")


# ---------------------------------------------------------------------------
# bgp.tools — quick ASN lookup
# ---------------------------------------------------------------------------

def asn_name(asn: int) -> Optional[str]:
    """Look up an AS name. Tries Cymru DNS first (fast, no rate limit) and
    falls back to bgpview.io only if Cymru can't answer.
    """
    from .enrich import _cymru_asname
    name = _cymru_asname(asn)
    if name:
        return name
    data = _get_json(f"https://api.bgpview.io/asn/{asn}")
    if data and data.get("status") == "ok":
        return (data["data"] or {}).get("name")
    return None


# ---------------------------------------------------------------------------
# Path extraction
# ---------------------------------------------------------------------------

def _path_from_atlas_result(result: dict, target_ip: str) -> list[int]:
    """Pull the chain of distinct ASNs out of one traceroute measurement.

    Atlas results don't include ASN per hop, but each hop has the IP. We
    look every IP up via DNS-based Cymru (used by ``hopwatch.enrich``) but
    here we use a lightweight inline version that avoids importing dns
    eagerly (RIPE Atlas results can be 30+ hops each).
    """
    from .enrich import _cymru_asn   # lazy import — needs dnspython
    # Pick at most one IP per TTL, then look up ASN.
    ips: list[str] = []
    for h in (result.get("result") or []):
        for probe in h.get("result", []):
            ip = probe.get("from")
            if ip:
                ips.append(ip)
                break
    # Parallelise the DNS lookups.
    seen: set[int] = set()
    path: list[int] = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for ip, info in zip(ips, ex.map(_cymru_asn, ips)):
            if not info:
                continue
            asn = info[0]
            if asn and asn not in seen:
                seen.add(asn)
                path.append(asn)
    return path


def find_alternatives(target: str,
                      *,
                      country: Optional[str] = None,
                      max_paths: int = 10,
                      max_measurements: int = 5,
                      max_results_per_msm: int = 8,
                      max_workers: int = 8) -> list[AlternativePath]:
    """Return a list of distinct AS paths to ``target`` seen from various
    RIPE Atlas probes. Parallelises HTTP + DNS lookups for responsiveness.
    """
    target_ip = _resolve(target)
    _log(f"resolved {target} -> {target_ip}")
    _log("searching RIPE Atlas measurements…")
    measurements = _atlas_search_measurements(target, target_ip)
    _log(f"found {len(measurements)} measurements; "
         f"sampling top {max_measurements}")
    measurements = measurements[:max_measurements]

    # 1) Pull recent results from every measurement in parallel.
    candidates: list[tuple[int, dict]] = []   # (probe_id, result)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_msm = {ex.submit(_atlas_latest_results, m["id"],
                                    max_results_per_msm): m["id"]
                          for m in measurements}
        for fut in as_completed(future_to_msm):
            try:
                results = fut.result()
            except Exception:
                results = []
            for r in results:
                pid = r.get("prb_id")
                if pid is not None:
                    candidates.append((pid, r))
    _log(f"collected {len(candidates)} probe results")

    # 2) Fetch probe metadata + country filter in parallel.
    unique_probe_ids = sorted({pid for pid, _ in candidates})
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        probe_info = dict(zip(unique_probe_ids,
                              ex.map(_atlas_probe_info, unique_probe_ids)))
    matched = []
    for pid, result in candidates:
        info = probe_info.get(pid) or {}
        src_country = (info.get("country_code") or "").upper()
        if country and src_country != country.upper():
            continue
        src_asn = info.get("asn_v4") or info.get("asn_v6")
        if not src_asn:
            continue
        matched.append((pid, result, int(src_asn), src_country))
    _log(f"{len(matched)} probes match country filter "
         f"{country!r}; extracting AS paths…")

    # 3) Extract AS paths in parallel (most expensive step: DNS Cymru lookups).
    def _extract(pid, result):
        return pid, _path_from_atlas_result(result, target_ip)

    paths_by_pid: dict[int, list[int]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = [ex.submit(_extract, pid, r) for pid, r, _, _ in matched]
        for fut in as_completed(futs):
            try:
                pid, p = fut.result()
            except Exception:
                continue
            if len(p) >= 2:
                paths_by_pid[pid] = p

    # 4) Resolve ASN names for every distinct ASN in one batch.
    all_asns = {asn for p in paths_by_pid.values() for asn in p}
    all_asns |= {asn for _, _, asn, _ in matched}
    name_cache: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for asn, name in zip(all_asns, ex.map(asn_name, all_asns)):
            name_cache[asn] = name or f"AS{asn}"

    # 5) Build AlternativePath objects, dedupe by AS-sequence.
    deduped: dict[tuple, AlternativePath] = {}
    for pid, result, src_asn, src_country in matched:
        path = paths_by_pid.get(pid)
        if not path:
            continue
        key = tuple(path)
        if key in deduped:
            continue
        deduped[key] = AlternativePath(
            source_asn=src_asn,
            source_name=name_cache.get(src_asn) or f"AS{src_asn}",
            source_country=src_country,
            as_path=path,
            as_names=[name_cache.get(a) or f"AS{a}" for a in path],
            probe_id=pid,
            seen_at=str(result.get("timestamp") or ""),
        )
        if len(deduped) >= max_paths:
            break
    _log(f"deduped to {len(deduped)} distinct AS paths")
    return list(deduped.values())


# ---------------------------------------------------------------------------
# RIPE Stat looking-glass — counterfactual paths via BGP RRC collectors
# ---------------------------------------------------------------------------

# RRC ids whose collectors are physically located in (or near) Brazil. The
# RIPE RRC15 collector lives at IX.br São Paulo and peers with most major
# Brazilian carriers, so it's our best source of BR-anchored paths.
_RRC_COUNTRY: dict[str, str] = {
    "RRC00": "NL", "RRC01": "GB", "RRC03": "NL", "RRC04": "CH",
    "RRC05": "AT", "RRC06": "JP", "RRC07": "SE", "RRC10": "IT",
    "RRC11": "US", "RRC12": "DE", "RRC13": "RU", "RRC14": "US",
    "RRC15": "BR", "RRC16": "US", "RRC18": "BR", "RRC19": "ZA",
    "RRC20": "ZA", "RRC21": "FR", "RRC22": "BG", "RRC23": "SG",
    "RRC24": "EG", "RRC25": "NL", "RRC26": "AE",
}


def find_alternatives_stat(target: str,
                            *,
                            country: Optional[str] = None,
                            max_paths: int = 12,
                            max_workers: int = 8) -> list[AlternativePath]:
    """Pull alternative AS paths from RIPE Stat's looking-glass.

    The looking-glass endpoint returns BGP RIB entries from every RRC
    collector for the prefix containing ``target``. Each peer of each
    collector contributes an AS-path; we keep the most-specific distinct
    paths and tag them with the source ASN.
    """
    target_ip = _resolve(target)
    _log(f"querying RIPE Stat looking-glass for {target_ip}…")
    payload = _get_json(
        f"https://stat.ripe.net/data/looking-glass/data.json"
        f"?resource={target_ip}"
    )
    if not payload or payload.get("status") != "ok":
        _log("RIPE Stat returned no data")
        return []
    data = payload.get("data") or {}
    rrcs = data.get("rrcs") or []
    _log(f"{len(rrcs)} RRC collectors returned peers")

    paths_raw: list[tuple[str, list[int]]] = []  # (rrc_id, as_path)
    for rrc in rrcs:
        rrc_id = rrc.get("rrc") or ""
        peers = rrc.get("peers") or []
        for peer in peers:
            as_path_str = peer.get("as_path") or ""
            asns = []
            for tok in as_path_str.split():
                # collapse AS sets like "{15169}" and skip the source's own ASN
                tok = tok.strip("{}")
                if tok.isdigit():
                    asn = int(tok)
                    if not asns or asns[-1] != asn:    # de-dup adjacent
                        asns.append(asn)
            if len(asns) >= 2:
                paths_raw.append((rrc_id, asns))

    # If a country filter is set, prefer paths whose RRC is in that country.
    if country:
        wanted = country.upper()
        primary = [p for p in paths_raw if _RRC_COUNTRY.get(p[0]) == wanted]
        if primary:
            paths_raw = primary

    # Deduplicate by (source_asn, as_path tail)
    deduped: dict[tuple, tuple[str, list[int]]] = {}
    for rrc_id, asns in paths_raw:
        key = (asns[0], tuple(asns[-3:]))
        if key not in deduped:
            deduped[key] = (rrc_id, asns)

    # Resolve names for distinct ASNs in parallel.
    distinct_asns = {asn for _, asns in deduped.values() for asn in asns}
    name_cache: dict[int, str] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for asn, name in zip(distinct_asns, ex.map(asn_name, distinct_asns)):
            name_cache[asn] = name or f"AS{asn}"

    out: list[AlternativePath] = []
    for (src_asn, _), (rrc_id, asns) in list(deduped.items())[:max_paths]:
        out.append(AlternativePath(
            source_asn=src_asn,
            source_name=name_cache.get(src_asn) or f"AS{src_asn}",
            source_country=_RRC_COUNTRY.get(rrc_id, ""),
            as_path=asns,
            as_names=[name_cache.get(a) or f"AS{a}" for a in asns],
            probe_id=0,
            seen_at=rrc_id,
        ))
    _log(f"extracted {len(out)} distinct paths from RIPE Stat")
    return out


# ---------------------------------------------------------------------------
# Combined entry point — Atlas + Stat, country-aware
# ---------------------------------------------------------------------------

def find_alternatives_combined(target: str,
                                *,
                                country: Optional[str] = None,
                                source: str = "both",
                                max_paths: int = 12) -> list[AlternativePath]:
    """Run both Atlas and Stat lookups and merge the results.

    ``source`` is ``"atlas"``, ``"stat"`` or ``"both"``.
    """
    stat_paths: list[AlternativePath] = []
    atlas_paths: list[AlternativePath] = []
    if source in ("stat", "both"):
        try:
            stat_paths = find_alternatives_stat(target, country=country,
                                                max_paths=max_paths)
        except Exception as e:                                  # noqa: BLE001
            _log(f"stat lookup failed: {e}")
    if source in ("atlas", "both"):
        try:
            atlas_paths = find_alternatives(target, country=country,
                                            max_paths=max_paths)
        except Exception as e:                                  # noqa: BLE001
            _log(f"atlas lookup failed: {e}")

    # Stat first (BR-friendly via RRC15), then atlas. Deduplicate.
    out: list[AlternativePath] = []
    seen: set[tuple] = set()
    for p in stat_paths + atlas_paths:
        key = (p.source_asn, tuple(p.as_path))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
        if len(out) >= max_paths:
            break
    return out


# ---------------------------------------------------------------------------
# Why: BGP looking-glass via RIPE Stat
# ---------------------------------------------------------------------------

def explain_route(target: str) -> Optional[dict]:
    """Return a dict with the AS-paths different RIPE RRC collectors see
    for the most-specific prefix containing ``target``.
    """
    target_ip = _resolve(target)
    data = _get_json(
        f"https://stat.ripe.net/data/looking-glass/data.json?resource={target_ip}"
    )
    if not data or data.get("status") != "ok":
        return None
    payload = data.get("data") or {}
    summary = []
    for rrc in payload.get("rrcs") or []:
        as_paths = []
        for peer in rrc.get("peers") or []:
            as_path = peer.get("as_path") or ""
            as_paths.append(as_path.split())
        # most common path from this collector
        if not as_paths:
            continue
        as_paths.sort(key=len)
        summary.append({
            "rrc": rrc.get("rrc"),
            "location": rrc.get("location"),
            "shortest_as_path": as_paths[0],
            "n_peers": len(rrc.get("peers") or []),
        })
    return {"prefix": payload.get("prefix"), "rrcs": summary}
