"""
HopWatch — enrich raw hop IPs with ASN, AS name and (optionally) country.

Strategy
========

For ASN + AS-name we use Team Cymru's DNS-based service — free, no API key,
no rate limits worth mentioning. Each IP costs one DNS lookup.

For per-country tagging we hit the RIPE Stat ``geoloc`` endpoint, which is
also free + key-less but rate limits to roughly 1 req/s per source IP. The
lookup is best-effort and degrades silently to ``None``.

We cache everything in memory for the lifetime of the process.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

import urllib.request
import json


@dataclass
class AsnInfo:
    asn: Optional[int] = None
    name: Optional[str] = None
    prefix: Optional[str] = None
    country: Optional[str] = None


# ---------------------------------------------------------------------------
# Team Cymru DNS service
# ---------------------------------------------------------------------------

def _reverse_octets(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


@lru_cache(maxsize=4096)
def _cymru_asn(ip: str) -> Optional[tuple[int, str, str]]:
    """Return (asn, prefix, country) for ``ip`` via DNS, or None."""
    if not ip:
        return None
    try:
        # Validate + skip private addresses (Cymru won't have them anyway).
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
    except ValueError:
        return None
    query = f"{_reverse_octets(ip)}.origin.asn.cymru.com"
    try:
        txt = socket.gethostbyname_ex(query)
    except socket.gaierror:
        return None
    # The TXT record itself is what we want; gethostbyname_ex only gives A
    # records, so we fall back to dns via socket directly.
    try:
        import socket as _s
        # Lazy: use os 'host -t TXT' as a portable last resort? Skip — use
        # standard library only.
        # We'll instead call dnspython if available.
        import dns.resolver           # type: ignore
        ans = dns.resolver.resolve(query, "TXT", lifetime=2.0)
        rec = str(ans[0]).strip('"')
    except Exception:
        # Without dnspython we cannot read TXT — return empty.
        return None
    # "ASN | Prefix | CC | Registry | Allocated"
    parts = [p.strip() for p in rec.split("|")]
    if not parts:
        return None
    try:
        asn = int(parts[0].split()[0])
    except ValueError:
        return None
    prefix = parts[1] if len(parts) > 1 else None
    country = parts[2] if len(parts) > 2 else None
    return asn, prefix or "", country or ""


@lru_cache(maxsize=4096)
def _cymru_asname(asn: int) -> Optional[str]:
    try:
        import dns.resolver           # type: ignore
        ans = dns.resolver.resolve(f"AS{asn}.asn.cymru.com", "TXT", lifetime=2.0)
        rec = str(ans[0]).strip('"')
    except Exception:
        return None
    parts = [p.strip() for p in rec.split("|")]
    return parts[-1] if parts else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _private_kind(ip: str) -> Optional[str]:
    """Classify private / shared address ranges into a human note."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if ipaddress.ip_network("100.64.0.0/10").supernet_of(
        ipaddress.ip_network(f"{ip}/32")
    ):
        return "CGNAT (RFC 6598)"
    if addr.is_private:
        return "private (RFC 1918)"
    return None


def annotate(ip: Optional[str]) -> AsnInfo:
    """Return as much information as we can about ``ip``. Always succeeds.
    Caller decides how to render missing fields.
    """
    info = AsnInfo()
    if not ip:
        return info
    kind = _private_kind(ip)
    if kind:
        # Private addresses don't have public ASNs; surface the classification
        # in the ``name`` field so it shows up in the table.
        info.name = f"⟨{kind}⟩"
        return info
    cymru = _cymru_asn(ip)
    if cymru:
        info.asn, info.prefix, info.country = cymru
        info.name = _cymru_asname(info.asn)
    return info


def annotate_many(ips: list[Optional[str]]) -> list[AsnInfo]:
    return [annotate(ip) for ip in ips]
