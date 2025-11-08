"""
HopWatch — probe layer.

Multi-protocol traceroute:
  - ICMP (default; needs root / CAP_NET_RAW)
  - UDP  (classic traceroute, ports 33434+)
  - TCP  (SYN probe, useful where ICMP is filtered)

Each hop is probed `probes` times and we keep the median RTT plus loss.

Fallback path: when scapy / raw sockets are not usable we shell out to the
system ``traceroute`` binary and parse its output. That lets the rest of the
toolchain (enrichment, alternatives) work without root in containers / CI.
"""
from __future__ import annotations

import os
import re
import socket
import statistics
import subprocess
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Hop:
    ttl: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    rtt_ms: list[float] = field(default_factory=list)   # raw samples
    mpls_labels: list[int] = field(default_factory=list)
    loss: int = 0
    probes_sent: int = 0

    @property
    def median_rtt(self) -> Optional[float]:
        return statistics.median(self.rtt_ms) if self.rtt_ms else None

    @property
    def jitter(self) -> Optional[float]:
        return statistics.pstdev(self.rtt_ms) if len(self.rtt_ms) > 1 else None

    def to_dict(self) -> dict:
        return {
            "ttl": self.ttl, "ip": self.ip, "hostname": self.hostname,
            "median_rtt_ms": self.median_rtt, "jitter_ms": self.jitter,
            "loss": self.loss, "probes_sent": self.probes_sent,
            "mpls_labels": self.mpls_labels,
        }


# ---------------------------------------------------------------------------
# Scapy-based probes (preferred)
# ---------------------------------------------------------------------------

def _have_scapy() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


def _scapy_trace(target: str, *, max_ttl: int, probes: int, timeout: float,
                 protocol: str, dst_port: int) -> list[Hop]:
    """Run a TTL-stepped trace using scapy. Returns the *first* hop responding
    at each TTL plus all RTT samples.
    """
    from scapy.all import IP, ICMP, UDP, TCP, sr1, conf
    conf.verb = 0

    hops: dict[int, Hop] = {}
    for ttl in range(1, max_ttl + 1):
        for _ in range(probes):
            t0 = time.perf_counter()
            if protocol == "icmp":
                pkt = IP(dst=target, ttl=ttl) / ICMP(id=os.getpid() & 0xFFFF, seq=ttl)
            elif protocol == "udp":
                pkt = IP(dst=target, ttl=ttl) / UDP(dport=dst_port + ttl)
            elif protocol == "tcp":
                pkt = IP(dst=target, ttl=ttl) / TCP(dport=dst_port, flags="S")
            else:
                raise ValueError(protocol)
            reply = sr1(pkt, timeout=timeout, verbose=0)
            rtt = (time.perf_counter() - t0) * 1000
            h = hops.setdefault(ttl, Hop(ttl=ttl))
            h.probes_sent += 1
            if reply is None:
                h.loss += 1
                continue
            # First response sets ip/hostname
            if h.ip is None:
                h.ip = reply.src
                try:
                    h.hostname = socket.gethostbyaddr(reply.src)[0]
                except Exception:
                    h.hostname = None
                # Parse MPLS extensions (ICMP extension header — RFC 4950)
                if reply.haslayer(ICMP):
                    raw = bytes(reply[ICMP].payload)
                    h.mpls_labels.extend(_parse_mpls(raw))
            h.rtt_ms.append(rtt)
            # if reached the target we can stop probing this ttl
            if reply.src == target:
                pass
        # Early exit: target reached
        if hops.get(ttl) and hops[ttl].ip == target:
            break
    return [hops[t] for t in sorted(hops)]


def _parse_mpls(payload: bytes) -> list[int]:
    """Very loose parse of MPLS labels embedded in the ICMP extension area."""
    labels: list[int] = []
    # MPLS extension headers (RFC 4950) follow the original packet quoted in
    # the ICMP Time Exceeded response. Each label is a 32-bit field where the
    # top 20 bits are the label.
    for i in range(0, len(payload) - 3, 4):
        word = int.from_bytes(payload[i:i + 4], "big")
        label = word >> 12
        # heuristic: real labels are between 16 and 1048575
        if 16 <= label < (1 << 20):
            labels.append(label)
    # de-dupe in order
    seen, out = set(), []
    for l in labels[:8]:   # cap at 8 labels per hop
        if l not in seen:
            seen.add(l); out.append(l)
    return out


# ---------------------------------------------------------------------------
# Subprocess fallback (system traceroute)
# ---------------------------------------------------------------------------

_TRACEROUTE_LINE = re.compile(
    r"^\s*(?P<ttl>\d+)\s+(?P<rest>.+)$"
)
_PROBE = re.compile(
    r"(?P<host>[\w.\-]+)\s+\((?P<ip>[\d.]+)\)\s+(?P<rtt>[\d.]+)\s*ms"
)


def _have(binary: str) -> bool:
    from shutil import which
    return which(binary) is not None


def _system_trace(target: str, *, max_ttl: int, probes: int, timeout: float,
                  protocol: str, dst_port: int) -> list[Hop]:
    """Shell-out to whichever traceroute-like binary is available.

    Order of preference:
        traceroute → mtr (one-shot) → tracepath
    """
    backend: str
    if _have("traceroute"):
        backend = "traceroute"
        flag = {"icmp": "-I", "udp": "", "tcp": "-T"}[protocol]
        cmd = ["traceroute", "-n", "-m", str(max_ttl), "-q", str(probes),
               "-w", str(int(timeout))]
        if flag:
            cmd.append(flag)
        if protocol in ("udp", "tcp"):
            cmd += ["-p", str(dst_port)]
        cmd.append(target)
    elif _have("mtr"):
        backend = "mtr"
        cmd = ["mtr", "-n", "-r", "-c", str(probes), "-m", str(max_ttl), target]
    elif _have("tracepath"):
        backend = "tracepath"
        cmd = ["tracepath", "-n", "-m", str(max_ttl), target]
    else:
        raise RuntimeError(
            "No traceroute backend found. Install one of: traceroute, mtr, "
            "tracepath. Or run as root with scapy installed."
        )
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT,
                                      timeout=max_ttl * (timeout + 1))
    except subprocess.CalledProcessError as e:
        out = e.output
    by_ttl: dict[int, Hop] = {}
    for line in out.splitlines():
        if backend == "mtr":
            # `  3.|-- 172.16.130.42   0.0%   2   3.9   2.6   1.4   3.9   1.7`
            m = re.match(r"\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+"
                         r"([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", line)
            if not m:
                continue
            ttl = int(m.group(1)); ip = m.group(2)
            if ttl > max_ttl:
                continue
            h = by_ttl.setdefault(ttl, Hop(ttl=ttl, probes_sent=probes))
            loss_pct = float(m.group(3))
            snt = int(m.group(4))
            avg_rtt = float(m.group(6))
            best = float(m.group(7))
            worst = float(m.group(8))
            received = snt - int(round(snt * loss_pct / 100))
            if ip != "???":
                h.ip = ip
            # Approximate per-probe RTT list (mtr only reports aggregates).
            if received >= 2:
                h.rtt_ms.extend([best, worst][:received] + [avg_rtt] * max(0, received - 2))
            elif received == 1:
                h.rtt_ms.append(avg_rtt)
            h.loss = snt - received
            h.probes_sent = snt
        else:
            # traceroute / tracepath: leading number, dotted IP, rtt with "ms"
            m = re.match(r"\s*(\d+)[\.\?:|\s]+(?P<rest>.+)$", line)
            if not m:
                continue
            try:
                ttl = int(m.group(1))
            except ValueError:
                continue
            rest = m.group("rest")
            if ttl > max_ttl:
                continue
            h = by_ttl.setdefault(ttl, Hop(ttl=ttl, probes_sent=probes))
            ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            if ip_m and not h.ip:
                h.ip = ip_m.group(1)
            for rtt_m in re.finditer(r"([\d.]+)\s*ms", rest):
                h.rtt_ms.append(float(rtt_m.group(1)))
    hops: list[Hop] = []
    for ttl in sorted(by_ttl):
        h = by_ttl[ttl]
        if backend != "mtr":
            h.loss = max(0, probes - len(h.rtt_ms))
        if h.ip and not h.hostname:
            try:
                h.hostname = socket.gethostbyaddr(h.ip)[0]
            except Exception:
                pass
        hops.append(h)
        if h.ip == target:
            break
    return hops


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def trace(target: str,
          *,
          protocol: str = "icmp",
          max_ttl: int = 30,
          probes: int = 3,
          timeout: float = 2.0,
          dst_port: int = 33434,
          force_subprocess: bool = False) -> list[Hop]:
    """Trace a route to ``target``. Returns one Hop per TTL.

    ``protocol`` is one of ``"icmp"``, ``"udp"``, ``"tcp"``.
    """
    target_ip = socket.gethostbyname(target)
    if not force_subprocess and _have_scapy() and (os.geteuid() == 0 if hasattr(os, "geteuid") else True):
        try:
            return _scapy_trace(target_ip, max_ttl=max_ttl, probes=probes,
                                timeout=timeout, protocol=protocol, dst_port=dst_port)
        except PermissionError:
            pass
    return _system_trace(target_ip, max_ttl=max_ttl, probes=probes,
                         timeout=timeout, protocol=protocol, dst_port=dst_port)
