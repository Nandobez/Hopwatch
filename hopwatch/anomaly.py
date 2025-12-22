"""
HopWatch — anomaly detection on a finished trace.

We look for a handful of patterns that usually indicate something interesting:

- **filtered hops** — consecutive ``*`` replies (firewall / ACL)
- **AS loops** — same AS appears, disappears, reappears later in the path
  (route leaks, fall-back via private peering)
- **RTT inversion** — hop N+1 reports a shorter RTT than hop N
  (asymmetric routes, MPLS LSP hiding hops)
- **MPLS detected** — surface the labels so the reader knows the operator
  uses an MPLS backbone
- **high packet loss** — > 33 % loss on any hop that isn't the destination
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .enrich import AsnInfo
from .probe import Hop


@dataclass
class Alert:
    severity: str        # "info" | "warn" | "high"
    hop_ttl: int
    message: str


def detect(hops: list[Hop], asn_info: list[AsnInfo]) -> list[Alert]:
    alerts: list[Alert] = []

    # 1) Filtered hops
    run = 0
    for h in hops:
        if h.ip is None:
            run += 1
            if run >= 2:
                alerts.append(Alert("warn", h.ttl,
                                    f"{run} consecutive filtered hops "
                                    "(firewall or ACL ahead)"))
        else:
            run = 0

    # 2) AS loops + transitions
    last_asn: int | None = None
    seen_asns: dict[int, int] = {}
    for h, a in zip(hops, asn_info):
        if a.asn is None:
            continue
        if last_asn is not None and a.asn != last_asn:
            if a.asn in seen_asns:
                alerts.append(Alert("warn", h.ttl,
                                    f"AS {a.asn} ({a.name}) re-appears "
                                    f"after leaving at hop {seen_asns[a.asn]} "
                                    "— possible route leak / asymmetric path"))
        seen_asns[a.asn] = h.ttl
        last_asn = a.asn

    # 3) RTT inversion
    prev_rtt = None
    prev_ttl = None
    for h in hops:
        if h.median_rtt is None:
            continue
        if prev_rtt is not None and h.median_rtt + 1 < prev_rtt:
            alerts.append(Alert("info", h.ttl,
                                f"RTT inversion: hop {prev_ttl} "
                                f"({prev_rtt:.1f}ms) > hop {h.ttl} "
                                f"({h.median_rtt:.1f}ms) — asymmetric/MPLS"))
        prev_rtt = h.median_rtt
        prev_ttl = h.ttl

    # 4) MPLS
    for h in hops:
        if h.mpls_labels:
            alerts.append(Alert("info", h.ttl,
                                f"MPLS labels seen: {h.mpls_labels}"))

    # 5) Loss
    target_ttl = max((h.ttl for h in hops if h.ip), default=None)
    for h in hops:
        if h.probes_sent == 0:
            continue
        loss_pct = h.loss / h.probes_sent
        if loss_pct > 0.33 and h.ttl != target_ttl and h.ip:
            alerts.append(Alert("warn", h.ttl,
                                f"{int(loss_pct * 100)}% packet loss "
                                f"(hop responsive but rate-limiting ICMP)"))

    return alerts
