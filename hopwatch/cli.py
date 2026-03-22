"""HopWatch — command-line entry point."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from typing import Optional

from .anomaly import detect
from .alternatives import (
    explain_route, find_alternatives, find_alternatives_combined,
    find_alternatives_stat, asn_name,
)
from .enrich import annotate_many
from .probe import Hop, trace

# Optional pretty terminal — degrade gracefully if missing.
try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except ModuleNotFoundError:
    _RICH = False


def _print_plain(hops, infos):
    print(f"\n{'#':>3} {'IP':<16} {'RTT(ms)':>8} {'LOSS':>5}  "
          f"{'ASN':<8} {'OWNER':<28} {'COUNTRY':>3}  NOTES")
    print("-" * 95)
    for h, info in zip(hops, infos):
        ip = h.ip or "*"
        rtt = f"{h.median_rtt:.1f}" if h.median_rtt is not None else "  -  "
        loss = f"{h.loss}/{h.probes_sent}"
        asn = f"AS{info.asn}" if info.asn else "--"
        owner = (info.name or "")[:28]
        country = info.country or "--"
        notes = []
        if h.mpls_labels:
            notes.append(f"MPLS {','.join(map(str, h.mpls_labels[:3]))}")
        if h.hostname:
            notes.append(h.hostname[:30])
        print(f"{h.ttl:>3} {ip:<16} {rtt:>8} {loss:>5}  "
              f"{asn:<8} {owner:<28} {country:>3}  {' | '.join(notes)}")


def _print_rich(hops, infos):
    c = Console()
    t = Table(title=None, show_lines=False, expand=False)
    t.add_column("#", justify="right", style="cyan")
    t.add_column("IP", style="white")
    t.add_column("RTT(ms)", justify="right")
    t.add_column("Loss", justify="right")
    t.add_column("ASN")
    t.add_column("Owner")
    t.add_column("CC", justify="center")
    t.add_column("Notes")
    for h, info in zip(hops, infos):
        ip = h.ip or "[dim]*[/dim]"
        rtt = f"{h.median_rtt:.1f}" if h.median_rtt is not None else "-"
        loss = f"{h.loss}/{h.probes_sent}"
        asn = f"AS{info.asn}" if info.asn else "[dim]--[/dim]"
        owner = (info.name or "")[:32]
        cc = info.country or "--"
        notes = []
        if h.mpls_labels:
            notes.append(f"MPLS {','.join(map(str, h.mpls_labels[:3]))}")
        if h.hostname:
            notes.append(h.hostname[:32])
        t.add_row(str(h.ttl), ip, rtt, loss, asn, owner, cc, " · ".join(notes))
    c.print(t)


def _format_alerts(alerts):
    if not alerts:
        print("\nNo anomalies detected.\n")
        return
    print("\n── Anomalies ──")
    for a in alerts:
        tag = {"info": "ℹ ", "warn": "⚠ ", "high": "✖ "}.get(a.severity, "·")
        print(f"  {tag} [{a.severity:>4}] hop {a.hop_ttl}: {a.message}")
    print()


def _format_alternatives(target_ip: str, paths):
    if not paths:
        print("\nNo alternative paths found (try --source both, or remove "
              "the --country filter).\n")
        return
    print(f"\n── Alternative AS paths to {target_ip} ──")
    for p in paths:
        chain = " → ".join(f"AS{a}" for a in p.as_path)
        names = " · ".join(p.as_names[:5])
        rrc = f" [{p.seen_at}]" if p.seen_at and p.seen_at.startswith("RRC") else ""
        src = f"{p.source_name} (AS{p.source_asn}, {p.source_country or '??'})"
        print(f"  via {src}{rrc}")
        print(f"      {chain}")
        print(f"      {names}")
        print()


def _format_why(target: str, why: Optional[dict]):
    if not why:
        print("\nLooking-glass data unavailable for this target.\n")
        return
    print(f"\n── BGP looking-glass for prefix {why.get('prefix')} ──")
    for rrc in why["rrcs"]:
        loc = rrc.get("location") or rrc.get("rrc")
        path = " → ".join(rrc.get("shortest_as_path") or [])
        print(f"  {rrc.get('rrc'):<6}  ({loc})")
        print(f"          {path}")
        print()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_trace(args):
    print(f"\nHopWatch — tracing {args.target} via {args.protocol.upper()} "
          f"(probes={args.probes}, timeout={args.timeout}s)")
    target_ip = socket.gethostbyname(args.target)
    print(f"resolved to {target_ip}")
    t0 = time.perf_counter()
    hops = trace(args.target,
                 protocol=args.protocol,
                 max_ttl=args.max_ttl,
                 probes=args.probes,
                 timeout=args.timeout,
                 force_subprocess=args.subprocess)
    elapsed = time.perf_counter() - t0
    infos = annotate_many([h.ip for h in hops])
    if _RICH:
        _print_rich(hops, infos)
    else:
        _print_plain(hops, infos)
    print(f"\n{len(hops)} hops, {elapsed:.1f}s")

    alerts = detect(hops, infos)
    _format_alerts(alerts)

    if args.alternatives:
        paths = find_alternatives_combined(args.target, country=args.country,
                                           source=args.source,
                                           max_paths=args.max_alternatives)
        _format_alternatives(target_ip, paths)

    if args.why:
        why = explain_route(args.target)
        _format_why(args.target, why)


def cmd_why(args):
    why = explain_route(args.target)
    _format_why(args.target, why)


def cmd_alternatives(args):
    target_ip = socket.gethostbyname(args.target)
    paths = find_alternatives_combined(args.target, country=args.country,
                                       source=args.source,
                                       max_paths=args.max)
    _format_alternatives(target_ip, paths)


# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(prog="hopwatch",
                                description="Cross-ISP route probe with "
                                "AS / BGP enrichment.")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("trace", help="Run a traceroute with enrichment.")
    t.add_argument("target")
    t.add_argument("--protocol", choices=["icmp", "udp", "tcp"], default="icmp")
    t.add_argument("--probes", type=int, default=3)
    t.add_argument("--max-ttl", type=int, default=30)
    t.add_argument("--timeout", type=float, default=2.0)
    t.add_argument("--alternatives", action="store_true",
                   help="Show counterfactual AS paths from other ISPs.")
    t.add_argument("--why", action="store_true",
                   help="Print BGP looking-glass paths from RIPE RRCs.")
    t.add_argument("--country", default=None,
                   help="Filter alternative paths to this country code "
                        "(e.g. BR, US, DE).")
    t.add_argument("--max-alternatives", type=int, default=8)
    t.add_argument("--source", choices=["stat", "atlas", "both"], default="stat",
                   help="Where to pull alternative paths from. 'stat' = RIPE "
                        "Stat looking-glass (fast, broad BGP coverage). "
                        "'atlas' = RIPE Atlas measurements (slower, real "
                        "traceroutes). Default: stat.")
    t.add_argument("--subprocess", action="store_true",
                   help="Force shell-out to system traceroute "
                        "(no raw sockets required).")
    t.set_defaults(func=cmd_trace)

    a = sub.add_parser("alternatives",
                       help="Just print alternative AS paths to a target.")
    a.add_argument("target")
    a.add_argument("--country", default=None)
    a.add_argument("--source", choices=["stat", "atlas", "both"], default="stat")
    a.add_argument("--max", type=int, default=12)
    a.set_defaults(func=cmd_alternatives)

    w = sub.add_parser("why",
                       help="BGP looking-glass: how do various RIPE RRCs "
                            "reach this destination?")
    w.add_argument("target")
    w.set_defaults(func=cmd_why)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
