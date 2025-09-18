<div align="center">

<pre>
██╗  ██╗ ██████╗ ██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██║  ██║██╔═══██╗██╔══██╗██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
███████║██║   ██║██████╔╝██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔══██║██║   ██║██╔═══╝ ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║  ██║╚██████╔╝██║     ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
</pre>

### Cross-ISP route probe with AS-level enrichment + counterfactual paths

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](./LICENSE)

</div>

HopWatch traces the path a packet takes to a destination, annotates every hop
with its **autonomous system** and owner, flags anomalies (filtered hops, AS
loops, RTT inversions, MPLS), and — uniquely — shows **what other ISPs would
have done with the same packet** by mining public RIPE Atlas measurements.

## Install

```bash
# minimal
pip install -e .

# with pretty terminal + scapy-based raw-socket probes
pip install -e .[fancy]
```

### Backends and privileges

HopWatch picks the first available backend in this order:

1. **scapy** (raw sockets) — needs ``sudo`` or ``CAP_NET_RAW``, supports
   ICMP / UDP / TCP probes natively.
2. **traceroute** binary.
3. **mtr** in report mode.
4. **tracepath** — works without root.

Use ``--subprocess`` to force a shell-out path. Most distros already ship
``mtr`` or ``tracepath``.

## Quick usage

```bash
# basic trace (auto-detects the best available backend)
hopwatch trace 1.1.1.1

# add alternative AS paths via the public RIPE Stat looking-glass,
# preferring vantage points in Brazil
hopwatch trace google.com --alternatives --country BR

# include RIPE Atlas results too (slower but real measurements)
hopwatch trace google.com --alternatives --source both

# ask BGP looking-glass collectors how *they* reach the target
hopwatch trace cloudflare.com --why
```

Two standalone commands are also available:

```bash
# just the alternatives
hopwatch alternatives www.u-tokyo.ac.jp --source stat --country BR --max 12

# just the looking-glass dump
hopwatch why 1.1.1.1
```

## All flags

```text
trace <target> [options]
  --protocol {icmp,udp,tcp}    probe protocol (default: icmp)
  --probes N                   probes per hop (default: 3)
  --max-ttl N                  TTL ceiling (default: 30)
  --timeout S                  per-probe timeout in seconds (default: 2)
  --subprocess                 force the system traceroute backend
  --alternatives               also print AS paths from other ISPs
  --source {stat,atlas,both}   alternatives source (default: stat)
  --country CC                 prefer this ISO country (e.g. BR, US, DE)
  --max-alternatives N         cap distinct paths to show (default: 8)
  --why                        print BGP looking-glass output too

alternatives <target> [options]
  --source {stat,atlas,both}   (default: stat)
  --country CC                 prefer this country
  --max N                      cap paths (default: 12)

why <target>
```

## How to read the output

- **Owner column** uses Team Cymru AS data, so the registered company name
  appears as-is. Private addresses (RFC 1918) and CGNAT (RFC 6598) are
  surfaced as ``⟨private (RFC 1918)⟩`` and ``⟨CGNAT (RFC 6598)⟩`` so you
  can tell when you're still inside your own ISP's internal network.
- **Anomalies** block highlights the things worth reading the trace for:
  filtered hops, MPLS labels, RTT inversions, AS re-appearance (route
  leaks).
- **Alternative AS paths** show, for the *same destination*, what AS-paths
  are observed by other ISPs' BGP feeds. The ``[RRC15]`` suffix indicates
  the RIPE Stat collector — RRC15 sits at IX.br São Paulo, so paths tagged
  with it are anchored in Brazil.

## What you get

```
HopWatch — tracing 8.8.8.8 via ICMP (probes=3, timeout=2.0s)
resolved to 8.8.8.8

  # IP             RTT(ms) Loss  ASN     Owner                CC  Notes
  1 192.168.1.1       1.2  0/3   --      ----                 --
  2 100.64.0.1        8.4  0/3   AS28573 CLARO S.A.           BR
  3 187.123.10.5     11.0  0/3   AS28573 CLARO S.A.           BR
  4 4.69.150.66      24.0  0/3   AS3356  LUMEN-3356           US  MPLS 524288
  5 *                  -   3/3   --      ----                 --
  6 108.170.252.10   41.0  0/3   AS15169 GOOGLE               US
  7 8.8.8.8          42.0  0/3   AS15169 GOOGLE               US  dns.google

7 hops, 6.5s

── Anomalies ──
  ⚠  [warn] hop 5: 1 consecutive filtered hops (firewall or ACL ahead)
  ℹ  [info] hop 4: MPLS labels seen: [524288]

── Alternative AS paths to 8.8.8.8 (RIPE Atlas) ──
  via Telefônica Brasil (BR, AS27699)
      AS27699 → AS6453 → AS15169
  via TIM Brasil (BR, AS26615)
      AS26615 → AS2914 → AS15169
  via Algar Telecom (BR, AS16735)
      AS16735 → AS12956 → AS15169
```

## Components

| Module | Responsibility |
|---|---|
| `hopwatch/probe.py` | Multi-protocol traceroute (ICMP / UDP / TCP). Scapy if available, falls back to system `traceroute`. Parses MPLS labels from ICMP Time Exceeded responses. |
| `hopwatch/enrich.py` | Resolves each hop IP to ASN + AS name + country via Team Cymru DNS service. In-memory LRU cached. |
| `hopwatch/anomaly.py` | Heuristics: filtered hops, AS loops, RTT inversion, MPLS, high loss. |
| `hopwatch/alternatives.py` | Counterfactual AS paths. Two sources: **RIPE Stat looking-glass** (RRC collectors worldwide — `RRC15` at IX.br São Paulo gives the BR perspective) and **RIPE Atlas** measurements (real traceroutes from ~10k probes). Combined via `--source both`. Looking-glass RIB dump for the `why` command. Parallelised HTTP/DNS lookups via `ThreadPoolExecutor`. |
| `hopwatch/cli.py` | Argparse front-end. Rich tables when `rich` is installed. |

## Example: maximum-diversity targets

To exercise the alternatives panel against a destination that traverses many
distinct ISPs, try a far-away academic or government host. From Brazil the
following will show 4-5 distinct ASes in the local trace plus 10+ paths in
the alternatives panel:

```bash
hopwatch trace www.u-tokyo.ac.jp --alternatives --source both
hopwatch trace www.csiro.au --alternatives
hopwatch trace archive.org --alternatives
hopwatch trace www.ru.is --alternatives          # Iceland — exotic routing
```

## Limitations

- Raw sockets need root or `CAP_NET_RAW`. Use `--subprocess` if that's a
  blocker — HopWatch then drives ``mtr`` or ``tracepath``.
- Counterfactual paths are limited to what RIPE collectors / Atlas probes
  have measured. Some destinations have great coverage, others have none.
- Local hops on most modern ISPs are RFC 1918 / CGNAT (you'll see this in
  the table). The first public ASN you see is the upstream peering edge,
  not necessarily the ISP that bills you.
- We never spoof or attempt to send through other networks. Everything is
  read-only from public APIs + your own machine.

## License

MIT.
