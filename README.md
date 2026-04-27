# LAN Guard

LAN Guard is a defensive LAN MITM and sniffing-indicator detector for authorized local networks, labs, small businesses, and blue-team exercises.

It detects conditions commonly associated with sniffing and interception, including ARP poisoning, rogue DHCP, gateway impersonation, DNS resolver drift, TLS inspection, name-resolution poisoning indicators, IPv6 router-advertisement signals, and local endpoint packet-capture indicators.

> LAN Guard does **not** claim to prove every sniffer. Fully passive sniffers, SPAN ports, taps, and hardware recorders may be invisible from the network.

## Features

- ARP poisoning indicators
- Rogue DHCP server candidates
- Gateway MAC baseline comparison
- IPv4 and IPv6 DNS drift detection
- Duplicate MAC and multiple-MAC-per-IP detection
- TLS/HTTPS inspection checks
- Optional Scapy promiscuous-mode probe
- Local PROMISC interface and packet-capture process checks
- LLMNR/NBNS/mDNS/WPAD monitoring
- IPv6 Router Advertisement monitoring
- DNS consistency checks using `dig`, when available
- Offline OUI/MAC vendor annotation
- TLS certificate baseline pinning
- JSON, Markdown, text, and HTML reports
- JSONL events for SIEM ingestion
- Local scan history
- Profiles: `home`, `enterprise`, `lab`, `passive`
- Config file support: JSON or simple YAML
- Doctor command
- Dry-run, quiet mode, timestamped reports
- Cron/at scheduling helper
- Switch telemetry import helper

## Quick start

```bash
chmod +x lan_guard.py
python3 lan_guard.py deps-check
sudo python3 lan_guard.py scan
```

## Create a baseline

```bash
sudo python3 lan_guard.py baseline-create
```

## Run with a profile

```bash
sudo python3 lan_guard.py scan --profile home --format all --timestamped-reports
```

## Non-interactive example

```bash
sudo python3 lan_guard.py scan   --non-interactive   --interface eth0   --gateway-ip 192.168.0.1   --expected-dns 192.168.0.1   --expected-dhcp 192.168.0.1   --tls-check github.com,cloudflare.com,google.com   --trusted-inspection-issuers "Zscaler,Fortinet,Palo Alto"   --enable-name-resolution-monitor   --enable-ipv6-ra-monitor   --local-checks   --format all   --timestamped-reports
```

## Schedule autoruns

Interactive scheduler:

```bash
python3 lan_guard.py schedule
```

Daily at 02:30 and install into crontab:

```bash
python3 lan_guard.py schedule   --frequency daily   --time 02:30   --scan-args "--non-interactive --interface eth0 --gateway-ip 192.168.0.1 --expected-dns 192.168.0.1 --expected-dhcp 192.168.0.1 --format all --timestamped-reports --quiet"   --install
```

## Reports

Default report outputs:

- `lan_guard_report.txt`
- `lan_guard_report.json`
- `lan_guard_report.md`
- `lan_guard_report.html`

Use timestamped report directories:

```bash
sudo python3 lan_guard.py scan --timestamped-reports --output-dir reports
```

## What it detects

- ARP poisoning indicators
- Rogue DHCP server candidates
- Unexpected gateway MAC changes
- IPv4 and IPv6 DNS drift
- Possible TLS inspection
- Name-resolution poisoning indicators
- IPv6 router-advertisement indicators
- Possible promiscuous-mode responses
- Local PROMISC interfaces
- Local packet-capture processes

## What it does not detect

- Fully passive sniffers with certainty
- Passive taps, SPAN ports, or hardware recorders with certainty
- Whether trusted TLS inspection is authorized without policy context
- All attack types; it complements switch telemetry, EDR, NAC, IDS, and SIEM

## Privacy

LAN Guard does not upload scan data by default. Reports, baselines, history, and JSONL events are stored locally.
