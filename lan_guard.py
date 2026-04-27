#!/usr/bin/env python3
"""
LAN Guard - Defensive LAN MITM & Sniffing Indicator Detector

LAN Guard helps defenders identify local network conditions commonly associated
with packet sniffing, man-in-the-middle activity, rogue DHCP, DNS tampering,
gateway impersonation, TLS inspection, and local packet-capture indicators.

This tool is designed for authorized defensive use in local labs, home networks,
small businesses, and internal security assessments.

What it detects:
    - ARP poisoning indicators
    - Rogue DHCP server candidates
    - Unexpected gateway MAC changes
    - IPv4 and IPv6 DNS resolver drift
    - Duplicate MAC mappings
    - One IP claimed by multiple MAC addresses
    - Possible TLS/HTTPS inspection
    - Optional promiscuous-mode probe responses using Scapy, if installed
    - Local PROMISC interfaces, when run on an endpoint
    - Local packet-capture/security-monitoring processes, when enabled

What it does not detect:
    - It cannot reliably prove fully passive sniffing from the network alone.
    - It cannot detect passive taps, SPAN ports, or hardware recorders with certainty.
    - It cannot determine whether TLS inspection is authorized without policy context.
    - It does not replace switch telemetry, NAC, EDR, IDS, or SIEM monitoring.

Required permissions:
    - Root/admin privileges are recommended for tcpdump packet capture.
    - Dependency installation requires root privileges.
    - Read-only checks can run without root, but results may be incomplete.

Supported platforms:
    - Linux is the primary supported platform.
    - Debian/Ubuntu/Kali, Fedora/RHEL, Arch, and openSUSE are target platforms.
    - macOS/BSD support is partial.
    - Windows is not supported in this version.

Safe lab setup:
    - Use a dedicated lab VLAN or isolated virtual network.
    - Use at least one client, one gateway/router, and one monitoring host.
    - Do not run against networks you do not own or administer.
    - Capture only traffic you are authorized to inspect.

License:
    MIT
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


APP_NAME = "LAN Guard"
APP_VERSION = "1.0.0"
BASELINE_FILE = "lan_guard_baseline.json"
REPORT_BASENAME = "lan_guard_report"

REQUIRED_DEPENDENCIES = {
    "tcpdump": {
        "command": "tcpdump",
        "packages": {
            "apt": "tcpdump",
            "dnf": "tcpdump",
            "yum": "tcpdump",
            "pacman": "tcpdump",
            "zypper": "tcpdump",
        },
        "description": "Packet capture engine for ARP and DHCP checks",
    },
    "ip": {
        "command": "ip",
        "packages": {
            "apt": "iproute2",
            "dnf": "iproute",
            "yum": "iproute",
            "pacman": "iproute2",
            "zypper": "iproute2",
        },
        "description": "Modern Linux networking utility for routes and neighbour table",
    },
}

OPTIONAL_DEPENDENCIES = {
    "arp": {
        "command": "arp",
        "packages": {
            "apt": "net-tools",
            "dnf": "net-tools",
            "yum": "net-tools",
            "pacman": "net-tools",
            "zypper": "net-tools",
        },
        "description": "Legacy ARP cache utility; optional fallback",
    },
    "resolvectl": {
        "command": "resolvectl",
        "packages": {},
        "description": "Optional DNS discovery utility. LAN Guard will not install systemd.",
    },
    "nmcli": {
        "command": "nmcli",
        "packages": {
            "apt": "network-manager",
            "dnf": "NetworkManager",
            "yum": "NetworkManager",
            "pacman": "networkmanager",
            "zypper": "NetworkManager",
        },
        "description": "Optional NetworkManager DNS discovery utility",
    },
    "python3-scapy": {
        "command": None,
        "packages": {
            "apt": "python3-scapy",
            "dnf": "python3-scapy",
            "yum": "python3-scapy",
            "pacman": "python-scapy",
            "zypper": "python3-scapy",
        },
        "description": "Optional Scapy dependency for promiscuous-mode probing",
    },
}


PROJECT_DOCUMENTATION = {
    "what_it_detects": [
        "ARP poisoning indicators",
        "Rogue DHCP server candidates",
        "Unexpected gateway MAC changes",
        "IPv4 and IPv6 DNS resolver drift",
        "Duplicate MAC mappings",
        "One IP claimed by multiple MAC addresses",
        "Possible TLS/HTTPS inspection",
        "Possible promiscuous-mode responses when Scapy probing is enabled",
        "Local PROMISC interfaces when local checks are enabled",
        "Local packet-capture/security-monitoring processes when local checks are enabled",
    ],
    "what_it_does_not_detect": [
        "It cannot reliably prove fully passive sniffing from the network alone.",
        "It cannot detect passive taps, SPAN ports, or hardware recorders with certainty.",
        "It cannot determine whether TLS inspection is authorized without policy context.",
        "It does not replace switch telemetry, NAC, EDR, IDS, or SIEM monitoring.",
        "It does not guarantee that zero DHCP packets means no DHCP server exists.",
    ],
    "required_permissions": [
        "Root/admin privileges are recommended for tcpdump packet capture.",
        "Dependency installation requires root privileges.",
        "Read-only checks can run without root, but packet capture may fail.",
    ],
    "supported_platforms": [
        "Linux is the primary supported platform.",
        "Debian/Ubuntu/Kali, Fedora/RHEL, Arch, and openSUSE are target platforms.",
        "macOS/BSD support is partial.",
        "Windows is not supported in this version.",
    ],
    "false_positives": [
        "Routers, firewalls, VRRP/HSRP/CARP clusters, and proxy ARP may cause duplicate MAC mappings.",
        "IPv6 router advertisements may legitimately provide IPv6 DNS resolvers.",
        "VPN clients may alter DNS resolvers.",
        "Virtualization platforms and bridges may create unusual MAC/IP mappings.",
        "TLS inspection may be authorized in enterprise networks.",
        "Security tools such as Zeek, Suricata, Snort, or tcpdump may be legitimate monitoring processes.",
        "DHCP capture can miss DHCP servers if no DHCP activity occurs during the capture window.",
    ],
    "safe_lab_setup": [
        "Use a dedicated lab VLAN or isolated virtual network.",
        "Use one client, one gateway/router, and one monitoring host.",
        "Generate benign traffic such as ping, DNS queries, and web browsing.",
        "Do not capture traffic on networks you do not own or administer.",
        "Compare baseline and scan results before and after controlled lab changes.",
    ],
    "example_reports": [
        "Text report: lan_guard_report.txt",
        "JSON report: lan_guard_report.json",
        "Markdown report: lan_guard_report.md",
    ],
}


SNIFFER_PROCESS_KEYWORDS = [
    "tcpdump",
    "wireshark",
    "dumpcap",
    "tshark",
    "ettercap",
    "bettercap",
    "dsniff",
    "arpspoof",
    "mitmproxy",
    "zeek",
    "bro",
    "suricata",
    "snort",
    "netsniff-ng",
]


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    details: str
    recommendation: str
    evidence: Dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_command(command: str, timeout: int = 30) -> Tuple[str, str, int]:
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out: {command}", 124
    except Exception as exc:
        return "", str(exc), 1


def is_root() -> bool:
    return os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0


def command_exists(command: Optional[str]) -> bool:
    if not command:
        return False
    return shutil.which(command) is not None


def python_module_exists(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except Exception:
        return False


def detect_package_manager() -> Optional[str]:
    for manager in ["apt", "dnf", "yum", "pacman", "zypper"]:
        if command_exists(manager):
            return manager
    return None


def dependency_status() -> Dict[str, Dict[str, Any]]:
    status: Dict[str, Dict[str, Any]] = {}

    for name, info in REQUIRED_DEPENDENCIES.items():
        status[name] = {
            "required": True,
            "installed": command_exists(info["command"]),
            "description": info["description"],
            "packages": info["packages"],
        }

    for name, info in OPTIONAL_DEPENDENCIES.items():
        if name == "python3-scapy":
            installed = python_module_exists("scapy")
        else:
            installed = command_exists(info["command"])

        status[name] = {
            "required": False,
            "installed": installed,
            "description": info["description"],
            "packages": info["packages"],
        }

    return status


def print_dependency_status() -> Dict[str, Dict[str, Any]]:
    deps = dependency_status()
    print("=" * 80)
    print("Dependency Check")
    print("=" * 80)

    for name, info in deps.items():
        label = "required" if info["required"] else "optional"
        state = "FOUND" if info["installed"] else "MISSING"
        print(f"{state:<8} {name:<16} {label:<10} {info['description']}")

    missing_required = [name for name, info in deps.items() if info["required"] and not info["installed"]]
    missing_optional = [name for name, info in deps.items() if not info["required"] and not info["installed"]]

    print("")
    if missing_required:
        print("[!] Missing required dependencies:")
        for name in missing_required:
            print(f"    - {name}")
    else:
        print("[+] All required dependencies are present.")

    if missing_optional:
        print("[i] Missing optional dependencies:")
        for name in missing_optional:
            print(f"    - {name}")

    print("")
    return deps


def install_dependencies(include_optional: bool = False) -> bool:
    deps = dependency_status()
    manager = detect_package_manager()

    if not manager:
        print("[!] No supported package manager detected. Install dependencies manually.")
        return False

    if not is_root():
        print("[!] Dependency installation requires root privileges. Re-run with sudo.")
        return False

    packages: List[str] = []

    for name, info in deps.items():
        if info["installed"]:
            continue
        if not info["required"] and not include_optional:
            continue

        package = info["packages"].get(manager)
        if not package:
            print(f"[i] Skipping {name}: no safe package mapping for {manager}.")
            continue
        if package not in packages:
            packages.append(package)

    if not packages:
        print("[+] No installable missing dependencies selected.")
        return True

    print("=" * 80)
    print("Dependency Installation")
    print("=" * 80)
    print(f"Package manager: {manager}")
    print("Packages:")
    for package in packages:
        print(f"    - {package}")

    if manager == "apt":
        command = f"apt update && apt install -y {' '.join(packages)}"
    elif manager == "dnf":
        command = f"dnf install -y {' '.join(packages)}"
    elif manager == "yum":
        command = f"yum install -y {' '.join(packages)}"
    elif manager == "pacman":
        command = f"pacman -Sy --noconfirm {' '.join(packages)}"
    elif manager == "zypper":
        command = f"zypper install -y {' '.join(packages)}"
    else:
        print("[!] Unsupported package manager.")
        return False

    print("\nCommand to run:")
    print(f"    {command}")
    choice = input("\nProceed? [y/N]: ").strip().lower()
    if choice != "y":
        print("[!] Installation cancelled.")
        return False

    stdout, stderr, code = run_command(command, timeout=300)
    if code == 0:
        print("[+] Dependency installation completed.")
        return True

    print("[!] Dependency installation failed.")
    print(stderr or stdout)
    return False


def validate_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def validate_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except Exception:
        return False


def validate_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except Exception:
        return False


def validate_mac(value: str) -> bool:
    if not value:
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", value))


def parse_csv_strings(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    values = [item.strip() for item in raw.split(",") if item.strip()]
    return sorted(set(values))


def parse_csv_ips(raw: Optional[str], allow_empty: bool = True) -> List[str]:
    if raw is None:
        return []
    raw = raw.strip()
    if not raw and allow_empty:
        return []

    values = parse_csv_strings(raw)
    invalid = []

    for value in values:
        if "-" in value:
            invalid.append(value)
            continue
        if not validate_ip(value):
            invalid.append(value)

    if invalid:
        raise ValueError(
            "Invalid IP value(s): "
            + ", ".join(invalid)
            + ". Enter individual server IPs, not ranges."
        )

    return values


def split_dns_by_family(dns_servers: Iterable[str]) -> Tuple[List[str], List[str]]:
    ipv4: List[str] = []
    ipv6: List[str] = []

    for server in dns_servers:
        try:
            ip_obj = ipaddress.ip_address(server)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                ipv4.append(server)
            else:
                ipv6.append(server)
        except Exception:
            continue

    return sorted(ipv4), sorted(ipv6)


def safe_int(value: Optional[str], default: int) -> int:
    try:
        parsed = int(value or "")
        return parsed if parsed > 0 else default
    except Exception:
        return default


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def get_default_interface() -> str:
    if not command_exists("ip"):
        return ""
    stdout, _, code = run_command("ip route | awk '/default/ {print $5; exit}'", timeout=5)
    return stdout.strip() if code == 0 and stdout else ""


def get_default_gateway() -> str:
    if not command_exists("ip"):
        return ""
    stdout, _, code = run_command("ip route | awk '/default/ {print $3; exit}'", timeout=5)
    return stdout.strip() if code == 0 and stdout else ""


def get_gateway_mac_from_neigh(gateway_ip: str) -> str:
    if not gateway_ip or not command_exists("ip"):
        return ""
    stdout, _, _ = run_command(f"ip neigh show {gateway_ip}", timeout=5)
    match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", stdout)
    return match.group(1).lower() if match else ""


def get_dns_from_resolvectl() -> List[str]:
    dns_servers = set()
    if not command_exists("resolvectl"):
        return []

    stdout, _, _ = run_command("resolvectl dns", timeout=10)
    candidates = re.findall(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]{2,})\b", stdout)
    for candidate in candidates:
        if validate_ip(candidate):
            dns_servers.add(candidate)
    return sorted(dns_servers)


def get_dns_from_resolv_conf() -> List[str]:
    dns_servers = set()
    path = Path("/etc/resolv.conf")
    if not path.exists():
        return []

    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2 and validate_ip(parts[1]):
                    dns_servers.add(parts[1])
    except Exception:
        pass
    return sorted(dns_servers)


def get_dns_from_nmcli() -> List[str]:
    dns_servers = set()
    if not command_exists("nmcli"):
        return []

    stdout, _, _ = run_command("nmcli dev show", timeout=10)
    for line in stdout.splitlines():
        if "IP4.DNS" in line or "IP6.DNS" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                candidate = parts[1].strip()
                if validate_ip(candidate):
                    dns_servers.add(candidate)
    return sorted(dns_servers)


def get_current_dns_servers() -> List[str]:
    dns_servers = set()
    for func in [get_dns_from_resolvectl, get_dns_from_resolv_conf, get_dns_from_nmcli]:
        for server in func():
            dns_servers.add(server)
    return sorted(dns_servers)


def get_ip_neigh() -> Tuple[str, str, int]:
    if not command_exists("ip"):
        return "", "ip command not found", 1
    return run_command("ip neigh", timeout=10)


def get_arp_a() -> Tuple[str, str, int]:
    if not command_exists("arp"):
        return "", "arp command not found", 1
    return run_command("arp -a", timeout=10)


def parse_ip_neigh(output: str) -> List[Dict[str, Any]]:
    records = []

    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip_value = parts[0]
        if not validate_ip(ip_value):
            continue

        mac_match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", line)
        mac = mac_match.group(1).lower() if mac_match else "unknown"
        state = parts[-1] if parts else "unknown"

        records.append({
            "source": "ip neigh",
            "ip": ip_value,
            "mac": mac,
            "state": state,
            "raw": line,
        })

    return records


def parse_arp_a(output: str) -> List[Dict[str, Any]]:
    records = []

    for line in output.splitlines():
        ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
        mac_match = re.search(r"\bat\s+([0-9a-fA-F:]{17})", line)
        if not ip_match:
            continue

        ip_value = ip_match.group(1)
        if not validate_ip(ip_value):
            continue

        mac = mac_match.group(1).lower() if mac_match else "unknown"
        records.append({
            "source": "arp -a",
            "ip": ip_value,
            "mac": mac,
            "state": "unknown",
            "raw": line,
        })

    return records


def merge_arp_records(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for record in records:
        ip_value = record["ip"]
        mac = record["mac"]

        if ip_value not in merged:
            merged[ip_value] = {
                "ip": ip_value,
                "macs": set(),
                "sources": set(),
                "raw": [],
            }

        if mac != "unknown":
            merged[ip_value]["macs"].add(mac)

        merged[ip_value]["sources"].add(record["source"])
        merged[ip_value]["raw"].append(record["raw"])

    clean: Dict[str, Dict[str, Any]] = {}
    for ip_value, data in merged.items():
        clean[ip_value] = {
            "ip": ip_value,
            "macs": sorted(data["macs"]),
            "sources": sorted(data["sources"]),
            "raw": data["raw"],
        }

    return clean


def capture_arp_packets(interface: str, seconds: int) -> Tuple[str, str, int]:
    if not command_exists("tcpdump"):
        return "", "tcpdump not found", 1
    command = f"timeout {seconds} tcpdump -n -i {interface} arp"
    return run_command(command, timeout=seconds + 15)


def capture_dhcp_packets(interface: str, seconds: int) -> Tuple[str, str, int]:
    if not command_exists("tcpdump"):
        return "", "tcpdump not found", 1
    command = f"timeout {seconds} tcpdump -n -i {interface} 'udp port 67 or udp port 68'"
    return run_command(command, timeout=seconds + 15)


def analyze_arp_capture(output: str, gateway_ip: str) -> Dict[str, Any]:
    gateway_claims: Dict[str, int] = defaultdict(int)
    all_claims: Dict[str, set] = defaultdict(set)

    for line in output.splitlines():
        match = re.search(
            r"Reply\s+((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[a-fA-F0-9:]{2,}))\s+is-at\s+([0-9a-fA-F:]{17})",
            line,
        )
        if not match:
            continue

        ip_value = match.group(1)
        mac = match.group(2).lower()
        if not validate_ip(ip_value):
            continue

        all_claims[ip_value].add(mac)
        if ip_value == gateway_ip:
            gateway_claims[mac] += 1

    return {
        "gateway_claims": dict(gateway_claims),
        "ips_with_multiple_arp_claims": {
            ip_value: sorted(macs)
            for ip_value, macs in all_claims.items()
            if len(macs) > 1
        },
    }


def analyze_dhcp_capture(output: str) -> List[str]:
    dhcp_servers = set()

    for line in output.splitlines():
        match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\.67\s+>\s+", line)
        if match and validate_ipv4(match.group(1)):
            dhcp_servers.add(match.group(1))

    return sorted(dhcp_servers)


def detect_duplicate_macs(merged_records: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    mac_to_ips: Dict[str, List[str]] = defaultdict(list)
    for ip_value, data in merged_records.items():
        for mac in data.get("macs", []):
            mac_to_ips[mac].append(ip_value)

    return {mac: sorted(ips) for mac, ips in mac_to_ips.items() if len(ips) > 1}


def detect_multiple_macs_per_ip(merged_records: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    return {
        ip_value: data.get("macs", [])
        for ip_value, data in merged_records.items()
        if len(data.get("macs", [])) > 1
    }


def get_tls_certificate_summary(hostname: str, port: int = 443, timeout: int = 8) -> Dict[str, Any]:
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()

    subject = dict(item[0] for item in cert.get("subject", []))
    issuer = dict(item[0] for item in cert.get("issuer", []))

    return {
        "hostname": hostname,
        "subject_common_name": subject.get("commonName", ""),
        "issuer_common_name": issuer.get("commonName", ""),
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "subject_alt_names": cert.get("subjectAltName", []),
    }


def run_tls_checks(hostnames: List[str], trusted_issuers: List[str]) -> List[Dict[str, Any]]:
    results = []
    trusted_lower = [issuer.lower() for issuer in trusted_issuers]

    for hostname in hostnames:
        try:
            summary = get_tls_certificate_summary(hostname)
            issuer = summary.get("issuer_common_name", "")
            issuer_lower = issuer.lower()

            matched_trusted = [
                issuer_keyword for issuer_keyword in trusted_issuers
                if issuer_keyword.lower() in issuer_lower
            ]

            possible_inspection = bool(matched_trusted)

            results.append({
                "hostname": hostname,
                "status": "ok",
                "issuer": issuer,
                "subject": summary.get("subject_common_name", ""),
                "possible_tls_inspection": possible_inspection,
                "matched_trusted_issuers": matched_trusted,
                "details": summary,
            })
        except Exception as exc:
            results.append({
                "hostname": hostname,
                "status": "error",
                "error": str(exc),
                "possible_tls_inspection": False,
            })

    return results


def run_promisc_probe(network: str) -> Dict[str, Any]:
    if not network:
        return {"enabled": False, "status": "skipped", "results": []}

    if not validate_network(network):
        return {
            "enabled": True,
            "status": "error",
            "error": f"Invalid network CIDR: {network}",
            "results": [],
        }

    try:
        from scapy.all import promiscping  # type: ignore
    except Exception:
        return {
            "enabled": True,
            "status": "error",
            "error": "Scapy is not installed. Install python3-scapy or pip install scapy.",
            "results": [],
        }

    try:
        answers = promiscping(network)
        return {
            "enabled": True,
            "status": "ok",
            "raw_result": str(answers),
            "results": [],
            "note": "Scapy promiscping output is implementation-dependent; review raw_result.",
        }
    except Exception as exc:
        return {
            "enabled": True,
            "status": "error",
            "error": str(exc),
            "results": [],
        }


def local_promisc_interfaces() -> Dict[str, Any]:
    if not command_exists("ip"):
        return {"status": "error", "error": "ip command not found", "interfaces": []}

    stdout, stderr, code = run_command("ip -d link show", timeout=10)
    interfaces: List[Dict[str, str]] = []

    current_header = ""
    current_block: List[str] = []

    for line in stdout.splitlines():
        if re.match(r"^\d+:\s+", line):
            if current_block and "PROMISC" in "\n".join(current_block):
                name_match = re.match(r"^\d+:\s+([^:]+):", current_header)
                interfaces.append({
                    "interface": name_match.group(1) if name_match else "unknown",
                    "raw": "\n".join(current_block),
                })
            current_header = line
            current_block = [line]
        else:
            current_block.append(line)

    if current_block and "PROMISC" in "\n".join(current_block):
        name_match = re.match(r"^\d+:\s+([^:]+):", current_header)
        interfaces.append({
            "interface": name_match.group(1) if name_match else "unknown",
            "raw": "\n".join(current_block),
        })

    return {
        "status": "ok" if code == 0 else "error",
        "error": stderr if code != 0 else "",
        "interfaces": interfaces,
        "raw": stdout,
    }


def local_sniffer_processes() -> Dict[str, Any]:
    stdout, stderr, code = run_command("ps aux", timeout=10)
    matches: List[str] = []

    own_names = ["lan_guard.py", "lan_guard", Path(sys.argv[0]).name.lower()]

    for line in stdout.splitlines():
        lower = line.lower()
        if any(own in lower for own in own_names):
            continue
        if any(keyword in lower for keyword in SNIFFER_PROCESS_KEYWORDS):
            matches.append(line)

    return {
        "status": "ok" if code == 0 else "error",
        "error": stderr if code != 0 else "",
        "processes": matches,
    }


def run_local_checks(enabled: bool) -> Dict[str, Any]:
    if not enabled:
        return {"enabled": False, "status": "skipped"}

    return {
        "enabled": True,
        "status": "ok",
        "promisc_interfaces": local_promisc_interfaces(),
        "sniffer_processes": local_sniffer_processes(),
    }


def load_baseline(path: str = BASELINE_FILE) -> Dict[str, Any]:
    baseline_path = Path(path)
    if not baseline_path.exists():
        return {}

    try:
        return json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_baseline(data: Dict[str, Any], path: str = BASELINE_FILE) -> None:
    Path(path).write_text(json.dumps(data, indent=4), encoding="utf-8")


def severity_label(score: int) -> str:
    if score >= 80:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 15:
        return "Low"
    return "Informational"


def make_finding(
    title: str,
    severity: str,
    confidence: str,
    details: str,
    recommendation: str,
    evidence: Optional[Dict[str, Any]] = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        details=details,
        recommendation=recommendation,
        evidence=evidence or {},
    )


def generate_findings(
    config: Dict[str, Any],
    merged_records: Dict[str, Dict[str, Any]],
    arp_analysis: Dict[str, Any],
    dhcp_servers: List[str],
    current_dns: List[str],
    baseline: Dict[str, Any],
    tls_results: List[Dict[str, Any]],
    promisc_result: Dict[str, Any],
    local_results: Dict[str, Any],
) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []
    risk_score = 0

    gateway_ip = config["gateway_ip"]
    expected_gateway_mac = config.get("gateway_mac", "")
    expected_dns = set(config.get("expected_dns", []))
    expected_dhcp = set(config.get("expected_dhcp", []))

    current_dns_ipv4, current_dns_ipv6 = split_dns_by_family(current_dns)
    expected_dns_ipv4, expected_dns_ipv6 = split_dns_by_family(expected_dns)

    gateway_macs_seen = merged_records.get(gateway_ip, {}).get("macs", [])

    if expected_gateway_mac:
        if not gateway_macs_seen:
            findings.append(make_finding(
                "Gateway MAC not found in ARP/neighbour table",
                "Medium",
                "Medium",
                f"Expected gateway {gateway_ip} with MAC {expected_gateway_mac}, but no gateway MAC was observed.",
                "Generate traffic to the gateway, for example ping the gateway, then rerun the tool.",
                {"gateway_ip": gateway_ip, "expected_gateway_mac": expected_gateway_mac},
            ))
            risk_score += 25
        elif expected_gateway_mac not in gateway_macs_seen:
            findings.append(make_finding(
                "Unexpected gateway MAC address detected",
                "High",
                "High",
                f"Gateway {gateway_ip} expected MAC {expected_gateway_mac}, observed {gateway_macs_seen}.",
                "Investigate possible ARP poisoning, gateway impersonation, or unauthorized MITM activity.",
                {
                    "gateway_ip": gateway_ip,
                    "expected_gateway_mac": expected_gateway_mac,
                    "observed_gateway_macs": gateway_macs_seen,
                },
            ))
            risk_score += 50

    baseline_gateway_mac = baseline.get("gateway_mac")
    if baseline_gateway_mac and gateway_macs_seen and baseline_gateway_mac not in gateway_macs_seen:
        findings.append(make_finding(
            "Gateway MAC changed from saved baseline",
            "High",
            "High",
            f"Baseline gateway MAC: {baseline_gateway_mac}. Current observed MACs: {gateway_macs_seen}.",
            "Confirm whether the router/firewall was replaced. If not, investigate possible MITM activity.",
            {"baseline_gateway_mac": baseline_gateway_mac, "observed_gateway_macs": gateway_macs_seen},
        ))
        risk_score += 50

    multiple_macs_per_ip = detect_multiple_macs_per_ip(merged_records)
    if multiple_macs_per_ip:
        findings.append(make_finding(
            "One or more IP addresses mapped to multiple MAC addresses",
            "High",
            "High",
            json.dumps(multiple_macs_per_ip, indent=2),
            "Check for ARP poisoning, IP conflicts, failover appliances, or virtualized network behavior.",
            {"multiple_macs_per_ip": multiple_macs_per_ip},
        ))
        risk_score += 45

    duplicate_macs = detect_duplicate_macs(merged_records)
    suspicious_duplicate_macs = {
        mac: ips for mac, ips in duplicate_macs.items()
        if gateway_ip not in ips or len(ips) > 2
    }
    if suspicious_duplicate_macs:
        findings.append(make_finding(
            "Duplicate MAC address mapped to multiple IP addresses",
            "Medium",
            "Medium",
            json.dumps(suspicious_duplicate_macs, indent=2),
            "Review whether this is expected router, proxy ARP, VRRP, HSRP, CARP, or virtualization behavior.",
            {"duplicate_macs": suspicious_duplicate_macs},
        ))
        risk_score += 30

    multi_claims = arp_analysis.get("ips_with_multiple_arp_claims", {})
    if multi_claims:
        findings.append(make_finding(
            "Conflicting ARP claims observed during live capture",
            "High",
            "High",
            json.dumps(multi_claims, indent=2),
            "This is a strong ARP poisoning indicator. Inspect the listed MAC addresses.",
            {"conflicting_arp_claims": multi_claims},
        ))
        risk_score += 55

    gateway_claims = arp_analysis.get("gateway_claims", {})
    if expected_gateway_mac and gateway_claims:
        unexpected_claims = [mac for mac in gateway_claims if mac != expected_gateway_mac]
        if unexpected_claims:
            findings.append(make_finding(
                "Unexpected MAC claimed the gateway IP during ARP capture",
                "High",
                "High",
                f"Gateway ARP claims observed: {gateway_claims}",
                "Isolate the suspicious host and inspect switch CAM/ARP tables.",
                {"gateway_claims": gateway_claims, "unexpected_claims": unexpected_claims},
            ))
            risk_score += 60

    if expected_dns:
        unexpected_dns = sorted(set(current_dns) - expected_dns)
        missing_dns = sorted(expected_dns - set(current_dns))
        unexpected_ipv4, unexpected_ipv6 = split_dns_by_family(unexpected_dns)
        missing_ipv4, missing_ipv6 = split_dns_by_family(missing_dns)

        if unexpected_ipv4:
            findings.append(make_finding(
                "Unexpected IPv4 DNS server detected",
                "Medium",
                "Medium",
                f"Expected IPv4 DNS: {expected_dns_ipv4}. Current IPv4 DNS: {current_dns_ipv4}. Unexpected: {unexpected_ipv4}.",
                "Check DHCP, static resolver configuration, VPN settings, and possible rogue DHCP behavior.",
                {"expected_dns_ipv4": expected_dns_ipv4, "current_dns_ipv4": current_dns_ipv4, "unexpected_dns_ipv4": unexpected_ipv4},
            ))
            risk_score += 35

        if unexpected_ipv6:
            findings.append(make_finding(
                "Additional IPv6 DNS resolver observed",
                "Low",
                "Medium",
                f"Expected IPv6 DNS: {expected_dns_ipv6}. Current IPv6 DNS: {current_dns_ipv6}. Additional: {unexpected_ipv6}.",
                "IPv6 DNS resolvers may be legitimate router-advertised resolvers. Add them to baseline if expected.",
                {"expected_dns_ipv6": expected_dns_ipv6, "current_dns_ipv6": current_dns_ipv6, "unexpected_dns_ipv6": unexpected_ipv6},
            ))
            risk_score += 15

        if missing_ipv4 or missing_ipv6:
            findings.append(make_finding(
                "Expected DNS server missing",
                "Low",
                "Medium",
                f"Missing expected IPv4 DNS: {missing_ipv4}. Missing expected IPv6 DNS: {missing_ipv6}. Current DNS: {current_dns}.",
                "Validate local resolver configuration and VPN state.",
                {"missing_dns_ipv4": missing_ipv4, "missing_dns_ipv6": missing_ipv6, "current_dns": current_dns},
            ))
            risk_score += 15

    baseline_dns = set(baseline.get("dns_servers", []))
    if baseline_dns:
        new_dns = sorted(set(current_dns) - baseline_dns)
        missing_baseline_dns = sorted(baseline_dns - set(current_dns))
        if new_dns:
            findings.append(make_finding(
                "DNS resolver changed from saved baseline",
                "Medium",
                "Medium",
                f"Baseline DNS: {sorted(baseline_dns)}. Current DNS: {current_dns}. New DNS resolvers: {new_dns}.",
                "Confirm whether DNS changed due to DHCP, VPN, or router configuration. If unexpected, investigate DNS tampering.",
                {"baseline_dns": sorted(baseline_dns), "current_dns": current_dns, "new_dns": new_dns, "missing_dns": missing_baseline_dns},
            ))
            risk_score += 30

    if dhcp_servers:
        if expected_dhcp:
            rogue_dhcp = sorted(set(dhcp_servers) - expected_dhcp)
            if rogue_dhcp:
                findings.append(make_finding(
                    "Possible rogue DHCP server detected",
                    "High",
                    "High",
                    f"Expected DHCP servers: {sorted(expected_dhcp)}. Observed DHCP servers: {dhcp_servers}. Rogue candidates: {rogue_dhcp}.",
                    "Enable DHCP snooping on switches and investigate the rogue DHCP source.",
                    {"expected_dhcp": sorted(expected_dhcp), "observed_dhcp": dhcp_servers, "rogue_candidates": rogue_dhcp},
                ))
                risk_score += 65
        else:
            findings.append(make_finding(
                "DHCP servers observed but no expected DHCP baseline provided",
                "Informational",
                "Medium",
                f"Observed DHCP servers: {dhcp_servers}",
                "Provide expected DHCP server IPs on the next run for stronger detection.",
                {"observed_dhcp": dhcp_servers},
            ))
            risk_score += 5
    else:
        findings.append(make_finding(
            "No DHCP packets observed during capture window",
            "Informational",
            "Low",
            "No DHCP packets were captured. This does not prove there is no DHCP server.",
            "For DHCP validation, renew a client lease in a controlled lab or increase capture duration.",
            {"observed_dhcp": []},
        ))

    for tls in tls_results:
        if tls.get("status") == "error":
            findings.append(make_finding(
                "TLS certificate check failed for host",
                "Informational",
                "Low",
                f"TLS check failed for {tls.get('hostname')}: {tls.get('error')}",
                "Verify connectivity, DNS resolution, proxy policy, and whether the target hostname is reachable.",
                tls,
            ))
            continue

        if tls.get("possible_tls_inspection"):
            findings.append(make_finding(
                "Possible TLS/HTTPS inspection observed",
                "Medium",
                "Medium",
                f"{tls.get('hostname')} presented a certificate issued by {tls.get('issuer')}, matching configured inspection issuer keywords.",
                "Confirm whether HTTPS inspection is authorized and documented. If unexpected, investigate proxy or gateway configuration.",
                tls,
            ))
            risk_score += 30

    if promisc_result.get("enabled") and promisc_result.get("status") == "error":
        findings.append(make_finding(
            "Promiscuous-mode probe could not complete",
            "Informational",
            "Low",
            promisc_result.get("error", "Unknown Scapy/promisc probe error."),
            "Install Scapy for optional promiscuous-mode probing or skip this check.",
            promisc_result,
        ))

    if promisc_result.get("enabled") and promisc_result.get("status") == "ok":
        raw = promisc_result.get("raw_result", "")
        if raw and "None" not in raw:
            findings.append(make_finding(
                "Promiscuous-mode probe produced responses",
                "Medium",
                "Low",
                "Scapy promiscping returned output. Remote promiscuous-mode detection has known false positives and false negatives.",
                "Review raw Scapy output and validate with endpoint checks or switch telemetry.",
                promisc_result,
            ))
            risk_score += 20

    if local_results.get("enabled"):
        promisc_interfaces = local_results.get("promisc_interfaces", {}).get("interfaces", [])
        if promisc_interfaces:
            findings.append(make_finding(
                "Local interface in promiscuous mode",
                "Medium",
                "High",
                f"Local interfaces in PROMISC mode: {[item.get('interface') for item in promisc_interfaces]}",
                "Confirm whether packet capture, bridging, virtualization, or monitoring software is expected on this endpoint.",
                {"promisc_interfaces": promisc_interfaces},
            ))
            risk_score += 30

        processes = local_results.get("sniffer_processes", {}).get("processes", [])
        if processes:
            findings.append(make_finding(
                "Local packet-capture or network-monitoring process observed",
                "Low",
                "Medium",
                f"Observed {len(processes)} local process(es) matching known capture/monitoring tool names.",
                "Validate whether these processes are authorized monitoring tools or unexpected sniffing activity.",
                {"processes": processes},
            ))
            risk_score += 15

    if not findings:
        findings.append(make_finding(
            "No major LAN MITM indicators detected",
            "Informational",
            "Medium",
            "No obvious ARP poisoning, rogue DHCP, DNS mismatch, gateway MAC anomaly, duplicate MAC abuse, TLS inspection, or local sniffer indicators were detected.",
            "Continue monitoring. Consider switch-level protections such as DHCP snooping and Dynamic ARP Inspection.",
            {},
        ))

    return findings, risk_score


def prompt_user(args: argparse.Namespace) -> Dict[str, Any]:
    detected_interface = get_default_interface()
    detected_gateway = get_default_gateway()
    detected_gateway_mac = get_gateway_mac_from_neigh(detected_gateway)
    detected_dns = get_current_dns_servers()

    print("=" * 80)
    print(f"{APP_NAME} - Interactive LAN MITM/Sniffing Indicator Detector")
    print("=" * 80)
    if detected_interface:
        print(f"[+] Detected default interface: {detected_interface}")
    if detected_gateway:
        print(f"[+] Detected default gateway IP: {detected_gateway}")
    if detected_gateway_mac:
        print(f"[+] Detected gateway MAC: {detected_gateway_mac}")
    if detected_dns:
        print(f"[+] Detected DNS servers: {', '.join(detected_dns)}")
    print("")

    default_interface = detected_interface or "eth0"
    interface = input(f"Network interface [{default_interface}]: ").strip() or default_interface

    default_gateway = detected_gateway or "192.168.1.1"
    while True:
        gateway_ip = input(f"Expected gateway IP [{default_gateway}]: ").strip() or default_gateway
        if validate_ip(gateway_ip):
            break
        print("[!] Invalid gateway IP.")

    default_gateway_mac = detected_gateway_mac or ""
    while True:
        gateway_mac = input(f"Expected gateway MAC, or blank [{default_gateway_mac or 'blank'}]: ").strip().lower() or default_gateway_mac
        if validate_mac(gateway_mac):
            break
        print("[!] Invalid MAC format. Example: aa:bb:cc:dd:ee:ff")

    dns_default = ",".join(detected_dns) if detected_dns else gateway_ip
    while True:
        raw = input(f"Expected DNS server IPs, comma-separated, IPv4/IPv6 supported [{dns_default}]: ").strip() or dns_default
        try:
            expected_dns = parse_csv_ips(raw, allow_empty=True)
            break
        except ValueError as exc:
            print(f"[!] {exc}")

    while True:
        raw = input(f"Expected DHCP server IPs, not lease ranges, comma-separated [{gateway_ip}]: ").strip() or gateway_ip
        try:
            expected_dhcp = parse_csv_ips(raw, allow_empty=True)
            break
        except ValueError as exc:
            print(f"[!] {exc}")
            print("[i] Enter DHCP server IPs, usually the router IP, not a lease range.")

    capture_seconds = safe_int(input("ARP/DHCP capture duration in seconds [30]: ").strip(), 30)

    promisc_network = input("Optional promiscuous-mode probe network CIDR, e.g. 192.168.0.0/24, or blank to skip: ").strip()
    if promisc_network and not validate_network(promisc_network):
        print(f"[!] Invalid promiscuous probe network: {promisc_network}")
        print("[i] Skipping promiscuous-mode probe. Use a CIDR like 192.168.0.0/24.")
        promisc_network = ""

    tls_hosts_raw = input("Optional TLS inspection check hosts, comma-separated domains, or blank to skip: ").strip()
    tls_hosts = parse_csv_strings(tls_hosts_raw)

    trusted_issuers_raw = input("Optional trusted TLS inspection issuer keywords, comma-separated, or blank: ").strip()
    trusted_issuers = parse_csv_strings(trusted_issuers_raw)

    local_checks_raw = input("Run local endpoint checks for PROMISC/processes? [y/N]: ").strip().lower()
    local_checks = local_checks_raw == "y"

    return {
        "interface": interface,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "expected_dns": expected_dns,
        "expected_dhcp": expected_dhcp,
        "capture_seconds": capture_seconds,
        "promisc_network": promisc_network,
        "tls_hosts": tls_hosts,
        "trusted_inspection_issuers": trusted_issuers,
        "local_checks": local_checks,
    }


def config_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    detected_interface = get_default_interface()
    detected_gateway = get_default_gateway()
    detected_gateway_mac = get_gateway_mac_from_neigh(detected_gateway)
    detected_dns = get_current_dns_servers()

    interface = args.interface or detected_interface
    gateway_ip = args.gateway_ip or detected_gateway
    gateway_mac = args.gateway_mac or detected_gateway_mac
    expected_dns_raw = args.expected_dns if args.expected_dns is not None else ",".join(detected_dns)
    expected_dhcp_raw = args.expected_dhcp if args.expected_dhcp is not None else gateway_ip

    if not interface:
        raise ValueError("Interface is required in non-interactive mode.")
    if not gateway_ip or not validate_ip(gateway_ip):
        raise ValueError(f"Valid gateway IP is required. Got: {gateway_ip}")
    if gateway_mac and not validate_mac(gateway_mac):
        raise ValueError(f"Invalid gateway MAC: {gateway_mac}")

    expected_dns = parse_csv_ips(expected_dns_raw, allow_empty=True)
    expected_dhcp = parse_csv_ips(expected_dhcp_raw, allow_empty=True)

    if args.promisc_network and not validate_network(args.promisc_network):
        raise ValueError(f"Invalid --promisc-network CIDR: {args.promisc_network}")

    return {
        "interface": interface,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac.lower() if gateway_mac else "",
        "expected_dns": expected_dns,
        "expected_dhcp": expected_dhcp,
        "capture_seconds": args.capture_seconds,
        "promisc_network": args.promisc_network or "",
        "tls_hosts": parse_csv_strings(args.tls_check),
        "trusted_inspection_issuers": parse_csv_strings(args.trusted_inspection_issuers),
        "local_checks": bool(args.local_checks),
    }


def print_arp_table(merged_records: Dict[str, Dict[str, Any]]) -> None:
    print("\nObserved ARP/Neighbour Records")
    print("-" * 80)
    if not merged_records:
        print("No ARP/neighbour records found.")
        return

    print(f"{'IP Address':<40} {'MAC Address(es)':<30} {'Source'}")
    print("-" * 80)
    for ip_value, data in sorted(merged_records.items()):
        macs = ", ".join(data["macs"]) if data["macs"] else "unknown"
        sources = ", ".join(data["sources"])
        print(f"{ip_value:<40} {macs:<30} {sources}")


def build_report_object(
    config: Dict[str, Any],
    merged_records: Dict[str, Dict[str, Any]],
    arp_raw: str,
    dhcp_raw: str,
    arp_analysis: Dict[str, Any],
    dhcp_servers: List[str],
    current_dns: List[str],
    findings: List[Finding],
    risk_score: int,
    tls_results: List[Dict[str, Any]],
    promisc_result: Dict[str, Any],
    local_results: Dict[str, Any],
) -> Dict[str, Any]:
    current_dns_ipv4, current_dns_ipv6 = split_dns_by_family(current_dns)

    finding_dicts = [asdict(finding) for finding in findings]
    finding_counts = {
        "High": sum(1 for f in finding_dicts if f["severity"] == "High"),
        "Medium": sum(1 for f in finding_dicts if f["severity"] == "Medium"),
        "Low": sum(1 for f in finding_dicts if f["severity"] == "Low"),
        "Informational": sum(1 for f in finding_dicts if f["severity"] == "Informational"),
    }

    return {
        "tool": {"name": APP_NAME, "version": APP_VERSION},
        "metadata": {
            "report_time": utc_now(),
            "host": get_hostname(),
            "os": platform.platform(),
            "python_version": sys.version.split()[0],
        },
        "configuration": config,
        "summary": {
            "overall_risk_rating": severity_label(risk_score),
            "risk_score": risk_score,
            "finding_counts": finding_counts,
        },
        "observations": {
            "current_dns_servers": current_dns,
            "current_dns_ipv4": current_dns_ipv4,
            "current_dns_ipv6": current_dns_ipv6,
            "observed_dhcp_servers": dhcp_servers,
            "gateway_arp_claims": arp_analysis.get("gateway_claims", {}),
            "ips_with_multiple_arp_claims": arp_analysis.get("ips_with_multiple_arp_claims", {}),
            "tls_results": tls_results,
            "promisc_probe": promisc_result,
            "local_checks": local_results,
        },
        "findings": finding_dicts,
        "arp_neighbour_records": merged_records,
        "raw_evidence": {
            "arp_capture": arp_raw,
            "dhcp_capture": dhcp_raw,
        },
        "project_documentation": PROJECT_DOCUMENTATION,
        "recommended_defensive_actions": [
            "Enable DHCP snooping on managed switches.",
            "Enable Dynamic ARP Inspection where supported.",
            "Monitor gateway MAC changes and duplicate MAC mappings.",
            "Use encrypted protocols such as HTTPS, SSH, SFTP, TLS, and VPNs.",
            "Disable insecure cleartext protocols such as Telnet, FTP, and HTTP admin portals.",
            "Segment sensitive systems into dedicated VLANs.",
            "Investigate unexpected DNS and DHCP sources immediately.",
            "Use static ARP entries only for critical systems where operationally practical.",
            "Use switch telemetry, NAC, EDR, IDS, and SIEM monitoring for stronger validation.",
        ],
    }


def generate_text_report(report: Dict[str, Any]) -> str:
    lines: List[str] = []

    lines.append("=" * 80)
    lines.append("LAN GUARD EXECUTIVE SUMMARY REPORT")
    lines.append("=" * 80)
    lines.append(f"Tool: {report['tool']['name']} {report['tool']['version']}")
    lines.append(f"Report Time: {report['metadata']['report_time']}")
    lines.append(f"Host: {report['metadata']['host']}")
    lines.append(f"OS: {report['metadata']['os']}")
    lines.append(f"Interface: {report['configuration']['interface']}")
    lines.append(f"Gateway IP: {report['configuration']['gateway_ip']}")
    lines.append(f"Expected Gateway MAC: {report['configuration'].get('gateway_mac') or 'Not provided'}")
    lines.append(f"Expected DNS Servers: {report['configuration'].get('expected_dns') or 'Not provided'}")
    lines.append(f"Expected DHCP Servers: {report['configuration'].get('expected_dhcp') or 'Not provided'}")
    lines.append("")
    lines.append(f"Overall Risk Rating: {report['summary']['overall_risk_rating']}")
    lines.append(f"Risk Score: {report['summary']['risk_score']}")
    lines.append("")

    lines.append("Finding Counts")
    lines.append("-" * 80)
    for severity, count in report["summary"]["finding_counts"].items():
        lines.append(f"{severity}: {count}")
    lines.append("")

    for title, key in [
        ("What It Detects", "what_it_detects"),
        ("What It Does Not Detect", "what_it_does_not_detect"),
        ("Required Permissions", "required_permissions"),
        ("Supported Platforms", "supported_platforms"),
        ("False Positives", "false_positives"),
        ("Safe Lab Setup", "safe_lab_setup"),
        ("Example Reports", "example_reports"),
    ]:
        lines.append(title)
        lines.append("-" * 80)
        for item in report["project_documentation"][key]:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("Key Observations")
    lines.append("-" * 80)
    lines.append(f"Current DNS Servers: {report['observations']['current_dns_servers'] or 'None detected'}")
    lines.append(f"Current IPv4 DNS: {report['observations']['current_dns_ipv4'] or 'None detected'}")
    lines.append(f"Current IPv6 DNS: {report['observations']['current_dns_ipv6'] or 'None detected'}")
    lines.append(f"Observed DHCP Servers: {report['observations']['observed_dhcp_servers'] or 'None observed'}")
    lines.append(f"Gateway ARP Claims: {report['observations']['gateway_arp_claims'] or 'None observed'}")
    lines.append(f"TLS Checks: {report['observations']['tls_results'] or 'Not enabled'}")
    lines.append(f"Promiscuous Probe: {report['observations']['promisc_probe'] or 'Not enabled'}")
    lines.append("")

    lines.append("Findings")
    lines.append("-" * 80)
    for index, finding in enumerate(report["findings"], start=1):
        lines.append(f"{index}. {finding['title']}")
        lines.append(f"   Severity: {finding['severity']}")
        lines.append(f"   Confidence: {finding['confidence']}")
        lines.append(f"   Details: {finding['details']}")
        lines.append(f"   Recommendation: {finding['recommendation']}")
        lines.append("")

    lines.append("Observed ARP/Neighbour Table")
    lines.append("-" * 80)
    if report["arp_neighbour_records"]:
        lines.append(f"{'IP Address':<40} {'MAC Address(es)':<30} {'Source'}")
        lines.append("-" * 80)
        for ip_value, data in sorted(report["arp_neighbour_records"].items()):
            macs = ", ".join(data["macs"]) if data["macs"] else "unknown"
            sources = ", ".join(data["sources"])
            lines.append(f"{ip_value:<40} {macs:<30} {sources}")
    else:
        lines.append("No ARP/neighbour records found.")

    lines.append("")
    lines.append("Recommended Defensive Actions")
    lines.append("-" * 80)
    for index, action in enumerate(report["recommended_defensive_actions"], start=1):
        lines.append(f"{index}. {action}")

    lines.append("")
    lines.append("Raw ARP Capture")
    lines.append("-" * 80)
    lines.append(report["raw_evidence"]["arp_capture"] or "No ARP packets captured or tcpdump unavailable.")
    lines.append("")
    lines.append("Raw DHCP Capture")
    lines.append("-" * 80)
    lines.append(report["raw_evidence"]["dhcp_capture"] or "No DHCP packets captured or tcpdump unavailable.")
    lines.append("")

    return "\n".join(lines)


def generate_markdown_report(report: Dict[str, Any]) -> str:
    lines: List[str] = []

    lines.append("# LAN Guard Executive Summary Report")
    lines.append("")
    lines.append(f"**Tool:** {report['tool']['name']} {report['tool']['version']}")
    lines.append(f"**Report Time:** {report['metadata']['report_time']}")
    lines.append(f"**Host:** {report['metadata']['host']}")
    lines.append(f"**OS:** {report['metadata']['os']}")
    lines.append(f"**Interface:** `{report['configuration']['interface']}`")
    lines.append(f"**Gateway IP:** `{report['configuration']['gateway_ip']}`")
    lines.append(f"**Overall Risk Rating:** {report['summary']['overall_risk_rating']}")
    lines.append(f"**Risk Score:** {report['summary']['risk_score']}")
    lines.append("")

    lines.append("## Finding Counts")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for severity, count in report["summary"]["finding_counts"].items():
        lines.append(f"| {severity} | {count} |")
    lines.append("")

    for title, key in [
        ("What It Detects", "what_it_detects"),
        ("What It Does Not Detect", "what_it_does_not_detect"),
        ("Required Permissions", "required_permissions"),
        ("Supported Platforms", "supported_platforms"),
        ("False Positives", "false_positives"),
        ("Safe Lab Setup", "safe_lab_setup"),
        ("Example Reports", "example_reports"),
    ]:
        lines.append(f"## {title}")
        lines.append("")
        for item in report["project_documentation"][key]:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("## Key Observations")
    lines.append("")
    lines.append("| Observation | Value |")
    lines.append("|---|---|")
    lines.append(f"| Current DNS Servers | `{report['observations']['current_dns_servers']}` |")
    lines.append(f"| Current IPv4 DNS | `{report['observations']['current_dns_ipv4']}` |")
    lines.append(f"| Current IPv6 DNS | `{report['observations']['current_dns_ipv6']}` |")
    lines.append(f"| Observed DHCP Servers | `{report['observations']['observed_dhcp_servers']}` |")
    lines.append(f"| Gateway ARP Claims | `{report['observations']['gateway_arp_claims']}` |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for index, finding in enumerate(report["findings"], start=1):
        lines.append(f"### {index}. {finding['title']}")
        lines.append("")
        lines.append(f"- **Severity:** {finding['severity']}")
        lines.append(f"- **Confidence:** {finding['confidence']}")
        lines.append(f"- **Details:** {finding['details']}")
        lines.append(f"- **Recommendation:** {finding['recommendation']}")
        lines.append("")

    lines.append("## Observed ARP/Neighbour Table")
    lines.append("")
    lines.append("| IP Address | MAC Address(es) | Source |")
    lines.append("|---|---|---|")
    if report["arp_neighbour_records"]:
        for ip_value, data in sorted(report["arp_neighbour_records"].items()):
            macs = ", ".join(data["macs"]) if data["macs"] else "unknown"
            sources = ", ".join(data["sources"])
            lines.append(f"| `{ip_value}` | `{macs}` | `{sources}` |")
    else:
        lines.append("| None | None | None |")
    lines.append("")

    lines.append("## Recommended Defensive Actions")
    lines.append("")
    for action in report["recommended_defensive_actions"]:
        lines.append(f"- {action}")

    lines.append("")
    lines.append("## Raw ARP Capture")
    lines.append("")
    lines.append("```text")
    lines.append(report["raw_evidence"]["arp_capture"] or "No ARP packets captured or tcpdump unavailable.")
    lines.append("```")
    lines.append("")
    lines.append("## Raw DHCP Capture")
    lines.append("")
    lines.append("```text")
    lines.append(report["raw_evidence"]["dhcp_capture"] or "No DHCP packets captured or tcpdump unavailable.")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def write_reports(report: Dict[str, Any], output_format: str, output_dir: str) -> List[str]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    written: List[str] = []

    if output_format in ["txt", "text", "all"]:
        path = output_path / f"{REPORT_BASENAME}.txt"
        path.write_text(generate_text_report(report), encoding="utf-8")
        written.append(str(path))

    if output_format in ["json", "all"]:
        path = output_path / f"{REPORT_BASENAME}.json"
        path.write_text(json.dumps(report, indent=4), encoding="utf-8")
        written.append(str(path))

    if output_format in ["md", "markdown", "all"]:
        path = output_path / f"{REPORT_BASENAME}.md"
        path.write_text(generate_markdown_report(report), encoding="utf-8")
        written.append(str(path))

    return written


def print_executive_summary(report: Dict[str, Any]) -> None:
    print("\n" + "=" * 80)
    print("EXECUTIVE SUMMARY")
    print("=" * 80)
    print(f"Overall Risk Rating: {report['summary']['overall_risk_rating']}")
    print(f"Risk Score: {report['summary']['risk_score']}")
    print("")
    for severity, count in report["summary"]["finding_counts"].items():
        print(f"{severity}: {count}")
    print("")
    for finding in report["findings"]:
        print(f"- [{finding['severity']} / Confidence: {finding['confidence']}] {finding['title']}")


def build_baseline_data(config: Dict[str, Any], merged_records: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    current_dns = get_current_dns_servers()
    current_dns_ipv4, current_dns_ipv6 = split_dns_by_family(current_dns)

    gateway_mac = config.get("gateway_mac", "")
    if not gateway_mac and merged_records:
        gateway_macs_seen = merged_records.get(config["gateway_ip"], {}).get("macs", [])
        if gateway_macs_seen:
            gateway_mac = gateway_macs_seen[0]

    return {
        "created_at": utc_now(),
        "tool": {"name": APP_NAME, "version": APP_VERSION},
        "interface": config["interface"],
        "gateway_ip": config["gateway_ip"],
        "gateway_mac": gateway_mac,
        "dns_servers": current_dns,
        "dns_servers_ipv4": current_dns_ipv4,
        "dns_servers_ipv6": current_dns_ipv6,
        "dhcp_servers": config.get("expected_dhcp", []),
        "notes": "Created by LAN Guard",
    }


def command_baseline_create(args: argparse.Namespace) -> None:
    if not args.skip_deps_check:
        print_dependency_status()

    config = config_from_args(args) if args.non_interactive else prompt_user(args)

    ip_neigh_out, _, _ = get_ip_neigh()
    records = parse_ip_neigh(ip_neigh_out)
    if command_exists("arp"):
        arp_out, _, _ = get_arp_a()
        records.extend(parse_arp_a(arp_out))

    merged = merge_arp_records(records)
    baseline = build_baseline_data(config, merged)
    save_baseline(baseline, args.baseline_file)
    print(f"[+] Baseline saved to: {args.baseline_file}")


def command_baseline_show(args: argparse.Namespace) -> None:
    baseline = load_baseline(args.baseline_file)
    if not baseline:
        print(f"[!] No baseline found at: {args.baseline_file}")
        return
    print(json.dumps(baseline, indent=4))


def command_scan(args: argparse.Namespace) -> None:
    if not args.skip_deps_check:
        print_dependency_status()

    if not is_root():
        print("[!] Warning: root privileges are recommended for packet capture.")
        print("[!] Some checks may fail or produce incomplete results.\n")

    config = config_from_args(args) if args.non_interactive else prompt_user(args)

    print("\n" + "=" * 80)
    print("Starting LAN checks")
    print("=" * 80)

    print("\n[+] Collecting neighbour table using ip neigh...")
    ip_neigh_out, ip_neigh_err, _ = get_ip_neigh()
    if ip_neigh_err:
        print(f"[i] ip neigh note: {ip_neigh_err}")

    records = parse_ip_neigh(ip_neigh_out)

    if command_exists("arp"):
        print("[+] Collecting ARP cache using arp -a...")
        arp_a_out, arp_a_err, _ = get_arp_a()
        if arp_a_err:
            print(f"[i] arp -a note: {arp_a_err}")
        records.extend(parse_arp_a(arp_a_out))
    else:
        print("[i] Optional command arp is unavailable. Using ip neigh only.")

    merged_records = merge_arp_records(records)
    print_arp_table(merged_records)

    print(f"\n[+] Capturing ARP packets on {config['interface']} for {config['capture_seconds']} seconds...")
    arp_raw, arp_err, _ = capture_arp_packets(config["interface"], config["capture_seconds"])
    if arp_err:
        print(f"[i] ARP capture note: {arp_err}")

    arp_analysis = analyze_arp_capture(arp_raw, config["gateway_ip"])

    print(f"\n[+] Capturing DHCP packets on {config['interface']} for {config['capture_seconds']} seconds...")
    dhcp_raw, dhcp_err, _ = capture_dhcp_packets(config["interface"], config["capture_seconds"])
    if dhcp_err:
        print(f"[i] DHCP capture note: {dhcp_err}")

    dhcp_servers = analyze_dhcp_capture(dhcp_raw)

    print("\n[+] Checking current DNS servers...")
    current_dns = get_current_dns_servers()

    tls_results: List[Dict[str, Any]] = []
    if config.get("tls_hosts"):
        print(f"[+] Running TLS inspection checks for: {', '.join(config['tls_hosts'])}")
        tls_results = run_tls_checks(config["tls_hosts"], config.get("trusted_inspection_issuers", []))

    promisc_result = {"enabled": False, "status": "skipped", "results": []}
    if config.get("promisc_network"):
        print(f"[+] Running optional Scapy promiscuous-mode probe against {config['promisc_network']}...")
        promisc_result = run_promisc_probe(config["promisc_network"])

    local_results = run_local_checks(config.get("local_checks", False))
    if config.get("local_checks", False):
        print("[+] Running local endpoint checks...")

    baseline = load_baseline(args.baseline_file)

    findings, risk_score = generate_findings(
        config=config,
        merged_records=merged_records,
        arp_analysis=arp_analysis,
        dhcp_servers=dhcp_servers,
        current_dns=current_dns,
        baseline=baseline,
        tls_results=tls_results,
        promisc_result=promisc_result,
        local_results=local_results,
    )

    report = build_report_object(
        config=config,
        merged_records=merged_records,
        arp_raw=arp_raw,
        dhcp_raw=dhcp_raw,
        arp_analysis=arp_analysis,
        dhcp_servers=dhcp_servers,
        current_dns=current_dns,
        findings=findings,
        risk_score=risk_score,
        tls_results=tls_results,
        promisc_result=promisc_result,
        local_results=local_results,
    )

    written = write_reports(report, args.format, args.output_dir)
    print_executive_summary(report)

    print("")
    for path in written:
        print(f"[+] Report written to: {path}")

    should_save = args.save_baseline
    if not args.non_interactive and not should_save:
        should_save = input("\nSave current gateway MAC/DNS/DHCP as new baseline? [y/N]: ").strip().lower() == "y"

    if should_save:
        baseline_data = build_baseline_data(config, merged_records)
        dhcp_to_save = dhcp_servers or config.get("expected_dhcp", [])
        baseline_data["dhcp_servers"] = dhcp_to_save
        save_baseline(baseline_data, args.baseline_file)
        print(f"[+] Baseline saved to: {args.baseline_file}")

    print("\n[+] Done.")


def command_docs(_: argparse.Namespace) -> None:
    print(f"# {APP_NAME} {APP_VERSION}\n")
    for title, key in [
        ("What It Detects", "what_it_detects"),
        ("What It Does Not Detect", "what_it_does_not_detect"),
        ("Required Permissions", "required_permissions"),
        ("Supported Platforms", "supported_platforms"),
        ("False Positives", "false_positives"),
        ("Safe Lab Setup", "safe_lab_setup"),
        ("Example Reports", "example_reports"),
    ]:
        print(f"## {title}")
        for item in PROJECT_DOCUMENTATION[key]:
            print(f"- {item}")
        print("")


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--non-interactive", action="store_true", help="Run without prompts.")
    parser.add_argument("--interface", help="Network interface, e.g. eth0, ens33, wlan0")
    parser.add_argument("--gateway-ip", help="Expected gateway IP address")
    parser.add_argument("--gateway-mac", help="Expected gateway MAC address")
    parser.add_argument("--expected-dns", help="Comma-separated expected DNS server IPs. IPv4 and IPv6 supported.")
    parser.add_argument("--expected-dhcp", help="Comma-separated expected DHCP server IPs. Do not enter DHCP lease ranges.")
    parser.add_argument("--capture-seconds", type=int, default=30, help="ARP/DHCP capture duration in seconds. Default: 30")
    parser.add_argument("--baseline-file", default=BASELINE_FILE, help=f"Baseline file path. Default: {BASELINE_FILE}")
    parser.add_argument("--skip-deps-check", action="store_true", help="Skip dependency check output.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lan_guard.py",
        description="Defensive LAN MITM and sniffing indicator detector",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")

    subparsers = parser.add_subparsers(dest="command")

    deps_check = subparsers.add_parser("deps-check", help="Check required and optional dependencies")
    deps_check.set_defaults(func=lambda args: print_dependency_status())

    deps_install = subparsers.add_parser("deps-install", help="Install required dependencies safely")
    deps_install.add_argument("--include-optional", action="store_true", help="Also install optional dependencies when safely mapped")
    deps_install.set_defaults(func=lambda args: install_dependencies(args.include_optional))

    baseline_create = subparsers.add_parser("baseline-create", help="Create a LAN baseline")
    add_common_args(baseline_create)
    baseline_create.set_defaults(func=command_baseline_create)

    baseline_show = subparsers.add_parser("baseline-show", help="Show saved baseline")
    baseline_show.add_argument("--baseline-file", default=BASELINE_FILE, help=f"Baseline file path. Default: {BASELINE_FILE}")
    baseline_show.set_defaults(func=command_baseline_show)

    scan = subparsers.add_parser("scan", help="Run LAN Guard scan")
    add_common_args(scan)
    scan.add_argument("--format", default="all", choices=["text", "txt", "json", "markdown", "md", "all"], help="Report output format. Default: all")
    scan.add_argument("--output-dir", default=".", help="Directory to write reports. Default: current directory")
    scan.add_argument("--tls-check", default="", help="Comma-separated TLS inspection check hostnames, e.g. github.com,cloudflare.com")
    scan.add_argument("--trusted-inspection-issuers", default="", help="Comma-separated trusted TLS inspection issuer keywords, e.g. Zscaler,Fortinet")
    scan.add_argument("--promisc-network", default="", help="Optional Scapy promiscuous-mode probe network CIDR, e.g. 192.168.0.0/24")
    scan.add_argument("--local-checks", action="store_true", help="Run local endpoint PROMISC and packet-capture process checks")
    scan.add_argument("--save-baseline", action="store_true", help="Save current observations as baseline after scan")
    scan.set_defaults(func=command_scan)

    docs = subparsers.add_parser("docs", help="Print project documentation sections")
    docs.set_defaults(func=command_docs)

    return parser



# ---------------------------------------------------------------------------
# Extended community features (v0.5)
# ---------------------------------------------------------------------------

APP_VERSION = "0.5.0"
DEFAULT_HISTORY_FILE = os.path.expanduser("~/.lan_guard/history.jsonl")
DEFAULT_EVENTS_FILE = "lan_guard_events.jsonl"

PROFILES = {
    "home": {
        "capture_seconds": 30,
        "tls_hosts": ["github.com", "cloudflare.com", "google.com"],
        "local_checks": False,
        "passive_only": False,
    },
    "enterprise": {
        "capture_seconds": 45,
        "tls_hosts": ["github.com", "cloudflare.com", "microsoft.com"],
        "local_checks": True,
        "enable_name_resolution_monitor": True,
        "enable_ipv6_ra_monitor": True,
        "passive_only": False,
    },
    "lab": {
        "capture_seconds": 30,
        "tls_hosts": ["github.com", "cloudflare.com", "google.com"],
        "local_checks": True,
        "passive_only": False,
    },
    "passive": {
        "capture_seconds": 30,
        "tls_hosts": [],
        "promisc_network": "",
        "local_checks": False,
        "passive_only": True,
    },
}


def parse_simple_yaml(path: str) -> Dict[str, Any]:
    """Tiny YAML-like parser for simple key/value and list config files.

    This avoids requiring PyYAML. JSON config is preferred when possible.
    Supported:
      key: value
      key:
        - item1
        - item2
    """
    data: Dict[str, Any] = {}
    current_key: Optional[str] = None
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        raise ValueError(f"Could not read config file {path}: {exc}")

    for raw_line in lines:
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue

        if re.match(r"^\s+-\s+", line) and current_key:
            value = re.sub(r"^\s+-\s+", "", line).strip().strip('"').strip("'")
            if not isinstance(data.get(current_key), list):
                data[current_key] = []
            data[current_key].append(value)
            continue

        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().replace("-", "_")
            value = value.strip()
            current_key = key
            if value == "":
                data[key] = []
            elif value.lower() in ["true", "yes", "on"]:
                data[key] = True
            elif value.lower() in ["false", "no", "off"]:
                data[key] = False
            elif "," in value:
                data[key] = [x.strip() for x in value.split(",") if x.strip()]
            else:
                data[key] = value.strip('"').strip("'")
    return data


def load_config_file(path: str) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        raise ValueError(f"Config file not found: {path}")
    if p.suffix.lower() == ".json":
        return json.loads(p.read_text(encoding="utf-8"))
    return parse_simple_yaml(path)


def csv_or_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return parse_csv_strings(str(value))


def apply_profile_and_config(args: argparse.Namespace, config: Dict[str, Any]) -> Dict[str, Any]:
    profile = getattr(args, "profile", "") or config.get("profile", "")
    profile_defaults = PROFILES.get(profile, {}) if profile else {}

    merged = dict(profile_defaults)
    merged.update({k: v for k, v in config.items() if v is not None})

    # CLI flags override config/profile when provided.
    for attr in [
        "interface", "gateway_ip", "gateway_mac", "expected_dns", "expected_dhcp",
        "capture_seconds", "tls_check", "trusted_inspection_issuers",
        "promisc_network", "local_checks", "enable_name_resolution_monitor",
        "enable_ipv6_ra_monitor", "sensitivity"
    ]:
        if hasattr(args, attr):
            val = getattr(args, attr)
            if val not in [None, "", False]:
                key = "tls_hosts" if attr == "tls_check" else attr
                merged[key] = val

    return merged


def enhanced_config_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    file_config = load_config_file(getattr(args, "config", "") or "")
    merged = apply_profile_and_config(args, file_config)

    # Temporarily map merged values onto args-like object for the original parser.
    class Obj:
        pass
    proxy = Obj()
    detected_interface = get_default_interface()
    detected_gateway = get_default_gateway()
    detected_dns = get_current_dns_servers()
    setattr(proxy, "interface", merged.get("interface") or detected_interface)
    setattr(proxy, "gateway_ip", merged.get("gateway_ip") or detected_gateway)
    setattr(proxy, "gateway_mac", merged.get("gateway_mac") or get_gateway_mac_from_neigh(detected_gateway))
    expected_dns = merged.get("expected_dns")
    expected_dhcp = merged.get("expected_dhcp")
    if isinstance(expected_dns, list):
        expected_dns = ",".join(expected_dns)
    if isinstance(expected_dhcp, list):
        expected_dhcp = ",".join(expected_dhcp)
    setattr(proxy, "expected_dns", expected_dns if expected_dns is not None else ",".join(detected_dns))
    setattr(proxy, "expected_dhcp", expected_dhcp if expected_dhcp is not None else (proxy.gateway_ip or ""))
    setattr(proxy, "capture_seconds", int(merged.get("capture_seconds", getattr(args, "capture_seconds", 30)) or 30))
    setattr(proxy, "tls_check", ",".join(csv_or_list(merged.get("tls_hosts", merged.get("tls_check", "")))))
    setattr(proxy, "trusted_inspection_issuers", ",".join(csv_or_list(merged.get("trusted_inspection_issuers", ""))))
    setattr(proxy, "promisc_network", "" if merged.get("passive_only") else (merged.get("promisc_network", "") or ""))
    setattr(proxy, "local_checks", bool(merged.get("local_checks", False)))

    cfg = config_from_args(proxy)
    cfg["enable_name_resolution_monitor"] = bool(merged.get("enable_name_resolution_monitor", getattr(args, "enable_name_resolution_monitor", False)))
    cfg["enable_ipv6_ra_monitor"] = bool(merged.get("enable_ipv6_ra_monitor", getattr(args, "enable_ipv6_ra_monitor", False)))
    cfg["sensitivity"] = merged.get("sensitivity", getattr(args, "sensitivity", "normal"))
    cfg["profile"] = getattr(args, "profile", "") or file_config.get("profile", "")
    cfg["config_file"] = getattr(args, "config", "") or ""
    return cfg


def ensure_timestamped_output_dir(args: argparse.Namespace) -> str:
    output_dir = getattr(args, "output_dir", ".")
    if getattr(args, "timestamped_reports", False):
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_dir = str(Path(output_dir) / stamp)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    return output_dir


def generate_html_report(report: Dict[str, Any]) -> str:
    import html
    md = generate_markdown_report(report)
    # Dependency-free simple HTML wrapper. Markdown is placed in <pre> for faithful output.
    title = "LAN Guard Executive Summary Report"
    risk = html.escape(report["summary"]["overall_risk_rating"])
    body = html.escape(md)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; line-height: 1.5; }}
.badge {{ display:inline-block; padding:.25rem .5rem; border:1px solid #999; border-radius:.4rem; }}
pre {{ background:#f6f8fa; padding:1rem; overflow:auto; border-radius:.5rem; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p><strong>Risk:</strong> <span class="badge">{risk}</span></p>
<pre>{body}</pre>
</body>
</html>
"""


def write_reports(report: Dict[str, Any], output_format: str, output_dir: str) -> List[str]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    written: List[str] = []

    if output_format in ["txt", "text", "all"]:
        path = output_path / f"{REPORT_BASENAME}.txt"
        path.write_text(generate_text_report(report), encoding="utf-8")
        written.append(str(path))
    if output_format in ["json", "all"]:
        path = output_path / f"{REPORT_BASENAME}.json"
        path.write_text(json.dumps(report, indent=4), encoding="utf-8")
        written.append(str(path))
    if output_format in ["md", "markdown", "all"]:
        path = output_path / f"{REPORT_BASENAME}.md"
        path.write_text(generate_markdown_report(report), encoding="utf-8")
        written.append(str(path))
    if output_format in ["html", "all"]:
        path = output_path / f"{REPORT_BASENAME}.html"
        path.write_text(generate_html_report(report), encoding="utf-8")
        written.append(str(path))
    return written


def append_history(report: Dict[str, Any], history_file: str = DEFAULT_HISTORY_FILE) -> None:
    try:
        path = Path(os.path.expanduser(history_file))
        path.parent.mkdir(parents=True, exist_ok=True)
        event = {
            "timestamp": report["metadata"]["report_time"],
            "host": report["metadata"]["host"],
            "interface": report["configuration"].get("interface"),
            "gateway_ip": report["configuration"].get("gateway_ip"),
            "risk": report["summary"]["overall_risk_rating"],
            "risk_score": report["summary"]["risk_score"],
            "finding_counts": report["summary"]["finding_counts"],
            "dns": report["observations"].get("current_dns_servers", []),
            "dhcp": report["observations"].get("observed_dhcp_servers", []),
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as exc:
        print(f"[i] Could not append history: {exc}")


def write_events_jsonl(report: Dict[str, Any], path: str) -> Optional[str]:
    if not path:
        return None
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True) if p.parent != Path(".") else None
        with p.open("a", encoding="utf-8") as f:
            for finding in report.get("findings", []):
                event = {
                    "timestamp": report["metadata"]["report_time"],
                    "tool": report["tool"],
                    "host": report["metadata"]["host"],
                    "interface": report["configuration"].get("interface"),
                    "gateway_ip": report["configuration"].get("gateway_ip"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                    "title": finding.get("title"),
                    "details": finding.get("details"),
                    "recommendation": finding.get("recommendation"),
                }
                f.write(json.dumps(event) + "\n")
        return str(p)
    except Exception as exc:
        print(f"[i] Could not write events JSONL: {exc}")
        return None


def command_doctor(args: argparse.Namespace) -> None:
    print("=" * 80)
    print("LAN Guard Doctor")
    print("=" * 80)
    print_dependency_status()

    checks = []
    checks.append(("Running as root", is_root()))
    iface = getattr(args, "interface", None) or get_default_interface()
    checks.append((f"Interface detected ({iface or 'none'})", bool(iface)))
    gateway = getattr(args, "gateway_ip", None) or get_default_gateway()
    checks.append((f"Gateway detected ({gateway or 'none'})", bool(gateway)))
    checks.append(("tcpdump available", command_exists("tcpdump")))
    checks.append(("ip available", command_exists("ip")))
    checks.append(("Can resolve DNS", bool(get_current_dns_servers())))

    if gateway and command_exists("ping"):
        _, _, code = run_command(f"ping -c 1 -W 2 {gateway}", timeout=5)
        checks.append((f"Gateway reachable by ping ({gateway})", code == 0))

    out_dir = Path(getattr(args, "output_dir", "."))
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        test = out_dir / ".lan_guard_write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        checks.append((f"Can write reports to {out_dir}", True))
    except Exception:
        checks.append((f"Can write reports to {out_dir}", False))

    print("")
    for name, ok in checks:
        print(f"{'PASS' if ok else 'WARN':<5} {name}")

    print("\nRecommended next step:")
    print("  sudo python3 lan_guard.py scan")


def capture_name_resolution_packets(interface: str, seconds: int) -> Tuple[str, str, int]:
    if not command_exists("tcpdump"):
        return "", "tcpdump not found", 1
    filt = "udp port 5355 or udp port 5353 or udp port 137"
    return run_command(f"timeout {seconds} tcpdump -n -i {interface} '{filt}'", timeout=seconds + 10)


def analyze_name_resolution_capture(output: str) -> Dict[str, Any]:
    protocols = {"llmnr": 0, "mdns": 0, "nbns": 0, "wpad_mentions": 0}
    responders: Dict[str, int] = {}
    for line in output.splitlines():
        lower = line.lower()
        if ".5355" in line:
            protocols["llmnr"] += 1
        if ".5353" in line:
            protocols["mdns"] += 1
        if ".137" in line:
            protocols["nbns"] += 1
        if "wpad" in lower:
            protocols["wpad_mentions"] += 1
        m = re.search(r"IP\s+(\d{1,3}(?:\.\d{1,3}){3})\.\d+\s+>", line)
        if m:
            responders[m.group(1)] = responders.get(m.group(1), 0) + 1
    return {"counts": protocols, "responders": responders}


def capture_ipv6_ra_packets(interface: str, seconds: int) -> Tuple[str, str, int]:
    if not command_exists("tcpdump"):
        return "", "tcpdump not found", 1
    return run_command(f"timeout {seconds} tcpdump -n -i {interface} 'icmp6 and ip6[40] == 134'", timeout=seconds + 10)


def get_ipv6_default_routes() -> List[str]:
    if not command_exists("ip"):
        return []
    stdout, _, _ = run_command("ip -6 route show default", timeout=5)
    return [line for line in stdout.splitlines() if line.strip()]


def run_dns_consistency_checks(hosts: List[str]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if not hosts:
        return results
    if not command_exists("dig"):
        return [{"status": "skipped", "reason": "dig not installed", "host": h} for h in hosts]
    for host in hosts:
        item: Dict[str, Any] = {"host": host, "answers": {}}
        for resolver in ["system", "1.1.1.1", "8.8.8.8"]:
            if resolver == "system":
                cmd = f"dig +short {host} A"
            else:
                cmd = f"dig +short @{resolver} {host} A"
            stdout, stderr, code = run_command(cmd, timeout=8)
            answers = sorted([x.strip() for x in stdout.splitlines() if validate_ip(x.strip())])
            item["answers"][resolver] = answers
        public = set(item["answers"].get("1.1.1.1", [])) | set(item["answers"].get("8.8.8.8", []))
        system = set(item["answers"].get("system", []))
        item["possible_difference"] = bool(system and public and system.isdisjoint(public))
        results.append(item)
    return results


def load_oui_map(path: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not path or not Path(path).exists():
        return mapping
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            parts = [p.strip() for p in re.split(r",|\t", line, maxsplit=1)]
            if len(parts) >= 2:
                prefix = parts[0].replace("-", ":").replace(".", "").upper()
                if len(prefix) == 6 and ":" not in prefix:
                    prefix = ":".join([prefix[0:2], prefix[2:4], prefix[4:6]])
                mapping[prefix.upper()] = parts[1]
    except Exception:
        pass
    return mapping


def lookup_mac_vendor(mac: str, oui_map: Dict[str, str]) -> str:
    if not mac:
        return ""
    prefix = ":".join(mac.upper().split(":")[:3])
    return oui_map.get(prefix, "")


def apply_sensitivity(report: Dict[str, Any], sensitivity: str) -> None:
    report.setdefault("settings", {})["sensitivity"] = sensitivity
    if sensitivity == "high":
        report["summary"]["risk_score"] = min(100, report["summary"]["risk_score"] + 10)
    elif sensitivity == "low":
        report["summary"]["risk_score"] = max(0, report["summary"]["risk_score"] - 10)
    report["summary"]["overall_risk_rating"] = severity_label(report["summary"]["risk_score"])


def add_extended_observations_and_findings(
    report: Dict[str, Any],
    config: Dict[str, Any],
    args: argparse.Namespace,
    name_raw: str = "",
    ipv6_ra_raw: str = "",
) -> None:
    findings = report.setdefault("findings", [])
    observations = report.setdefault("observations", {})

    if name_raw:
        analysis = analyze_name_resolution_capture(name_raw)
        observations["name_resolution_monitor"] = analysis
        counts = analysis["counts"]
        if any(counts.values()):
            findings.append(asdict(Finding(
                title="Name-resolution traffic observed",
                severity="Low",
                confidence="Medium",
                details=f"Observed LLMNR/mDNS/NBNS/WPAD traffic: {counts}",
                recommendation="Consider disabling LLMNR/NBNS where not required and monitor WPAD responses.",
                evidence=analysis,
            )))

    if ipv6_ra_raw or getattr(args, "enable_ipv6_ra_monitor", False):
        routes = get_ipv6_default_routes()
        observations["ipv6_default_routes"] = routes
        observations["ipv6_router_advertisements_raw"] = ipv6_ra_raw
        if routes:
            findings.append(asdict(Finding(
                title="IPv6 default route present",
                severity="Informational",
                confidence="Medium",
                details=f"IPv6 default route(s): {routes}",
                recommendation="Validate IPv6 router advertisements and IPv6 DNS against your baseline.",
                evidence={"routes": routes, "ra_capture": ipv6_ra_raw},
            )))

    dns_hosts = csv_or_list(getattr(args, "dns_consistency_hosts", ""))
    if dns_hosts:
        dns_consistency = run_dns_consistency_checks(dns_hosts)
        observations["dns_consistency"] = dns_consistency
        for item in dns_consistency:
            if item.get("possible_difference"):
                findings.append(asdict(Finding(
                    title=f"DNS answer differs from public resolvers for {item['host']}",
                    severity="Low",
                    confidence="Low",
                    details=f"Resolver answers: {item.get('answers')}",
                    recommendation="Review carefully; CDN-backed domains can legitimately return different answers.",
                    evidence=item,
                )))

    # Offline OUI annotation
    oui_map = load_oui_map(getattr(args, "oui_file", "") or "")
    if oui_map:
        for ip_value, data in report.get("arp_neighbour_records", {}).items():
            vendors = {}
            for mac in data.get("macs", []):
                vendor = lookup_mac_vendor(mac, oui_map)
                if vendor:
                    vendors[mac] = vendor
            if vendors:
                data["vendors"] = vendors

    # TLS baseline pinning
    tls_baseline_path = getattr(args, "tls_baseline_file", "") or ""
    if tls_baseline_path and report.get("tls_results"):
        tls_base = load_baseline(tls_baseline_path)
        new_base = tls_base.copy() if isinstance(tls_base, dict) else {}
        changed = []
        for item in report["tls_results"]:
            host = item.get("hostname") or item.get("host")
            issuer = item.get("issuer") or item.get("issuer_common_name")
            fp = item.get("fingerprint_sha256")
            if not host:
                continue
            old = new_base.get(host)
            current = {"issuer": issuer, "fingerprint_sha256": fp}
            if old and (old.get("issuer") != issuer or old.get("fingerprint_sha256") != fp):
                changed.append({"host": host, "old": old, "current": current})
            new_base[host] = current
        if changed:
            findings.append(asdict(Finding(
                title="TLS certificate baseline changed",
                severity="Medium",
                confidence="Medium",
                details=f"TLS baseline changes: {changed}",
                recommendation="Confirm whether TLS inspection, certificate rotation, or proxy changes are expected.",
                evidence={"changes": changed},
            )))
        if getattr(args, "save_tls_baseline", False):
            save_baseline(new_base, tls_baseline_path)


def command_scan(args: argparse.Namespace) -> None:
    if getattr(args, "dry_run", False):
        config = enhanced_config_from_args(args) if args.non_interactive else prompt_user(args)
        print("Dry run: LAN Guard would perform the following actions:")
        print(json.dumps({
            "config": config,
            "reports": getattr(args, "format", "all"),
            "output_dir": getattr(args, "output_dir", "."),
            "timestamped_reports": getattr(args, "timestamped_reports", False),
            "history": getattr(args, "history_file", DEFAULT_HISTORY_FILE),
            "events_jsonl": getattr(args, "events_jsonl", ""),
        }, indent=2))
        return

    if not getattr(args, "skip_deps_check", False) and not getattr(args, "quiet", False):
        print_dependency_status()

    if not is_root() and not getattr(args, "quiet", False):
        print("[!] Warning: root privileges are recommended for packet capture.")
        print("[!] Some checks may fail or produce incomplete results.\n")

    config = enhanced_config_from_args(args) if args.non_interactive else prompt_user(args)

    if not getattr(args, "quiet", False):
        print("\n" + "=" * 80)
        print("Starting LAN checks")
        print("=" * 80)

    ip_neigh_out, ip_neigh_err, _ = get_ip_neigh()
    if ip_neigh_err and not getattr(args, "quiet", False):
        print(f"[i] ip neigh note: {ip_neigh_err}")
    records = parse_ip_neigh(ip_neigh_out)

    if command_exists("arp"):
        arp_a_out, arp_a_err, _ = get_arp_a()
        if arp_a_err and not getattr(args, "quiet", False):
            print(f"[i] arp -a note: {arp_a_err}")
        records.extend(parse_arp_a(arp_a_out))

    merged_records = merge_arp_records(records)
    if not getattr(args, "quiet", False):
        print_arp_table(merged_records)

    arp_raw, arp_err, _ = capture_arp_packets(config["interface"], config["capture_seconds"])
    arp_analysis = analyze_arp_capture(arp_raw, config["gateway_ip"])

    dhcp_raw, dhcp_err, _ = capture_dhcp_packets(config["interface"], config["capture_seconds"])
    dhcp_servers = analyze_dhcp_capture(dhcp_raw)

    current_dns = get_current_dns_servers()

    tls_results: List[Dict[str, Any]] = []
    if config.get("tls_hosts"):
        tls_results = run_tls_checks(config["tls_hosts"], config.get("trusted_inspection_issuers", []))

    promisc_result = {"enabled": False, "status": "skipped", "results": []}
    if config.get("promisc_network"):
        promisc_result = run_promisc_probe(config["promisc_network"])

    local_results = run_local_checks(config.get("local_checks", False))
    baseline = load_baseline(args.baseline_file)

    findings, risk_score = generate_findings(
        config=config,
        merged_records=merged_records,
        arp_analysis=arp_analysis,
        dhcp_servers=dhcp_servers,
        current_dns=current_dns,
        baseline=baseline,
        tls_results=tls_results,
        promisc_result=promisc_result,
        local_results=local_results,
    )

    name_raw = ""
    if getattr(args, "enable_name_resolution_monitor", False) or config.get("enable_name_resolution_monitor"):
        name_raw, _, _ = capture_name_resolution_packets(config["interface"], max(5, min(30, config["capture_seconds"])))

    ipv6_ra_raw = ""
    if getattr(args, "enable_ipv6_ra_monitor", False) or config.get("enable_ipv6_ra_monitor"):
        ipv6_ra_raw, _, _ = capture_ipv6_ra_packets(config["interface"], max(5, min(30, config["capture_seconds"])))

    report = build_report_object(
        config=config,
        merged_records=merged_records,
        arp_raw=arp_raw,
        dhcp_raw=dhcp_raw,
        arp_analysis=arp_analysis,
        dhcp_servers=dhcp_servers,
        current_dns=current_dns,
        findings=findings,
        risk_score=risk_score,
        tls_results=tls_results,
        promisc_result=promisc_result,
        local_results=local_results,
    )
    add_extended_observations_and_findings(report, config, args, name_raw, ipv6_ra_raw)
    apply_sensitivity(report, getattr(args, "sensitivity", "normal"))

    output_dir = ensure_timestamped_output_dir(args)
    written = write_reports(report, args.format, output_dir)
    append_history(report, getattr(args, "history_file", DEFAULT_HISTORY_FILE))
    events_path = write_events_jsonl(report, getattr(args, "events_jsonl", ""))

    if getattr(args, "quiet", False):
        print(f"Risk: {report['summary']['overall_risk_rating']} | Findings: {len(report.get('findings', []))} | Report dir: {output_dir}")
    else:
        print_executive_summary(report)
        print("")
        for path in written:
            print(f"[+] Report written to: {path}")
        if events_path:
            print(f"[+] Events JSONL written to: {events_path}")

    should_save = getattr(args, "save_baseline", False)
    if not args.non_interactive and not should_save:
        should_save = input("\nSave current gateway MAC/DNS/DHCP as new baseline? [y/N]: ").strip().lower() == "y"
    if should_save:
        baseline_data = build_baseline_data(config, merged_records)
        baseline_data["dhcp_servers"] = dhcp_servers or config.get("expected_dhcp", [])
        baseline_data["history_file"] = getattr(args, "history_file", DEFAULT_HISTORY_FILE)
        save_baseline(baseline_data, args.baseline_file)
        if not getattr(args, "quiet", False):
            print(f"[+] Baseline saved to: {args.baseline_file}")

    if getattr(args, "exit_code_on_risk", False):
        risk = report["summary"]["overall_risk_rating"]
        code = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}.get(risk, 0)
        sys.exit(code)


def command_schedule(args: argparse.Namespace) -> None:
    print("=" * 80)
    print("LAN Guard Scheduler")
    print("=" * 80)

    script_path = Path(getattr(args, "script_path", "") or sys.argv[0]).resolve()
    python_bin = sys.executable

    frequency = getattr(args, "frequency", "") or input("Schedule frequency [daily/weekly/monthly/once]: ").strip().lower()
    if frequency not in ["daily", "weekly", "monthly", "once"]:
        raise ValueError("Frequency must be daily, weekly, monthly, or once.")

    date_value = getattr(args, "date", "") or ""
    time_value = getattr(args, "time", "") or input("Run time HH:MM, e.g. 02:30: ").strip()
    if not re.match(r"^\d{2}:\d{2}$", time_value):
        raise ValueError("Time must be HH:MM.")
    hour, minute = time_value.split(":")

    if frequency == "weekly":
        day = getattr(args, "day", "") or input("Day of week [mon/tue/wed/thu/fri/sat/sun]: ").strip().lower()
        dow_map = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
        if day not in dow_map:
            raise ValueError("Invalid day of week.")
        cron_time = f"{minute} {hour} * * {dow_map[day]}"
    elif frequency == "monthly":
        dom = getattr(args, "day", "") or input("Day of month [1-28 recommended]: ").strip()
        if not dom.isdigit() or not (1 <= int(dom) <= 31):
            raise ValueError("Invalid day of month.")
        cron_time = f"{minute} {hour} {int(dom)} * *"
    elif frequency == "daily":
        cron_time = f"{minute} {hour} * * *"
    else:
        date_value = date_value or input("Run date YYYY-MM-DD: ").strip()
        cron_time = None

    output_dir = getattr(args, "output_dir", "reports")
    scan_args = getattr(args, "scan_args", "") or "--non-interactive --format all --timestamped-reports --quiet"
    command = f"cd {script_path.parent} && {python_bin} {script_path} scan {scan_args} --output-dir {output_dir}"

    if frequency == "once":
        at_cmd = f'echo "{command}" | at {time_value} {date_value}'
        print("\nOne-time schedule command:")
        print(at_cmd)
        if getattr(args, "install", False):
            if not command_exists("at"):
                print("[!] 'at' is not installed. Install it or run the command manually.")
            else:
                stdout, stderr, code = run_command(at_cmd, timeout=10)
                print(stdout or stderr)
        return

    cron_line = f"{cron_time} {command} # LAN_GUARD_AUTORUN"
    cron_file = Path(getattr(args, "cron_file", "lan_guard_schedule.cron"))
    cron_file.write_text(cron_line + "\n", encoding="utf-8")

    print("\nCron entry:")
    print(cron_line)
    print(f"\n[+] Written to: {cron_file}")

    if getattr(args, "install", False):
        existing, _, _ = run_command("crontab -l 2>/dev/null", timeout=10)
        new_cron = "\n".join([line for line in existing.splitlines() if "LAN_GUARD_AUTORUN" not in line] + [cron_line]) + "\n"
        tmp = Path("/tmp/lan_guard_crontab")
        tmp.write_text(new_cron, encoding="utf-8")
        stdout, stderr, code = run_command(f"crontab {tmp}", timeout=10)
        if code == 0:
            print("[+] Crontab installed/updated.")
        else:
            print(f"[!] Failed to install crontab: {stderr or stdout}")


def command_analyze_switch(args: argparse.Namespace) -> None:
    path = Path(args.file)
    if not path.exists():
        raise ValueError(f"Switch output file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    macs = re.findall(r"([0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", text)
    normalized = []
    for m in macs:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", m).lower()
        if len(cleaned) == 12:
            normalized.append(":".join(cleaned[i:i+2] for i in range(0, 12, 2)))
    counts = {m: normalized.count(m) for m in sorted(set(normalized))}
    possible_flaps = {m: c for m, c in counts.items() if c > 1}
    result = {
        "file": str(path),
        "vendor": args.vendor,
        "mac_count": len(normalized),
        "unique_mac_count": len(counts),
        "macs_seen_multiple_times": possible_flaps,
        "note": "Generic parser. Review switch context manually for port moves, gateway MAC location, and DHCP snooping bindings.",
    }
    print(json.dumps(result, indent=4))


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--non-interactive", action="store_true", help="Run without prompts.")
    parser.add_argument("--config", default="", help="JSON or simple YAML config file.")
    parser.add_argument("--profile", choices=["home", "enterprise", "lab", "passive"], default="", help="Preset scan profile.")
    parser.add_argument("--interface", help="Network interface, e.g. eth0, ens33, wlan0")
    parser.add_argument("--gateway-ip", help="Expected gateway IP address")
    parser.add_argument("--gateway-mac", help="Expected gateway MAC address")
    parser.add_argument("--expected-dns", help="Comma-separated expected DNS server IPs. IPv4 and IPv6 supported.")
    parser.add_argument("--expected-dhcp", help="Comma-separated expected DHCP server IPs. Do not enter DHCP lease ranges.")
    parser.add_argument("--capture-seconds", type=int, default=30, help="ARP/DHCP capture duration in seconds. Default: 30")
    parser.add_argument("--baseline-file", default=BASELINE_FILE, help=f"Baseline file path. Default: {BASELINE_FILE}")
    parser.add_argument("--skip-deps-check", action="store_true", help="Skip dependency check output.")
    parser.add_argument("--sensitivity", choices=["low", "normal", "high"], default="normal", help="Finding sensitivity/risk scoring adjustment.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lan_guard.py",
        description="Defensive LAN MITM and sniffing indicator detector",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    deps_check = subparsers.add_parser("deps-check", help="Check required and optional dependencies")
    deps_check.set_defaults(func=lambda args: print_dependency_status())

    deps_install = subparsers.add_parser("deps-install", help="Install required dependencies safely")
    deps_install.add_argument("--include-optional", action="store_true", help="Also install optional dependencies when safely mapped")
    deps_install.set_defaults(func=lambda args: install_dependencies(args.include_optional))

    doctor = subparsers.add_parser("doctor", help="Diagnose setup, permissions, interface, capture, DNS, and report paths")
    doctor.add_argument("--interface", help="Network interface to validate")
    doctor.add_argument("--gateway-ip", help="Gateway IP to ping")
    doctor.add_argument("--output-dir", default=".", help="Report output directory to test")
    doctor.set_defaults(func=command_doctor)

    baseline_create = subparsers.add_parser("baseline-create", help="Create a LAN baseline")
    add_common_args(baseline_create)
    baseline_create.set_defaults(func=command_baseline_create)

    baseline_show = subparsers.add_parser("baseline-show", help="Show saved baseline")
    baseline_show.add_argument("--baseline-file", default=BASELINE_FILE, help=f"Baseline file path. Default: {BASELINE_FILE}")
    baseline_show.set_defaults(func=command_baseline_show)

    scan = subparsers.add_parser("scan", help="Run LAN Guard scan")
    add_common_args(scan)
    scan.add_argument("--format", default="all", choices=["text", "txt", "json", "markdown", "md", "html", "all"], help="Report output format. Default: all")
    scan.add_argument("--output-dir", default="reports", help="Directory to write reports. Default: reports")
    scan.add_argument("--timestamped-reports", action="store_true", help="Write reports to a timestamped subdirectory.")
    scan.add_argument("--tls-check", default="", help="Comma-separated TLS inspection check hostnames, e.g. github.com,cloudflare.com")
    scan.add_argument("--trusted-inspection-issuers", default="", help="Comma-separated trusted TLS inspection issuer keywords, e.g. Zscaler,Fortinet")
    scan.add_argument("--tls-baseline-file", default="", help="Optional TLS certificate baseline JSON file.")
    scan.add_argument("--save-tls-baseline", action="store_true", help="Update TLS baseline file after scan.")
    scan.add_argument("--promisc-network", default="", help="Optional Scapy promiscuous-mode probe network CIDR, e.g. 192.168.0.0/24")
    scan.add_argument("--local-checks", action="store_true", help="Run local endpoint PROMISC and packet-capture process checks")
    scan.add_argument("--enable-name-resolution-monitor", action="store_true", help="Capture LLMNR/NBNS/mDNS/WPAD indicators.")
    scan.add_argument("--enable-ipv6-ra-monitor", action="store_true", help="Capture IPv6 Router Advertisement indicators.")
    scan.add_argument("--dns-consistency-hosts", default="", help="Comma-separated domains to compare system DNS against public resolvers.")
    scan.add_argument("--oui-file", default="", help="Offline OUI CSV file for MAC vendor annotations.")
    scan.add_argument("--save-baseline", action="store_true", help="Save current observations as baseline after scan")
    scan.add_argument("--history-file", default=DEFAULT_HISTORY_FILE, help="JSONL history file. Default: ~/.lan_guard/history.jsonl")
    scan.add_argument("--events-jsonl", default="", help="Write one JSONL event per finding for SIEM ingestion.")
    scan.add_argument("--dry-run", action="store_true", help="Show planned actions without capturing packets.")
    scan.add_argument("--quiet", action="store_true", help="Minimal output for automation.")
    scan.add_argument("--verbose", action="store_true", help="Reserved for detailed debug output.")
    scan.add_argument("--exit-code-on-risk", action="store_true", help="Exit 1/2/3 for Low/Medium/High risk.")
    scan.set_defaults(func=command_scan)

    schedule = subparsers.add_parser("schedule", help="Create daily/weekly/monthly/once autorun schedule")
    schedule.add_argument("--frequency", choices=["daily", "weekly", "monthly", "once"], default="", help="Schedule frequency")
    schedule.add_argument("--date", default="", help="Date for once schedules, YYYY-MM-DD")
    schedule.add_argument("--time", default="", help="Run time HH:MM")
    schedule.add_argument("--day", default="", help="Day of week for weekly or day of month for monthly")
    schedule.add_argument("--script-path", default="", help="Path to lan_guard.py. Default: current script")
    schedule.add_argument("--output-dir", default="reports", help="Report output directory")
    schedule.add_argument("--scan-args", default="", help="Arguments passed to scan command")
    schedule.add_argument("--cron-file", default="lan_guard_schedule.cron", help="Write cron entry to this file")
    schedule.add_argument("--install", action="store_true", help="Install into current user's crontab or at queue")
    schedule.set_defaults(func=command_schedule)

    analyze_switch = subparsers.add_parser("analyze-switch", help="Analyze pasted/exported switch telemetry text")
    analyze_switch.add_argument("--vendor", default="generic", help="Switch vendor, e.g. cisco, aruba, juniper")
    analyze_switch.add_argument("--file", required=True, help="Switch output text file")
    analyze_switch.set_defaults(func=command_analyze_switch)

    docs = subparsers.add_parser("docs", help="Print project documentation sections")
    docs.set_defaults(func=command_docs)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        args.command = "scan"
        args.non_interactive = False
        args.interface = None
        args.gateway_ip = None
        args.gateway_mac = None
        args.expected_dns = None
        args.expected_dhcp = None
        args.capture_seconds = 30
        args.baseline_file = BASELINE_FILE
        args.skip_deps_check = False
        args.format = "all"
        args.output_dir = "."
        args.tls_check = ""
        args.trusted_inspection_issuers = ""
        args.promisc_network = ""
        args.local_checks = False
        args.save_baseline = False
        args.func = command_scan

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
    except ValueError as exc:
        print(f"[!] Input error: {exc}")
        sys.exit(2)
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
