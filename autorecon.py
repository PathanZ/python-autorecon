"""
Python AutoRecon
Modular reconnaissance tool for pentest engagements
Modules: Nmap, Whois, DNS, HTTP Headers, Subdomains, Banner Grab, SSL/TLS
"""

import os
import json
import csv
import socket
import datetime
import argparse
import requests
import dns.resolver
import nmap
import whois
import ssl
from dataclasses import dataclass, field, asdict
from typing import Optional


# ─── Data Model ────────────────────────────────────────────────────────────────

@dataclass
class ReconResult:
    target: str
    timestamp: str = ""

    # Nmap
    open_ports: list = field(default_factory=list)       # [{port, protocol, state, service, version}]

    # Whois
    whois_registrar: str = ""
    whois_creation_date: str = ""
    whois_expiry_date: str = ""
    whois_org: str = ""
    whois_country: str = ""

    # DNS
    dns_a: list = field(default_factory=list)
    dns_mx: list = field(default_factory=list)
    dns_ns: list = field(default_factory=list)
    dns_txt: list = field(default_factory=list)

    # HTTP Headers
    http_status: int = 0
    http_server: str = ""
    http_headers: dict = field(default_factory=dict)
    http_missing_headers: list = field(default_factory=list)

    # Subdomains
    subdomains_found: list = field(default_factory=list)

    # Banner Grabbing
    banners: list = field(default_factory=list)          # [{port, banner}]

    # SSL/TLS
    ssl_subject: str = ""
    ssl_issuer: str = ""
    ssl_expiry: str = ""
    ssl_expired: bool = False
    ssl_days_remaining: int = 0

    errors: list = field(default_factory=list)


# ─── Modules ───────────────────────────────────────────────────────────────────

def run_nmap(target: str, result: ReconResult):
    print("  [*] Nmap port scan...")
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments="-sV -T4 --top-ports 1000")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    svc = nm[host][proto][port]
                    result.open_ports.append({
                        "port":     port,
                        "protocol": proto,
                        "state":    svc["state"],
                        "service":  svc["name"],
                        "version":  svc.get("version", ""),
                    })
        print(f"  [+] Found {len(result.open_ports)} open port(s)")
    except Exception as e:
        result.errors.append(f"Nmap: {e}")
        print(f"  [!] Nmap error: {e}")


def run_whois(target: str, result: ReconResult):
    print("  [*] Whois lookup...")
    try:
        w = whois.whois(target)
        result.whois_registrar     = str(w.registrar or "")
        result.whois_org           = str(w.org or "")
        result.whois_country       = str(w.country or "")

        cd = w.creation_date
        result.whois_creation_date = str(cd[0] if isinstance(cd, list) else cd or "")

        ed = w.expiration_date
        result.whois_expiry_date   = str(ed[0] if isinstance(ed, list) else ed or "")

        print(f"  [+] Registrar: {result.whois_registrar}")
    except Exception as e:
        result.errors.append(f"Whois: {e}")
        print(f"  [!] Whois error: {e}")


def run_dns(target: str, result: ReconResult):
    print("  [*] DNS enumeration...")
    record_types = {"A": "dns_a", "MX": "dns_mx", "NS": "dns_ns", "TXT": "dns_txt"}
    for rtype, attr in record_types.items():
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            records = [str(r) for r in answers]
            setattr(result, attr, records)
            print(f"  [+] {rtype}: {len(records)} record(s)")
        except Exception:
            pass


def run_http_headers(target: str, result: ReconResult):
    print("  [*] HTTP header analysis...")
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{target}", timeout=8, allow_redirects=True)
            result.http_status  = r.status_code
            result.http_server  = r.headers.get("Server", "")
            result.http_headers = dict(r.headers)
            result.http_missing_headers = [
                h for h in security_headers if h not in r.headers
            ]
            print(f"  [+] Status: {result.http_status} | Missing security headers: {len(result.http_missing_headers)}")
            break
        except Exception as e:
            result.errors.append(f"HTTP ({scheme}): {e}")


def run_subdomains(target: str, result: ReconResult):
    print("  [*] Subdomain enumeration...")
    wordlist = [
        "www", "mail", "ftp", "admin", "dev", "staging", "api", "vpn",
        "portal", "remote", "blog", "shop", "secure", "test", "mx",
        "webmail", "ns1", "ns2", "autodiscover", "lyncdiscover", "sip",
    ]
    found = []
    for sub in wordlist:
        subdomain = f"{sub}.{target}"
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(subdomain)
            found.append({"subdomain": subdomain, "ip": ip})
            print(f"  [+] Found: {subdomain} → {ip}")
        except socket.gaierror:
            pass
    result.subdomains_found = found
    print(f"  [+] {len(found)} subdomain(s) found")


def run_banner_grab(result: ReconResult):
    print("  [*] Banner grabbing...")
    banners = []
    for port_info in result.open_ports[:10]:   # limit to first 10 ports
        port = port_info["port"]
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((result.target, port))
            try:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            s.close()
            if banner:
                banners.append({"port": port, "banner": banner[:300]})
                print(f"  [+] Port {port}: {banner[:60]}...")
        except Exception:
            pass
    result.banners = banners


def run_ssl(target: str, result: ReconResult):
    print("  [*] SSL/TLS check...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(8)
            s.connect((target, 443))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        expiry_str = cert.get("notAfter", "")

        result.ssl_subject = subject.get("commonName", "")
        result.ssl_issuer  = issuer.get("organizationName", "")
        result.ssl_expiry  = expiry_str

        if expiry_str:
            expiry_dt = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.datetime.utcnow()).days
            result.ssl_days_remaining = days_left
            result.ssl_expired = days_left < 0
            print(f"  [+] Cert valid for {days_left} more day(s) | Issuer: {result.ssl_issuer}")
    except Exception as e:
        result.errors.append(f"SSL: {e}")
        print(f"  [!] SSL error: {e}")


# ─── Output ────────────────────────────────────────────────────────────────────

def print_summary(result: ReconResult):
    print("\n" + "="*60)
    print(f"  RECON SUMMARY — {result.target}")
    print("="*60)
    print(f"  Open ports    : {len(result.open_ports)}")
    print(f"  Subdomains    : {len(result.subdomains_found)}")
    print(f"  DNS records   : A={len(result.dns_a)} MX={len(result.dns_mx)} NS={len(result.dns_ns)}")
    print(f"  HTTP status   : {result.http_status} | Server: {result.http_server}")
    print(f"  Missing headers: {len(result.http_missing_headers)}")
    print(f"  SSL expiry    : {result.ssl_expiry} ({result.ssl_days_remaining} days)")
    print(f"  Errors        : {len(result.errors)}")
    print("="*60 + "\n")


def save_json(result: ReconResult, path: str):
    with open(path, "w") as f:
        json.dump(asdict(result), f, indent=2)
    print(f"  [+] JSON saved → {path}")


def save_csv(result: ReconResult, path: str):
    flat = {
        "target":                result.target,
        "timestamp":             result.timestamp,
        "open_ports_count":      len(result.open_ports),
        "open_ports":            ", ".join(str(p["port"]) for p in result.open_ports),
        "subdomains_count":      len(result.subdomains_found),
        "subdomains":            ", ".join(s["subdomain"] for s in result.subdomains_found),
        "dns_a":                 ", ".join(result.dns_a),
        "dns_mx":                ", ".join(result.dns_mx),
        "dns_ns":                ", ".join(result.dns_ns),
        "whois_registrar":       result.whois_registrar,
        "whois_org":             result.whois_org,
        "whois_country":         result.whois_country,
        "whois_expiry":          result.whois_expiry_date,
        "http_status":           result.http_status,
        "http_server":           result.http_server,
        "missing_headers":       ", ".join(result.http_missing_headers),
        "ssl_expiry":            result.ssl_expiry,
        "ssl_days_remaining":    result.ssl_days_remaining,
        "ssl_expired":           result.ssl_expired,
        "errors":                ", ".join(result.errors),
    }
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=flat.keys())
        w.writeheader()
        w.writerow(flat)
    print(f"  [+] CSV saved  → {path}")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Python AutoRecon — Modular Recon Tool")
    parser.add_argument("target", help="Target IP or domain (e.g. example.com)")
    parser.add_argument("--out", default="output", help="Output directory (default: output)")
    parser.add_argument("--skip", nargs="*", default=[],
                        help="Modules to skip: nmap whois dns http subdomains banners ssl")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    target = args.target.replace("https://", "").replace("http://", "").rstrip("/")

    print(f"\n[*] AutoRecon starting on target: {target}\n")

    result = ReconResult(
        target=target,
        timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )

    if "nmap"       not in args.skip: run_nmap(target, result)
    if "whois"      not in args.skip: run_whois(target, result)
    if "dns"        not in args.skip: run_dns(target, result)
    if "http"       not in args.skip: run_http_headers(target, result)
    if "subdomains" not in args.skip: run_subdomains(target, result)
    if "banners"    not in args.skip: run_banner_grab(result)
    if "ssl"        not in args.skip: run_ssl(target, result)

    print_summary(result)

    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    save_json(result, f"{args.out}/recon_{target}_{ts}.json")
    save_csv (result, f"{args.out}/recon_{target}_{ts}.csv")

    print(f"[✓] AutoRecon complete — results saved to {args.out}/")


if __name__ == "__main__":
    main()
