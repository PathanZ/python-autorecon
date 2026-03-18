# Python AutoRecon

A modular Python-based reconnaissance tool that automates 7 recon techniques into a single workflow, generating structured JSON and CSV reports for pentest engagements.

Built as part of a SOC/Pentesting home lab series.

## Features

- **Nmap port scanning** — top 1000 ports with service and version detection
- **Whois lookup** — registrar, org, country, creation and expiry dates
- **DNS enumeration** — A, MX, NS, TXT records
- **HTTP header analysis** — detects missing security headers
- **Subdomain enumeration** — wordlist-based subdomain discovery
- **Banner grabbing** — grabs service banners from open ports
- **SSL/TLS check** — certificate expiry, issuer, days remaining

## Architecture

```
Target (IP / Domain)
        │
        ▼
┌───────────────────────────────────────┐
│            AutoRecon Engine           │
├──────────┬──────────┬─────────────────┤
│  Nmap    │  Whois   │  DNS Enum       │
│  Banners │  HTTP    │  Subdomains     │
│          │  SSL/TLS │                 │
└──────────┴──────────┴─────────────────┘
        │
        ▼
  JSON Report + CSV Report
```

## Setup

### 1. Clone & install

```bash
git clone https://github.com/PathanZ/python-autorecon.git
cd python-autorecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Install Nmap binary

```bash
# Linux / WSL
sudo apt install nmap -y

# macOS
brew install nmap
```

## Usage

### Basic scan
```bash
python3 autorecon.py example.com
```

### Specify output directory
```bash
python3 autorecon.py example.com --out reports/
```

### Skip specific modules
```bash
python3 autorecon.py example.com --skip ssl subdomains
```

### Safe test target
```bash
python3 autorecon.py scanme.nmap.org --out output/
```
> `scanme.nmap.org` is provided by Nmap for legal scanning practice.

## Output

Results are saved to the output directory:

```
output/
  recon_example.com_20260318_210229.json   ← full structured data
  recon_example.com_20260318_210229.csv    ← flat summary for spreadsheet
```

## Sample Output

```
============================================================
  RECON SUMMARY — scanme.nmap.org
============================================================
  Open ports    : 4
  Subdomains    : 0
  DNS records   : A=1 MX=0 NS=0
  HTTP status   : 200 | Server: Apache/2.4.7 (Ubuntu)
  Missing headers: 6
  SSL expiry    : N/A
  Errors        : 1
============================================================
```

## Security Headers Checked

| Header | Purpose |
|---|---|
| Strict-Transport-Security | Forces HTTPS |
| Content-Security-Policy | Prevents XSS |
| X-Frame-Options | Prevents clickjacking |
| X-Content-Type-Options | Prevents MIME sniffing |
| Referrer-Policy | Controls referrer info |
| Permissions-Policy | Controls browser features |

## Project Structure

```
python-autorecon/
├── autorecon.py       # Main script
├── requirements.txt
├── .gitignore
└── README.md
```

## Extending This Project

- Add **CVE lookup** based on detected service versions
- Integrate **Shodan API** for passive recon
- Add **screenshot capture** of web services
- Build **HTML report** output
- Add **rate limiting** and stealth scan options

## Skills Demonstrated

- Python scripting for security automation
- Offensive security recon techniques
- Multi-module tool design
- REST API and socket programming
- Pentest workflow automation

## ⚠️ Legal Disclaimer

This tool is for **authorized testing and educational purposes only**. Only scan targets you have explicit permission to test. Unauthorized scanning may be illegal.

---

*Part of my SOC/Pentesting home lab series.*
*See also: [Mini SOC Home Lab](https://github.com/PathanZ/mini-home-soc) · [Threat Intel Feed Integrator](https://github.com/PathanZ/threat-intel-feed-integrator)*
