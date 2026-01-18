# cdn-origin-audit 🔎🛡️

**Passive-first** subdomain + DNS + hosting attribution toolkit for **authorized security testing** and defensive audits.

Built and maintained by **AfterPacket**
- GitHub: https://github.com/AfterPacket
- Repo: https://github.com/AfterPacket/cdn-origin-audit

---

## Overview

`cdn-origin-audit` helps security professionals and site owners identify infrastructure exposure that may exist even when a domain is behind a CDN (like Cloudflare).

It can:
- Discover **historical subdomains** via Certificate Transparency (**crt.sh**)
- Pull **DNS history** via **SecurityTrails** (apex + `www`) and **ViewDNS** (IP history)
- Identify shared-hosting neighbors via **reverse IP lookups** (ViewDNS)
- Fingerprint likely **cloud providers** (AWS / GCP / Azure) via PTR + RDAP/WHOIS
- Verify origin responsiveness via **safe HTTP banner** and **path checks** (authorized-only)

IMPORTANT:
Passive OSINT is the default posture. Active web checks are strictly opt-in and require `--i-have-authorization`.

---

## Installation

pip install -r requirements.txt

Alternative:
pip install -r requires.txt

---

## API Keys (Optional)

To enable full functionality, set the following environment variables:

Service: SecurityTrails
Variable: SECURITYTRAILS_APIKEY
Used for: Subdomain discovery + DNS history

Service: ViewDNS
Variable: VIEWDNS_APIKEY
Used for: IP history + Reverse IP lookups

Linux/macOS:
export SECURITYTRAILS_APIKEY="YOUR_KEY"
export VIEWDNS_APIKEY="YOUR_KEY"

Windows (PowerShell):
$env:SECURITYTRAILS_APIKEY="YOUR_KEY"
$env:VIEWDNS_APIKEY="YOUR_KEY"

---

## Usage

Full command syntax:

usage: origin_audit.py [-h] [--version] [--no-banner] [--debug-api]
                       [--crtsh] [--securitytrails] [--viewdns]
                       [--dns-history] [--reverseip]
                       [--no-bruteforce] [--wordlist WORDLIST]
                       [--i-have-authorization] [--http] [--paths]
                       [--paths-file PATHS_FILE]
                       [--max-hosts MAX_HOSTS]
                       [--dns-concurrency DNS_CONCURRENCY]
                       [--http-concurrency HTTP_CONCURRENCY]
                       [--output OUTPUT]
                       domain

---

## Sample Scenarios

1) Baseline Passive OSINT (Safest)
Recommended for initial reconnaissance without active probing.

python origin_audit.py example.com --crtsh --securitytrails --dns-history --output report.json

2) Historical Origin Discovery (API-heavy)
Leverages ViewDNS and SecurityTrails history endpoints.

python origin_audit.py example.com --viewdns --dns-history --reverseip --debug-api

3) Authorized Origin Verification (Active Checks)
Minimal interaction banner + path checks.

python origin_audit.py example.com --crtsh --http --paths --i-have-authorization

---

## Argument Reference

--crtsh
  Scrapes crt.sh for subdomains found in SSL/TLS certificates

--securitytrails
  Queries SecurityTrails for subdomain discovery

--viewdns
  Queries ViewDNS for historical IP records

--dns-history
  Pulls SecurityTrails DNS history (apex + www) and prints summary + best-effort extracted values

--reverseip
  Uses ViewDNS reverse-IP lookups on candidate IPs

--debug-api
  Prints API HTTP errors/status (401/429/etc.) for troubleshooting

--wordlist
  Add custom subdomain candidates from a file

--no-bruteforce
  Disable built-in subdomain brute candidates

--i-have-authorization
  Required to enable --http / --paths / --paths-file

--http
  Safe HTTP banner grab (HEAD -> tiny GET fallback)

--paths
  Checks safe paths (robots/sitemap/security.txt, well-known)

--paths-file
  Custom path list (authorized-only)

--output
  Writes a full JSON report

---

## Output

Console output includes:
- DNS summary table (A/AAAA/CNAME/NS/MX/TXT/CAA/SOA when available)
- Cloudflare detection flags
- Origin candidate IPs (non-Cloudflare exposures) + enrichment (PTR/ASN/org/provider guess)
- SecurityTrails DNS history summary (when enabled)
- ViewDNS IP history (when enabled)
- Reverse IP results (when enabled)
- Authorized-only HTTP banner + path checks (when enabled)

JSON output (--output) includes structured data for:
- Discovered hosts by source
- Full DNS results
- Cloudflare host list
- Origin candidate IPs + enrichment
- SecurityTrails history payloads
- ViewDNS history payloads
- Reverse-IP payloads
- Authorized checks (HTTP + paths)

---

## Project Structure

.
├── origin_audit.py     # Main application
├── requirements.txt    # Standard pip dependencies
├── requires.txt        # Alternate dependency list
└── README.md           # Documentation

---

## Safety & Ethics

- Passive OSINT features are designed to be safe and low-profile
- Active checks are minimal and rate-limited
- No exploit logic, credential brute forcing, or access-control bypassing

---

## License

GPLv3

---

## Disclaimer

This tool is provided for authorized security testing, defensive auditing, and research.
You are responsible for ensuring you have proper permission and comply with applicable laws before running active checks against any infrastructure.
