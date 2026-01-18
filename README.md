# cdn-origin-audit 🔎🛡️

Passive-first **subdomain + DNS + hosting attribution** toolkit for **authorized security testing** and defensive audits.

This tool helps you:
- Discover **historical subdomains** via Certificate Transparency (crt.sh)
- Pull **DNS history** via SecurityTrails / ViewDNS (API-based)
- Run **reverse IP lookups** to understand shared hosting / neighbors
- Fingerprint likely **cloud provider** (AWS / GCP / Azure) via PTR + RDAP/WHOIS
- Perform **safe HTTP banner checks** and **path checks** (subfolder checks) **only when authorized**

> ✅ Designed for defensive work and professional audits.  
> 🔒 **Passive OSINT is default.** Active checks require an explicit authorization flag.

---

## Features

### Passive (OSINT) Recon
- **crt.sh CT log scraping** for historical subdomains
- **DNS resolution**: A / AAAA / CNAME / NS / MX / TXT
- **Cloudflare detection**
  - NS (`*.ns.cloudflare.com`)
  - CNAME (`cdn.cloudflare.net`)
  - Cloudflare published IP ranges (v4/v6)
- **Origin candidate identification**
  - Collects **non-Cloudflare A/AAAA** IPs exposed by subdomains
- **Provider / hosting fingerprinting**
  - PTR + RDAP/WHOIS enrichment
  - Heuristics for **AWS / GCP / Azure / Cloudflare**
- **DNS history** (API)
  - SecurityTrails DNS history for apex + `www`
  - ViewDNS IP history
- **Reverse IP lookups** (API)
  - Identify other domains sharing candidate IPs (useful for scoping shared infra)

### Authorized Active Checks (Opt-in)
- **Safe HTTP banner checks** (`HEAD` → tiny `GET` fallback)
- **Subfolder/path checks** (conservative defaults like `robots.txt`, `sitemap.xml`, `/.well-known/security.txt`)
- Captures:
  - status codes
  - `Server` header
  - redirects (`Location`)

> Active checks are **disabled unless** you pass `--i-have-authorization`.

---

## Project Layout

```text
.
├── origin_audit.py
├── requires.txt
├── requirements.txt
└── README.md

```

Install
Option A: install from requires.txt (this repo)
bash
Copy code
pip install -r requires.txt
Option B: install from requirements.txt (common tooling expects this)
bash
Copy code
pip install -r requirements.txt
Optional API keys (enable extra passive enrichment):

SecurityTrails: SECURITYTRAILS_APIKEY

ViewDNS: VIEWDNS_APIKEY

```bash
export SECURITYTRAILS_APIKEY="YOUR_KEY"
export VIEWDNS_APIKEY="YOUR_KEY"
```

Usage
Passive OSINT only (recommended baseline)
```bash

python origin_audit.py example.com \
  --crtsh \
  --securitytrails \
  --viewdns \
  --dns-history \
  --reverseip \
  --output passive_report.json
Authorized active testing (your domains / explicit permission only)
```
```bash

python origin_audit.py example.com \
  --http \
  --paths \
  --i-have-authorization \
  --output active_report.json
Custom subdomain wordlist
```
```bash
python origin_audit.py example.com \
  --wordlist subdomains.txt \
  --crtsh \
  --output report.json
Custom path list (authorized only)
Create paths.txt:
```
```txt

/admin
/login
/status
/health
/.well-known/security.txt
```
Run:

```bash
python origin_audit.py example.com \
  --paths-file paths.txt \
  --i-have-authorization \
  --output paths_report.json
```

Output
Console tables
DNS summary per host

Cloudflare detection flags

Non-Cloudflare candidate IPs enriched with:

PTR

ASN / Org

Country (when available)

Provider guess (AWS/GCP/Azure)

JSON report
Use --output report.json to export:

discovered subdomains (by source)

all DNS records

cloudflare_hosts list

origin_candidate_ips list

enriched IP metadata

dns history (if enabled)

reverse IP results (if enabled)

authorized banner/path results (if enabled)

##Safety / Ethics
✅ Passive OSINT features are safe and low risk.

🔒 Active web checks are rate-limited and minimal.

🚫 No exploit logic.

🚫 No credential attacks.

🚫 No bypassing access controls.

Use only for systems you own or where you have explicit written permission.

##License


GPLv3 (copyleft)

##Disclaimer
This repository is provided for authorized security testing, defensive auditing, and research.
You are responsible for ensuring you have proper permission before running active checks.
