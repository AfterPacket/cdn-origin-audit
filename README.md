cdn-origin-audit 🔎🛡️
Passive-first subdomain + DNS + hosting attribution toolkit for authorized security testing and defensive audits.

Built and maintained by AfterPacket

Overview
This tool streamlines the process of uncovering infrastructure origins and bypasses. It helps you:

Discover historical subdomains via Certificate Transparency (crt.sh).

Pull DNS history via SecurityTrails (apex + www) and ViewDNS (IP history).

Run reverse IP lookups to understand shared hosting / neighbors (ViewDNS).

Fingerprint cloud providers (AWS / GCP / Azure) via PTR + RDAP/WHOIS.

Perform safe HTTP banner checks and path checks only when authorized.

[!IMPORTANT] ✅ Designed for defensive work and professional audits.

🔒 Passive OSINT is the default posture.

⚠️ Active checks require the --i-have-authorization flag.

Features
📡 Passive (OSINT) Recon
crt.sh CT log scraping for historical subdomains.

SecurityTrails subdomain discovery (via API).

DNS resolution: A / AAAA / CNAME / NS / MX / TXT.

Cloudflare detection:

NS (*.ns.cloudflare.com)

CNAME (cdn.cloudflare.net)

Cloudflare published IP ranges (v4/v6).

Origin candidate identification: Collects non-Cloudflare A/AAAA IPs exposed by subdomains.

Provider fingerprinting:

PTR + RDAP/WHOIS enrichment.

Heuristics for AWS / GCP / Azure / Cloudflare.

DNS History:

SecurityTrails: Summary + extraction of historical A/AAAA/CNAME values.

ViewDNS IP history: Shows historical IPs and last-seen dates.

Reverse IP lookups: Identify other domains sharing candidate IPs to scope shared infra.

⚡ Authorized Active Checks (Opt-in)
Safe HTTP banner checks: Uses HEAD requests with a tiny GET fallback.

Subfolder/path checks: Conservative defaults (e.g., robots.txt, sitemap.xml, /.well-known/security.txt).

Data Captured: Status codes, Server headers, and redirects (Location).

Project Layout
Plaintext

.
├── origin_audit.py     # Main engine
├── requires.txt        # Dependency list
├── requirements.txt    # Standard dependency list
└── README.md           # Documentation
Installation
You can install dependencies using either file provided in the repository:

Bash

# Option A: Standard install
pip install -r requirements.txt

# Option B: Alternative install
pip install -r requires.txt
API Keys (Optional)
To enable advanced passive enrichment, set your API keys as environment variables.

Service	Variable Name
SecurityTrails	SECURITYTRAILS_APIKEY
ViewDNS	VIEWDNS_APIKEY

Export to Sheets

Configuration
Linux / macOS

Bash

export SECURITYTRAILS_APIKEY="YOUR_KEY"
export VIEWDNS_APIKEY="YOUR_KEY"
Windows (PowerShell)

PowerShell

$env:SECURITYTRAILS_APIKEY="YOUR_KEY"
$env:VIEWDNS_APIKEY="YOUR_KEY"
Usage Examples
1. Passive OSINT Only (Recommended Baseline)
Bash

python origin_audit.py example.com \
  --crtsh \
  --securitytrails \
  --viewdns \
  --dns-history \
  --reverseip \
  --output passive_report.json
2. Authorized Active Testing
Use only on domains you own or have explicit permission to test.

Bash

python origin_audit.py example.com \
  --http \
  --paths \
  --i-have-authorization \
  --output active_report.json
3. Custom Subdomain & Path Audits
Bash

# Using a custom subdomain wordlist
python origin_audit.py example.com --wordlist subdomains.txt --crtsh

# Using a custom path list for active checks
python origin_audit.py example.com \
  --paths-file paths.txt \
  --i-have-authorization \
  --output paths_report.json
Output Data
Console Output
DNS summary per host and Cloudflare detection flags.

Origin candidate IP summary (non-Cloudflare exposures).

SecurityTrails & ViewDNS history summaries.

Authorized-only results (HTTP banners/Paths) if enabled.

JSON Report
Use --output report.json to export structured data including:

Discovered subdomains grouped by source.

Full DNS record sets.

Enriched IP metadata (RDAP/WHOIS).

Reverse IP and History results.

CLI Flag Reference
Flag	Description
--securitytrails	SecurityTrails subdomain discovery
--dns-history	SecurityTrails DNS history (apex + www)
--crtsh	CT-based historical subdomains
--viewdns	ViewDNS IP history
--reverseip	Reverse-IP lookups (ViewDNS)
--debug-api	Show API failures (401/429/etc.)
--i-have-authorization	Required to enable active checks
--http / --paths	Enable banner and path checking

Export to Sheets

Safety & Ethics
✅ Passive OSINT features are safe and low-risk.

🔒 Active web checks are rate-limited and minimal.

🚫 No exploit logic, credential attacks, or access control bypassing.

License: GPLv3 (Copyleft)

Disclaimer: This repository is provided for authorized security testing and defensive auditing. You are responsible for ensuring you have proper permission before running active checks.

Would you like me to generate a specific requirements.txt file or a Python setup script for this project?
