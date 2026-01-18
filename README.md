# cdn-origin-audit 🔎🛡️

Passive-first subdomain + DNS + hosting attribution toolkit for authorized security testing and defensive audits.

Built and maintained by AfterPacket
- GitHub: https://github.com/AfterPacket
- Repo:   https://github.com/AfterPacket/cdn-origin-audit

---

OVERVIEW

cdn-origin-audit helps security professionals and site owners identify infrastructure exposure that may exist even when a domain is behind a CDN (like Cloudflare).

It can:
- Discover historical subdomains via Certificate Transparency (crt.sh)
- Pull DNS history via SecurityTrails (apex + www) and ViewDNS (IP history)
- Identify shared-hosting neighbors via reverse IP lookups (ViewDNS)
- Fingerprint likely cloud providers (AWS / GCP / Azure) via PTR + RDAP/WHOIS
- Verify origin responsiveness via safe HTTP banner and path checks (authorized-only)

IMPORTANT:
Passive OSINT is the default posture. Active web checks are strictly opt-in and require --i-have-authorization.

---

INSTALLATION

pip install -r requirements.txt

Alternative:
pip install -r requires.txt

---

API KEYS (OPTIONAL)

To enable full functionality, set the following environment variables:

SecurityTrails
- Variable: SECURITYTRAILS_APIKEY
- Used for: Subdomain discovery + DNS history

ViewDNS
- Variable: VIEWDNS_APIKEY
- Used for: IP history + Reverse IP lookups

Linux/macOS:
export SECURITYTRAILS_APIKEY="YOUR_KEY"
export VIEWDNS_APIKEY="YOUR_KEY"

Windows (PowerShell):
$env:SECURITYTRAILS_APIKEY="YOUR_KEY"
$env:VIEWDNS_APIKEY="YOUR_KEY"

---

USAGE

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

QUICK START EXAMPLES

1) Baseline Passive OSINT (Safest)
Recommended for initial reconnaissance without active probing.

python origin_audit.py example.com --crtsh --securitytrails --dns-history --output report.json

2) Historical Origin Discovery (API-heavy)
Leverages ViewDNS and SecurityTrails history endpoints.

python origin_audit.py example.com --viewdns --dns-history --reverseip --debug-api

3) Authorized Origin Verification (Active Checks)
Minimal interaction banner + path checks.

python origin_audit.py example.com --crtsh --http --paths --i-have-authorization

4) Custom Subdomain Wordlist

python origin_audit.py example.com --wordlist subdomains.txt --crtsh --securitytrails --dns-history --output wordlist_report.json

5) Custom Path List (Authorized Only)

Create paths.txt:
  /admin
  /login
  /status
  /health
  /.well-known/security.txt

Run:
python origin_audit.py example.com --paths-file paths.txt --i-have-authorization --http --output paths_report.json

---

EVERYTHING ON (MAXIMUM COVERAGE)

Windows (PowerShell):

python origin_audit.py yourdomain.com `
  --crtsh --securitytrails --dns-history --viewdns --reverseip `
  --i-have-authorization --http --paths `
  --max-hosts 20000 `
  --dns-concurrency 800 `
  --http-concurrency 25 `
  --debug-api `
  --output yourdomain_full_max.json

If your build supports extra enumeration flags (--permutations, --wildcard-detect, --probe-email, --srv), use:

python origin_audit.py yourdomain.com `
  --crtsh --securitytrails --dns-history --viewdns --reverseip `
  --permutations --wildcard-detect `
  --probe-email --srv `
  --i-have-authorization --http --paths `
  --max-hosts 25000 `
  --dns-concurrency 900 `
  --http-concurrency 30 `
  --debug-api `
  --output yourdomain_enum_max.json

Linux/macOS (bash):

python origin_audit.py yourdomain.com \
  --crtsh --securitytrails --dns-history --viewdns --reverseip \
  --i-have-authorization --http --paths \
  --max-hosts 20000 \
  --dns-concurrency 800 \
  --http-concurrency 25 \
  --debug-api \
  --output yourdomain_full_max.json

---

TUNING / PERFORMANCE NOTES

- If you hit resolver timeouts or flaky results, reduce:
  --dns-concurrency to 200-500
  --max-hosts to 5000-15000

- If HTTP checks are too noisy for your infra, reduce:
  --http-concurrency to 5-15

---

ARGUMENT REFERENCE

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

OUTPUT

Console output includes:
- DNS summary table
- Cloudflare detection flags
- Origin candidate IP summary (non-Cloudflare exposures) + enrichment (PTR/ASN/org/provider guess)
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

PROJECT STRUCTURE

.
├── origin_audit.py     # Main application
├── requirements.txt    # Standard pip dependencies
├── requires.txt        # Alternate dependency list
└── README.md           # Documentation

---

SAFETY & ETHICS

- Passive OSINT features are designed to be safe and low-profile
- Active checks are minimal and rate-limited
- No exploit logic, credential brute forcing, or access-control bypassing

Use only for systems you own or where you have explicit written permission.

---

LICENSE

GNU General Public License v3.0

---

DISCLAIMER

This tool is provided for authorized security testing, defensive auditing, and research.
You are responsible for ensuring you have proper permission and comply with applicable laws before running active checks against any infrastructure.
