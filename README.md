# cdn-origin-audit 🔎🛡️

**Passive-first** subdomain + DNS + hosting attribution toolkit for **authorized security testing** and defensive audits.

Built and maintained by **AfterPacket** [](https://github.com/AfterPacket)
[](https://github.com/AfterPacket/cdn-origin-audit)

---

## Overview

`cdn-origin-audit` helps security professionals and site owners discover infrastructure origins that may be exposed despite being behind a CDN (like Cloudflare).

* **Discover historical subdomains** via Certificate Transparency (**crt.sh**).
* **Pull DNS history** via **SecurityTrails** (apex + `www`) and **ViewDNS** (IP history).
* **Identify shared hosting** neighbors via **reverse IP lookups** (ViewDNS).
* **Fingerprint cloud providers** (AWS / GCP / Azure) via PTR + RDAP/WHOIS.
* **Verify origin responsiveness** via safe HTTP banner and path checks.

> [!IMPORTANT]
> **Defensive Posture:** Passive OSINT is the default mode. Active network checks (HTTP/Path probes) are strictly opt-in and require the `--i-have-authorization` flag.

---

## 🛠️ Usage

### Full Command Syntax

```text
usage: origin_audit.py [-h] [--version] [--no-banner] [--debug-api] [--crtsh] [--securitytrails] [--viewdns]
                       [--dns-history] [--reverseip] [--no-bruteforce] [--wordlist WORDLIST] [--i-have-authorization]
                       [--http] [--paths] [--paths-file PATHS_FILE] [--max-hosts MAX_HOSTS]
                       [--dns-concurrency DNS_CONCURRENCY] [--http-concurrency HTTP_CONCURRENCY] [--output OUTPUT]
                       domain

```

### 🚀 Sample Scenarios

**1. Baseline Passive OSINT (Safest)**
Recommended for initial reconnaissance without touching the target's infrastructure.

```bash
python origin_audit.py example.com --crtsh --securitytrails --dns-history --output report.json

```

**2. Historical Origin Discovery**
Leverages API keys to find IP addresses previously associated with the domain.

```bash
python origin_audit.py example.com --viewdns --dns-history --reverseip --debug-api

```

**3. Authorized Origin Verification**
Verifies if discovered "Origin Candidate" IPs are serving web content.

```bash
python origin_audit.py example.com \
  --crtsh \
  --http \
  --paths \
  --i-have-authorization

```

---

## ⚙️ Configuration & API Keys

To enable full functionality, set the following environment variables:

| Service | Variable Name | Function |
| --- | --- | --- |
| **SecurityTrails** | `SECURITYTRAILS_APIKEY` | Subdomain discovery & DNS history |
| **ViewDNS** | `VIEWDNS_APIKEY` | IP history & Reverse IP lookups |

**Setup (Linux/macOS):**

```bash
export SECURITYTRAILS_APIKEY="YOUR_KEY"
export VIEWDNS_APIKEY="YOUR_KEY"

```

---

## 📋 Argument Reference

| Flag | Description |
| --- | --- |
| `--crtsh` | Scrapes crt.sh for subdomains found in SSL/TLS certificates. |
| `--securitytrails` | Queries SecurityTrails for subdomains. |
| `--viewdns` | Queries ViewDNS for historical IP records. |
| `--dns-history` | Extracts historical A/AAAA/CNAME values from SecurityTrails. |
| `--reverseip` | Identifies other domains hosted on candidate IPs. |
| `--i-have-authorization` | **Required** to enable `--http` and `--paths`. |
| `--http` | Performs safe HTTP banner grabbing (`HEAD` -> `GET`). |
| `--paths` | Checks for `/robots.txt`, `/.well-known/security.txt`, etc. |
| `--output` | Saves all structured data to a JSON file. |

---

## 📁 Project Structure

```text
.
├── origin_audit.py     # Main application logic
├── requirements.txt    # Standard pip dependencies
├── requires.txt        # Alternative dependency list
└── README.md           # Documentation

```

### Installation

```bash
pip install -r requirements.txt

```

---

## 🛡️ Safety & Ethics

* ✅ **Passive OSINT** features are designed to be safe and low-profile.
* 🔒 **Active checks** are rate-limited and perform minimal interaction.
* 🚫 **No exploit logic** or credential brute-forcing is included.

**License:** GPLv3 (Copyleft)

**Disclaimer:** This tool is for authorized security testing only. Users are responsible for compliance with local laws and obtaining explicit permission before running active checks against any infrastructure.

---

