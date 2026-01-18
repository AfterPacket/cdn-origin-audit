#!/usr/bin/env python3
"""
cdn-origin-audit
Author: AfterPacket (https://github.com/AfterPacket)

Passive-first, Cloudflare-aware origin exposure audit toolkit.
Active web checks are gated behind --i-have-authorization.

Repo: https://github.com/AfterPacket/cdn-origin-audit
"""

import argparse
import asyncio
import json
import os
import random
import re
import socket
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple
import ipaddress

import aiohttp
import dns.asyncresolver
from rich import print
from rich.table import Table
from rich.console import Console

try:
    from ipwhois import IPWhois  # type: ignore
except Exception:
    IPWhois = None

CONSOLE = Console()

TOOL_NAME = "cdn-origin-audit"
VERSION = "0.1.0"
AUTHOR = "AfterPacket"
AUTHOR_URL = "https://github.com/AfterPacket"
REPO_URL = "https://github.com/AfterPacket/cdn-origin-audit"

DEFAULT_SUBDOMAINS = [
    "www","mail","ftp","cpanel","webmail","direct","origin","dev","test","staging",
    "api","beta","old","legacy","admin","vpn","ns1","ns2","smtp","imap","pop",
    "git","gitlab","jira","grafana","status","dashboard","cdn","static","images",
    "m","mobile","app","portal","support","help","docs","blog","shop",
    "sso","auth","login","files","downloads","uploads","assets",
    # extra common infra labels
    "server","panel","webmin","grafana","prometheus","kibana","jenkins","ci","cd"
]

DEFAULT_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association"
]

# -----------------------------
# Data structures
# -----------------------------
@dataclass
class HostDNS:
    host: str
    a: List[str]
    aaaa: List[str]
    cname: List[str]
    ns: List[str]
    mx: List[str]
    txt: List[str]

@dataclass
class HTTPBanner:
    url: str
    status: Optional[int]
    server: Optional[str]
    content_type: Optional[str]
    location: Optional[str]

@dataclass
class PathCheck:
    url: str
    status: Optional[int]
    server: Optional[str]
    location: Optional[str]

@dataclass
class IPEnrichment:
    ip: str
    ptr: Optional[str]
    provider_guess: Optional[str]
    asn: Optional[str]
    org: Optional[str]
    country: Optional[str]
    raw: Optional[Dict[str, Any]]


# -----------------------------
# Banner helpers (dynamic)
# -----------------------------
def _get_flag(args, name: str, default=False):
    return getattr(args, name, default)

def _mode_label(args) -> str:
    passive_flags = any([
        _get_flag(args, "crtsh"),
        _get_flag(args, "securitytrails"),
        _get_flag(args, "viewdns"),
        _get_flag(args, "dns_history"),
        _get_flag(args, "reverseip"),
        (not _get_flag(args, "no_bruteforce")) or bool(_get_flag(args, "wordlist", None)),
    ])

    active_requested = any([
        _get_flag(args, "http"),
        _get_flag(args, "paths"),
        bool(_get_flag(args, "paths_file", None)),
    ])

    authorized = _get_flag(args, "i_have_authorization")

    if active_requested and authorized:
        return "ACTIVE (AUTHORIZED)"
    if active_requested and not authorized:
        return "ACTIVE REQUESTED (BLOCKED - missing --i-have-authorization)"
    if passive_flags:
        return "PASSIVE+ (OSINT enabled)"
    return "PASSIVE"

def _enabled_sources(args) -> str:
    parts = []
    if not _get_flag(args, "no_bruteforce"):
        parts.append("wordlist/bruteforce")
    if _get_flag(args, "wordlist", None):
        parts.append("custom-wordlist")
    if _get_flag(args, "crtsh"):
        parts.append("crt.sh")
    if _get_flag(args, "securitytrails"):
        parts.append("SecurityTrails")
    if _get_flag(args, "viewdns"):
        parts.append("ViewDNS")
    if _get_flag(args, "dns_history"):
        parts.append("DNS history")
    if _get_flag(args, "reverseip"):
        parts.append("Reverse IP")
    if _get_flag(args, "http"):
        parts.append("HTTP banners")
    if _get_flag(args, "paths") or _get_flag(args, "paths_file", None):
        parts.append("Path checks")
    return ", ".join(parts) if parts else "-"

def build_banner(args, target_domain: str = "") -> str:
    mode = _mode_label(args)
    sources = _enabled_sources(args)

    if mode.startswith("ACTIVE (AUTHORIZED)"):
        color = "green"
    elif mode.startswith("ACTIVE REQUESTED"):
        color = "red"
    elif mode.startswith("PASSIVE+"):
        color = "cyan"
    else:
        color = "blue"

    target_line = f"[dim]Target:[/dim] {target_domain}\n" if target_domain else ""

    return (
        f"\n[bold {color}]{TOOL_NAME}[/bold {color}]  [white]{VERSION}[/white]\n"
        f"[dim]Author:[/dim] [bold]{AUTHOR}[/bold]  [blue]{AUTHOR_URL}[/blue]\n"
        f"[dim]Repo:[/dim]   [blue]{REPO_URL}[/blue]\n"
        f"{target_line}"
        f"[dim]Mode:[/dim]   [bold]{mode}[/bold]\n"
        f"[dim]Enabled:[/dim] {sources}\n"
    )


# -----------------------------
# Helpers
# -----------------------------
def normalize_host(h: str) -> str:
    return h.strip().lower().rstrip(".")

async def run_blocking(fn, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: fn(*args))

async def safe_gethostbyaddr(ip: str) -> Optional[str]:
    try:
        res = await run_blocking(socket.gethostbyaddr, ip)
        return res[0]
    except Exception:
        return None

def guess_cloud_provider(ptr: Optional[str], org: Optional[str], asn: Optional[str]) -> Optional[str]:
    s = " ".join([ptr or "", org or "", asn or ""]).lower()

    if ("amazon" in s) or ("amazonaws.com" in s) or ("compute.amazonaws.com" in s) or (asn in {"AS16509","AS14618"}):
        return "AWS"
    if ("google" in s) or ("googleusercontent.com" in s) or (asn == "AS15169"):
        return "GCP"
    if ("microsoft" in s) or ("azure" in s) or ("cloudapp.azure.com" in s) or (asn == "AS8075"):
        return "Azure"
    if ("cloudflare" in s) or ("cdn.cloudflare.net" in s):
        return "Cloudflare"
    return None

async def fetch_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers=None,
    params=None,
    timeout=25,
    debug: bool = False
) -> Optional[Any]:
    try:
        async with session.get(
            url,
            headers=headers,
            params=params,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as r:
            text = await r.text()

            if r.status >= 400:
                if debug:
                    print(f"[yellow]API error[/yellow] {r.status} {url}")
                    snippet = text[:300].replace("\n", " ")
                    if snippet:
                        print(f"[dim]{snippet}[/dim]")
                return None

            try:
                return json.loads(text)
            except Exception:
                if debug:
                    print(f"[yellow]JSON parse failed[/yellow] {url}")
                return None
    except Exception as e:
        if debug:
            print(f"[yellow]Request failed[/yellow] {url} err={e}")
        return None

async def fetch_text(session: aiohttp.ClientSession, url: str, *, timeout=20) -> Optional[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status >= 400:
                return None
            return await r.text()
    except Exception:
        return None


# -----------------------------
# Cloudflare IP ranges (best-effort)
# -----------------------------
async def fetch_cloudflare_networks(session: aiohttp.ClientSession) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for url in ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]:
        body = await fetch_text(session, url, timeout=15)
        if not body:
            continue
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except Exception:
                pass
    return nets

def is_cloudflare_ip(ip: str, cf_nets: List[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in cf_nets)
    except Exception:
        return False

def is_cloudflare_host(dns: HostDNS, cf_nets: List[ipaddress._BaseNetwork]) -> bool:
    if any(normalize_host(ns).endswith("ns.cloudflare.com") for ns in dns.ns):
        return True
    if any("cdn.cloudflare.net" in normalize_host(c) for c in dns.cname):
        return True
    return any(is_cloudflare_ip(ip, cf_nets) for ip in dns.a + dns.aaaa)


# -----------------------------
# DNS resolving
# -----------------------------
async def resolve_record(resolver: dns.asyncresolver.Resolver, host: str, rtype: str) -> List[str]:
    try:
        ans = await resolver.resolve(host, rtype)
        return [str(r).strip().rstrip(".") for r in ans]
    except Exception:
        return []

async def resolve_host(resolver: dns.asyncresolver.Resolver, host: str) -> HostDNS:
    host = normalize_host(host)
    a = await resolve_record(resolver, host, "A")
    aaaa = await resolve_record(resolver, host, "AAAA")
    cname = await resolve_record(resolver, host, "CNAME")
    ns = await resolve_record(resolver, host, "NS")
    mx_raw = await resolve_record(resolver, host, "MX")
    txt = await resolve_record(resolver, host, "TXT")
    mx = [re.split(r"\s+", x, maxsplit=1)[-1].rstrip(".") if " " in x else x.rstrip(".") for x in mx_raw]
    return HostDNS(host=host, a=a, aaaa=aaaa, cname=cname, ns=ns, mx=mx, txt=txt)


# -----------------------------
# crt.sh (passive)
# -----------------------------
async def crtsh_subdomains(session: aiohttp.ClientSession, domain: str, *, debug: bool = False) -> Set[str]:
    domain = normalize_host(domain)
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    data = await fetch_json(session, url, params=params, timeout=35, debug=debug)
    out: Set[str] = set()
    if not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict):
            continue
        nv = row.get("name_value")
        if not isinstance(nv, str):
            continue
        for line in nv.splitlines():
            h = normalize_host(line.replace("*.", ""))
            if h and (h == domain or h.endswith("." + domain)):
                out.add(h)
    return out


# -----------------------------
# SecurityTrails (passive)
# -----------------------------
SECURITYTRAILS_BASE = "https://api.securitytrails.com/v1"

async def st_get(
    session: aiohttp.ClientSession,
    apikey: str,
    path: str,
    *,
    params: Optional[Dict[str, str]] = None,
    debug: bool = False
) -> Optional[Any]:
    headers = {"APIKEY": apikey}
    return await fetch_json(
        session,
        SECURITYTRAILS_BASE + path,
        headers=headers,
        params=params,
        timeout=25,
        debug=debug,
    )

async def st_subdomains(session: aiohttp.ClientSession, apikey: str, domain: str, *, debug: bool = False) -> Set[str]:
    domain = normalize_host(domain)
    data = await st_get(session, apikey, f"/domain/{domain}/subdomains", debug=debug)
    out: Set[str] = set()
    if isinstance(data, dict) and isinstance(data.get("subdomains"), list):
        for s in data["subdomains"]:
            if isinstance(s, str) and s.strip():
                out.add(normalize_host(f"{s}.{domain}"))
    return out

async def st_dns_history(session: aiohttp.ClientSession, apikey: str, hostname: str, rtype: str, *, debug: bool = False) -> Optional[Any]:
    hostname = normalize_host(hostname)
    return await st_get(session, apikey, f"/history/{hostname}/dns/{rtype.lower()}", debug=debug)

async def st_ip_whois(session: aiohttp.ClientSession, apikey: str, ip: str, *, debug: bool = False) -> Optional[Dict[str, Any]]:
    data = await st_get(session, apikey, f"/ips/{ip}/whois", debug=debug)
    return data if isinstance(data, dict) else None


# -----------------------------
# ViewDNS (passive)
# -----------------------------
VIEWDNS_BASE = "https://api.viewdns.info"

async def viewdns_get(
    session: aiohttp.ClientSession,
    apikey: str,
    path: str,
    params: Dict[str, str],
    *,
    debug: bool = False
) -> Optional[Any]:
    q = dict(params)
    q["apikey"] = apikey
    q.setdefault("output", "json")
    return await fetch_json(session, VIEWDNS_BASE + path, params=q, timeout=25, debug=debug)

async def viewdns_ip_history(session: aiohttp.ClientSession, apikey: str, domain: str, *, debug: bool = False) -> List[Dict[str, Any]]:
    data = await viewdns_get(session, apikey, "/iphistory/", {"domain": normalize_host(domain)}, debug=debug)
    if not isinstance(data, dict):
        return []
    resp = data.get("response", {})
    if isinstance(resp, dict) and isinstance(resp.get("records"), list):
        return [x for x in resp["records"] if isinstance(x, dict)]
    return []

async def viewdns_reverse_ip(session: aiohttp.ClientSession, apikey: str, host_or_ip: str, max_pages: int = 3, *, debug: bool = False) -> List[Dict[str, Any]]:
    host_or_ip = host_or_ip.strip()
    out: List[Dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        data = await viewdns_get(session, apikey, "/reverseip/", {"host": host_or_ip, "page": str(page)}, debug=debug)
        if not isinstance(data, dict):
            break
        resp = data.get("response", {})
        if not isinstance(resp, dict):
            break
        chunk = resp.get("domains", [])
        if isinstance(chunk, list) and chunk:
            out.extend([d for d in chunk if isinstance(d, dict)])
        else:
            break
    return out


# -----------------------------
# IP enrichment (RDAP/WHOIS)
# -----------------------------
def rdap_lookup(ip: str) -> Optional[Dict[str, Any]]:
    if IPWhois is None:
        return None
    try:
        return IPWhois(ip).lookup_rdap(depth=1)
    except Exception:
        try:
            return IPWhois(ip).lookup_whois()
        except Exception:
            return None

def pick_fields(raw: Optional[Dict[str, Any]]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not raw:
        return (None, None, None)
    asn = raw.get("asn") or raw.get("asn_registry") or raw.get("asn_cidr")
    org = raw.get("asn_description") or (raw.get("network", {}) or {}).get("name")
    country = raw.get("asn_country_code") or (raw.get("network", {}) or {}).get("country")
    return (str(asn) if asn else None, str(org) if org else None, str(country) if country else None)

async def enrich_ip(session: aiohttp.ClientSession, ip: str, st_key: Optional[str], *, debug: bool = False) -> IPEnrichment:
    ptr = await safe_gethostbyaddr(ip)
    raw = await st_ip_whois(session, st_key, ip, debug=debug) if st_key else None
    if raw is None:
        raw = await run_blocking(rdap_lookup, ip)
    asn, org, country = pick_fields(raw)
    provider = guess_cloud_provider(ptr, org, asn)
    return IPEnrichment(ip=ip, ptr=ptr, provider_guess=provider, asn=asn, org=org, country=country, raw=raw if raw else None)


# -----------------------------
# SecurityTrails history formatting helpers
# -----------------------------
def st_summarize(obj: Any) -> str:
    if not isinstance(obj, dict):
        return "n/a"
    for k in ("records", "items", "history", "result", "current"):
        v = obj.get(k)
        if isinstance(v, list):
            return f"{k}={len(v)}"
        if isinstance(v, dict):
            return f"{k}=dict"
    return "keys=" + ",".join(list(obj.keys())[:8]) if obj else "empty"

def st_extract_values(obj: Any, limit: int = 10) -> List[str]:
    """
    Best-effort extraction of values from SecurityTrails history responses.
    Handles common shapes:
      - {"records": [{"values": [{"ip": "1.2.3.4"}]}]}
      - {"records": [{"values": [{"value": "target"}]}]}
      - {"records": [{"values": ["1.2.3.4", ...]}]}
    """
    if not isinstance(obj, dict):
        return []
    recs = obj.get("records")
    if not isinstance(recs, list):
        return []

    out: List[str] = []
    seen: Set[str] = set()

    def add(v: str):
        v = str(v).strip()
        if not v or v in seen:
            return
        seen.add(v)
        out.append(v)

    for rec in recs:
        if not isinstance(rec, dict):
            continue
        vals = rec.get("values")
        if isinstance(vals, list):
            for item in vals:
                if isinstance(item, dict):
                    if "ip" in item:
                        add(item["ip"])
                    elif "value" in item:
                        add(item["value"])
                    elif "hostname" in item:
                        add(item["hostname"])
                else:
                    add(item)
        # sometimes record may directly contain "ip" or "value"
        if "ip" in rec:
            add(rec["ip"])
        if "value" in rec:
            add(rec["value"])

        if len(out) >= limit:
            break

    return out[:limit]


# -----------------------------
# AUTHORIZED-ONLY active checks
# -----------------------------
async def safe_banner_check(session: aiohttp.ClientSession, host: str, *, timeout=8) -> List[HTTPBanner]:
    host = normalize_host(host)
    headers = {
        "User-Agent": f"{TOOL_NAME}/{VERSION} (+{REPO_URL})",
        "Accept": "*/*",
        "Connection": "close",
    }

    async def one(url: str) -> HTTPBanner:
        try:
            async with session.head(
                url,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                return HTTPBanner(
                    url=url,
                    status=r.status,
                    server=r.headers.get("Server"),
                    content_type=r.headers.get("Content-Type"),
                    location=r.headers.get("Location"),
                )
        except Exception:
            # tiny GET fallback with Range
            try:
                h2 = dict(headers)
                h2["Range"] = "bytes=0-1024"
                async with session.get(
                    url,
                    headers=h2,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as r:
                    try:
                        await r.content.read(256)
                    except Exception:
                        pass
                    return HTTPBanner(
                        url=url,
                        status=r.status,
                        server=r.headers.get("Server"),
                        content_type=r.headers.get("Content-Type"),
                        location=r.headers.get("Location"),
                    )
            except Exception:
                return HTTPBanner(url=url, status=None, server=None, content_type=None, location=None)

    return [await one(f"https://{host}/"), await one(f"http://{host}/")]

async def safe_path_checks(
    session: aiohttp.ClientSession,
    host: str,
    paths: List[str],
    *,
    timeout=8,
    min_delay=0.2,
    max_delay=0.8
) -> List[PathCheck]:
    host = normalize_host(host)
    headers = {
        "User-Agent": f"{TOOL_NAME}/{VERSION} (+{REPO_URL})",
        "Accept": "*/*",
        "Connection": "close",
    }

    async def check(url: str) -> PathCheck:
        await asyncio.sleep(random.uniform(min_delay, max_delay))
        try:
            async with session.head(
                url,
                headers=headers,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as r:
                return PathCheck(
                    url=url,
                    status=r.status,
                    server=r.headers.get("Server"),
                    location=r.headers.get("Location"),
                )
        except Exception:
            return PathCheck(url=url, status=None, server=None, location=None)

    results: List[PathCheck] = []
    for scheme in ["https", "http"]:
        for pth in paths:
            if not pth.startswith("/"):
                pth = "/" + pth
            results.append(await check(f"{scheme}://{host}{pth}"))
    return results


# -----------------------------
# Main
# -----------------------------
async def main():
    ap = argparse.ArgumentParser(
        description=f"{TOOL_NAME}: Passive OSINT origin exposure audit (Cloudflare-aware). Active checks require explicit authorization flag."
    )
    ap.add_argument("domain", help="Target domain (use only with permission for active checks).")

    # UI / metadata
    ap.add_argument("--version", action="store_true", help="Print version and exit.")
    ap.add_argument("--no-banner", action="store_true", help="Disable banner output.")
    ap.add_argument("--debug-api", action="store_true", help="Print API HTTP errors/status for crt.sh / SecurityTrails / ViewDNS.")

    # Passive sources
    ap.add_argument("--crtsh", action="store_true", help="Passive: crt.sh CT subdomain discovery.")
    ap.add_argument("--securitytrails", action="store_true", help="Passive: SecurityTrails subdomains + IP whois (key required).")
    ap.add_argument("--viewdns", action="store_true", help="Passive: ViewDNS IP history + reverse IP (key required).")
    ap.add_argument("--dns-history", action="store_true", help="Passive: SecurityTrails DNS history for apex + www (key required).")
    ap.add_argument("--reverseip", action="store_true", help="Passive: Reverse IP for candidate IPs via ViewDNS (key required).")

    # Host discovery controls
    ap.add_argument("--no-bruteforce", action="store_true", help="Disable wordlist-based subdomain candidates.")
    ap.add_argument("--wordlist", help="Optional subdomain wordlist file.")

    # Active checks (authorized only)
    ap.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="REQUIRED to run any active web checks (banner/path). Use only for systems you own or have explicit permission to test."
    )
    ap.add_argument("--http", action="store_true", help="Active: minimal HTTP banner checks (Server header).")
    ap.add_argument("--paths", action="store_true", help="Active: check a small set of safe paths (robots/sitemap/security.txt).")
    ap.add_argument("--paths-file", help="Active: path list file (one path per line). Use only with authorization.")
    ap.add_argument("--max-hosts", type=int, default=2000, help="Safety cap: max hosts to resolve.")
    ap.add_argument("--dns-concurrency", type=int, default=150)
    ap.add_argument("--http-concurrency", type=int, default=10)
    ap.add_argument("--output", help="Write full JSON report to file.")
    args = ap.parse_args()

    if args.version:
        print(f"{TOOL_NAME} {VERSION} - {AUTHOR} ({AUTHOR_URL})")
        return

    if not args.no_banner:
        CONSOLE.print(build_banner(args, target_domain=args.domain))

    domain = normalize_host(args.domain)
    debug_api = bool(args.debug_api)

    # keys
    st_key = os.getenv("SECURITYTRAILS_APIKEY") if (args.securitytrails or args.dns_history) else None
    vd_key = os.getenv("VIEWDNS_APIKEY") if (args.viewdns or args.reverseip) else None

    resolver = dns.asyncresolver.Resolver()

    async with aiohttp.ClientSession() as session:
        cf_nets = await fetch_cloudflare_networks(session)

        # Build host set
        hosts: Set[str] = {domain, f"www.{domain}"}

        # Optional bruteforce
        brutelist = list(DEFAULT_SUBDOMAINS)
        if args.wordlist:
            try:
                with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        if w and not w.startswith("#") and "." not in w:
                            brutelist.append(w.lower())
            except Exception as e:
                print(f"[yellow]Could not read wordlist: {e}[/yellow]")

        if not args.no_bruteforce:
            for s in brutelist:
                hosts.add(f"{s}.{domain}")

        # Passive enrichment: crt.sh
        crt_hosts: Set[str] = set()
        if args.crtsh:
            crt_hosts = await crtsh_subdomains(session, domain, debug=debug_api)
            hosts |= crt_hosts
            print(f"\n[bold]crt.sh subdomains:[/bold] {len(crt_hosts)} found")

        # Passive enrichment: SecurityTrails subdomains
        st_hosts: Set[str] = set()
        if args.securitytrails:
            if not st_key:
                print("[yellow]SECURITYTRAILS_APIKEY not set; skipping SecurityTrails.[/yellow]")
            else:
                st_hosts = await st_subdomains(session, st_key, domain, debug=debug_api)
                hosts |= st_hosts
                print(f"[bold]SecurityTrails subdomains:[/bold] {len(st_hosts)} found")

        # Passive: ViewDNS IP history (apex)
        vd_ip_history: List[Dict[str, Any]] = []
        if args.viewdns:
            if not vd_key:
                print("[yellow]VIEWDNS_APIKEY not set; skipping ViewDNS.[/yellow]")
            else:
                vd_ip_history = await viewdns_ip_history(session, vd_key, domain, debug=debug_api)

        # Cap
        if len(hosts) > args.max_hosts:
            hosts = set(list(hosts)[: args.max_hosts])

        # Resolve DNS
        dns_results: Dict[str, HostDNS] = {}
        sem = asyncio.Semaphore(args.dns_concurrency)

        async def resolve_one(h: str):
            async with sem:
                dns_results[h] = await resolve_host(resolver, h)

        await asyncio.gather(*(resolve_one(h) for h in sorted(hosts)))

        # CF & origin candidate IPs
        cf_hosts: Set[str] = set()
        origin_candidate_ips: Set[str] = set()

        for h, d in dns_results.items():
            if is_cloudflare_host(d, cf_nets):
                cf_hosts.add(h)
            for ip in d.a + d.aaaa:
                if ip and not is_cloudflare_ip(ip, cf_nets):
                    origin_candidate_ips.add(ip)

        # Passive: SecurityTrails DNS history (apex + www)
        st_dns_hist: Dict[str, Any] = {}
        if args.dns_history:
            if not st_key:
                print("[yellow]SECURITYTRAILS_APIKEY not set; skipping DNS history.[/yellow]")
            else:
                for hn in [domain, f"www.{domain}"]:
                    st_dns_hist[hn] = {
                        "a": await st_dns_history(session, st_key, hn, "a", debug=debug_api),
                        "aaaa": await st_dns_history(session, st_key, hn, "aaaa", debug=debug_api),
                        "cname": await st_dns_history(session, st_key, hn, "cname", debug=debug_api),
                    }

        # Enrich IPs
        enriched_ips: Dict[str, IPEnrichment] = {}
        if origin_candidate_ips:
            ip_sem = asyncio.Semaphore(25)

            async def enrich_one(ip: str):
                async with ip_sem:
                    enriched_ips[ip] = await enrich_ip(session, ip, st_key, debug=debug_api)

            await asyncio.gather(*(enrich_one(ip) for ip in sorted(origin_candidate_ips)))

        # Passive: Reverse IP via ViewDNS
        reverseip_results: Dict[str, List[Dict[str, Any]]] = {}
        if args.reverseip:
            if not vd_key:
                print("[yellow]VIEWDNS_APIKEY not set; skipping reverse IP.[/yellow]")
            else:
                rip_sem = asyncio.Semaphore(8)

                async def rip_one(ip: str):
                    async with rip_sem:
                        reverseip_results[ip] = await viewdns_reverse_ip(session, vd_key, ip, debug=debug_api)

                await asyncio.gather(*(rip_one(ip) for ip in sorted(origin_candidate_ips)))

        # Active checks (authorized-only)
        http_results: Dict[str, Any] = {}
        path_results: Dict[str, Any] = {}

        if (args.http or args.paths or args.paths_file) and not args.i_have_authorization:
            print("[red]Active checks requested but --i-have-authorization was NOT provided. Skipping all active checks.[/red]")

        if args.i_have_authorization:
            interesting = {domain, f"www.{domain}"}
            for h, d in dns_results.items():
                if any(ip and not is_cloudflare_ip(ip, cf_nets) for ip in d.a + d.aaaa):
                    interesting.add(h)

            http_sem = asyncio.Semaphore(args.http_concurrency)

            if args.http:
                async def http_one(h: str):
                    async with http_sem:
                        http_results[h] = [asdict(b) for b in await safe_banner_check(session, h)]
                await asyncio.gather(*(http_one(h) for h in sorted(interesting)))

            paths = list(DEFAULT_PATHS)
            if args.paths_file:
                try:
                    with open(args.paths_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            pth = line.strip()
                            if pth and not pth.startswith("#"):
                                paths.append(pth)
                except Exception as e:
                    print(f"[yellow]Could not read paths file: {e}[/yellow]")

            if args.paths or args.paths_file:
                async def path_one(h: str):
                    async with http_sem:
                        res = await safe_path_checks(session, h, paths)
                        path_results[h] = [asdict(x) for x in res]
                await asyncio.gather(*(path_one(h) for h in sorted(interesting)))

        # -----------------------------
        # Console report
        # -----------------------------
        t = Table(title=f"DNS Summary — {domain}")
        t.add_column("Host", style="cyan", no_wrap=True)
        t.add_column("A/AAAA")
        t.add_column("CNAME")
        t.add_column("NS")
        t.add_column("Cloudflare?")

        for h in sorted(dns_results.keys()):
            d = dns_results[h]
            ips = ", ".join(d.a + d.aaaa) if (d.a or d.aaaa) else "-"
            cn = ", ".join(d.cname) if d.cname else "-"
            ns = ", ".join(d.ns) if d.ns else "-"
            cf = "YES" if h in cf_hosts else "NO"
            t.add_row(h, ips, cn, ns, cf)

        CONSOLE.print(t)

        if enriched_ips:
            it = Table(title="Non-Cloudflare IPs Exposed via DNS (candidates)")
            it.add_column("IP", style="yellow")
            it.add_column("PTR")
            it.add_column("Provider Guess", style="cyan")
            it.add_column("ASN")
            it.add_column("Org")
            it.add_column("Country")

            for ip in sorted(enriched_ips.keys()):
                e = enriched_ips[ip]
                it.add_row(
                    e.ip,
                    e.ptr or "-",
                    e.provider_guess or "-",
                    e.asn or "-",
                    (e.org or "-")[:60],
                    e.country or "-"
                )
            CONSOLE.print(it)
        else:
            print("\n[green]No non-Cloudflare IPs exposed via DNS on discovered hosts.[/green]")

        if st_dns_hist:
            print("\n[bold]SecurityTrails DNS History (apex + www):[/bold]")
            for hn, hist in st_dns_hist.items():
                a_obj = hist.get("a")
                aaaa_obj = hist.get("aaaa")
                cname_obj = hist.get("cname")
                print(f"  • {hn}: A({st_summarize(a_obj)}) AAAA({st_summarize(aaaa_obj)}) CNAME({st_summarize(cname_obj)})")

                # show a few extracted values (best-effort)
                a_vals = st_extract_values(a_obj, limit=8)
                aaaa_vals = st_extract_values(aaaa_obj, limit=8)
                cname_vals = st_extract_values(cname_obj, limit=8)

                if a_vals:
                    print(f"      A values: {', '.join(a_vals)}")
                if aaaa_vals:
                    print(f"      AAAA values: {', '.join(aaaa_vals)}")
                if cname_vals:
                    print(f"      CNAME values: {', '.join(cname_vals)}")

        if vd_ip_history:
            print("\n[bold]ViewDNS IP History (apex):[/bold]")
            shown, seen = 0, set()
            for rec in vd_ip_history:
                ip = rec.get("ip")
                if not isinstance(ip, str) or ip in seen:
                    continue
                seen.add(ip)
                print(f"  • {ip} owner={rec.get('owner','?')} lastseen={rec.get('lastseen','')}")
                shown += 1
                if shown >= 10:
                    break

        if reverseip_results:
            print("\n[bold]Reverse IP (ViewDNS) for candidate IPs:[/bold]")
            for ip, doms in reverseip_results.items():
                print(f"  • {ip}: {len(doms)} domains (showing up to 10)")
                for d in doms[:10]:
                    name = d.get("name")
                    if isinstance(name, str):
                        print(f"      - {name}")

        if http_results:
            print("\n[bold]HTTP Server Header (authorized-only):[/bold]")
            for h, banners in http_results.items():
                parts = []
                for b in banners:
                    parts.append(f"{b.get('url')} -> {b.get('status')} server={b.get('server') or '-'}")
                print(f"  • {h}: " + " | ".join(parts))

        if path_results:
            print("\n[bold]Path Checks (authorized-only):[/bold]")
            for h, checks in path_results.items():
                hits = [c for c in checks if c.get("status") not in (None, 404)]
                print(f"  • {h}: {len(hits)} hits (non-404)")
                for c in hits[:12]:
                    print(f"      - {c.get('url')} -> {c.get('status')} server={c.get('server') or '-'}")

        report = {
            "tool": {"name": TOOL_NAME, "version": VERSION, "author": AUTHOR, "author_url": AUTHOR_URL, "repo_url": REPO_URL},
            "domain": domain,
            "sources": {
                "crtsh_hosts": sorted(crt_hosts),
                "securitytrails_hosts": sorted(st_hosts),
                "viewdns_enabled": bool(args.viewdns),
                "securitytrails_enabled": bool(args.securitytrails),
                "dns_history_enabled": bool(args.dns_history),
                "reverseip_enabled": bool(args.reverseip),
                "bruteforce_enabled": not args.no_bruteforce,
            },
            "dns": {h: asdict(d) for h, d in dns_results.items()},
            "cloudflare_hosts": sorted(cf_hosts),
            "origin_candidate_ips": sorted(origin_candidate_ips),
            "ip_enrichment": {ip: asdict(e) for ip, e in enriched_ips.items()},
            "securitytrails_dns_history": st_dns_hist,
            "viewdns_ip_history": vd_ip_history,
            "reverse_ip": reverseip_results,
            "http_banners_authorized": http_results,
            "path_checks_authorized": path_results,
        }

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"\n[green]Wrote JSON report:[/green] {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
