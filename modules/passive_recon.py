"""
Trace Foundry V7 - Passive Recon Module
Wayback Machine, Certificate Transparency (crt.sh),
DNS history, Google dorking hints, Shodan-style checks
Zero active requests to target — fully passive
"""
import urllib.request
import urllib.error
import urllib.parse
import json
import re
from utils.display import section, ok, warn, info, bug_found, print_section

class PassiveReconModule:
    def __init__(self, domain, timeout=8):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (TraceFoundry/7.0) Security Research"
        }

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(131072).decode("utf-8", errors="ignore"), r.status
        except:
            return "", 0

    # ── 1. Certificate Transparency (crt.sh) ────────────────────────────────
    def _crtsh(self):
        """Find subdomains via SSL certificate logs"""
        info("Querying crt.sh certificate transparency logs...")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        body, status = self._fetch(url)
        if not body:
            warn("crt.sh unreachable")
            return []

        subdomains = set()
        try:
            data = json.loads(body)
            for entry in data:
                name = entry.get("name_value","")
                for sub in name.splitlines():
                    sub = sub.strip().lower()
                    if sub.endswith(f".{self.domain}") and "*" not in sub:
                        subdomains.add(sub)
        except:
            pass

        found = sorted(subdomains)
        ok(f"crt.sh found {len(found)} subdomains from SSL certificates")
        for s in found[:20]:
            info(f"  cert subdomain → {s}")
        if len(found) > 20:
            info(f"  ... and {len(found)-20} more")
        return found

    # ── 2. Wayback Machine ──────────────────────────────────────────────────
    def _wayback(self):
        """Find historical URLs and endpoints from Wayback Machine"""
        info("Querying Wayback Machine CDX API...")
        url = (f"http://web.archive.org/cdx/search/cdx"
               f"?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
               f"&limit=500&filter=statuscode:200")
        body, status = self._fetch(url)
        if not body:
            warn("Wayback Machine unreachable")
            return []

        interesting = []
        sensitive_patterns = [
            r'\.env', r'\.git', r'backup', r'config', r'admin',
            r'api/', r'swagger', r'upload', r'debug', r'test',
            r'\.sql', r'\.zip', r'\.tar', r'password', r'secret',
            r'token', r'key', r'\.log', r'phpmyadmin', r'\.bak',
        ]

        try:
            data = json.loads(body)
            for row in data[1:]:  # skip header
                url_found = row[0] if row else ""
                for pat in sensitive_patterns:
                    if re.search(pat, url_found, re.I):
                        interesting.append(url_found)
                        break
        except:
            pass

        deduped = list(dict.fromkeys(interesting))[:50]
        ok(f"Wayback Machine found {len(deduped)} interesting historical URLs")

        bugs = []
        for u in deduped[:20]:
            info(f"  historical URL → {u}")
            # Flag highly sensitive ones
            if any(p in u.lower() for p in [".env","backup",".sql",".git","password","secret"]):
                bugs.append({
                    "type":     "Historical Sensitive URL in Wayback Machine",
                    "severity": "MEDIUM",
                    "url":      u,
                    "evidence": f"URL was publicly accessible: {u}",
                    "detail":   "Sensitive file previously exposed — may still be accessible",
                })
                bug_found("Historical Sensitive URL", "MEDIUM", {
                    "URL":      u,
                    "Evidence": "Found in Wayback Machine archive",
                    "Impact":   "File may still be accessible or reveals internal structure",
                })

        return {"urls": deduped, "bugs": bugs}

    # ── 3. DNS History ──────────────────────────────────────────────────────
    def _dns_history(self):
        """Check SecurityTrails-like data via public APIs"""
        info("Checking DNS history via HackerTarget...")
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        body, status = self._fetch(url)
        if not body or "error" in body.lower():
            warn("HackerTarget DNS history unavailable")
            return []

        hosts = []
        for line in body.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                hostname = parts[0].strip()
                ip       = parts[1].strip()
                if hostname.endswith(self.domain):
                    hosts.append({"hostname": hostname, "ip": ip})
                    info(f"  DNS history → {hostname} ({ip})")

        ok(f"DNS history found {len(hosts)} hosts")
        return hosts

    # ── 4. Google Dork Hints ─────────────────────────────────────────────────
    def _google_dorks(self):
        """Generate useful Google dorks for manual investigation"""
        dorks = [
            f'site:{self.domain} ext:php inurl:?',
            f'site:{self.domain} ext:env',
            f'site:{self.domain} ext:sql',
            f'site:{self.domain} inurl:admin',
            f'site:{self.domain} inurl:login',
            f'site:{self.domain} inurl:upload',
            f'site:{self.domain} inurl:api',
            f'site:{self.domain} inurl:debug',
            f'site:{self.domain} inurl:backup',
            f'site:{self.domain} filetype:log',
            f'site:{self.domain} filetype:bak',
            f'site:{self.domain} "index of"',
            f'site:{self.domain} "password" filetype:txt',
            f'site:{self.domain} "DB_PASSWORD" OR "DB_HOST"',
            f'site:{self.domain} intext:"sql syntax" OR "mysql_fetch"',
        ]

        print(f"\n  Google Dorks untuk {self.domain}:")
        print(f"  (Copy paste ke Google untuk investigasi manual)\n")
        for d in dorks:
            print(f"  {d}")

        return dorks

    # ── 5. IP Reputation Check ───────────────────────────────────────────────
    def _ip_reputation(self, ip):
        """Check IP via AbuseIPDB public API"""
        if not ip:
            return {}
        info(f"Checking IP reputation for {ip}...")
        url = f"https://api.hackertarget.com/nmap/?q={ip}"
        body, status = self._fetch(url)
        result = {}
        if body and "open" in body.lower():
            open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\w+)', body)
            if open_ports:
                ok(f"Open ports via passive scan: {open_ports}")
                result["open_ports"] = open_ports
        return result

    # ── 6. Email Breach Check ────────────────────────────────────────────────
    def _check_email_exposure(self):
        """Check if domain emails appear in breach data via public sources"""
        info("Checking email exposure via HaveIBeenPwned domain search...")
        url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
        try:
            req = urllib.request.Request(url, headers={
                **self.headers,
                "hibp-api-key": "public-check-only"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                data = json.loads(body)
                if data:
                    ok(f"Domain found in {len(data)} breach(es)!")
                    for breach in data[:5]:
                        name  = breach.get("Name","?")
                        date  = breach.get("BreachDate","?")
                        count = breach.get("PwnCount",0)
                        warn(f"  Breach: {name} ({date}) — {count:,} accounts")
                    return data
        except:
            pass

        # Fallback — check via emailrep.io
        url2 = f"https://emailrep.io/query/test@{self.domain}"
        body2, _ = self._fetch(url2)
        if body2 and "suspicious" in body2.lower():
            info("Domain flagged as suspicious in email reputation check")

        return []

    def run(self):
        section("Passive Recon (crt.sh | Wayback | DNS History | Dorks)")
        results = {
            "bugs": [],
            "cert_subdomains": [],
            "wayback_urls": [],
            "dns_history": [],
            "google_dorks": [],
        }

        # 1. Certificate transparency
        cert_subs = self._crtsh()
        results["cert_subdomains"] = cert_subs
        if len(cert_subs) > 10:
            results["bugs"].append({
                "type":     "Large Attack Surface via Certificate Transparency",
                "severity": "INFO",
                "url":      f"https://crt.sh/?q=%.{self.domain}",
                "evidence": f"{len(cert_subs)} subdomains found in SSL cert logs",
                "detail":   "Many subdomains may have different security postures",
            })

        # 2. Wayback Machine
        wb = self._wayback()
        if isinstance(wb, dict):
            results["wayback_urls"] = wb.get("urls", [])
            results["bugs"].extend(wb.get("bugs", []))

        # 3. DNS History
        dns_hist = self._dns_history()
        results["dns_history"] = dns_hist

        # 4. Google Dorks
        dorks = self._google_dorks()
        results["google_dorks"] = dorks

        # 5. Email breach
        breaches = self._check_email_exposure()
        if breaches:
            results["bugs"].append({
                "type":     "Domain Found in Data Breach",
                "severity": "HIGH",
                "url":      f"https://haveibeenpwned.com/DomainSearch",
                "evidence": f"Domain in {len(breaches)} known breach(es)",
                "detail":   "Employee credentials may be compromised",
            })

        info(f"Passive recon done — {len(results['bugs'])} findings")
        return results
