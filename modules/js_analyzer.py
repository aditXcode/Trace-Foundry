"""
Trace Foundry - JavaScript Analyzer
Extracts API endpoints, hardcoded secrets, tokens, and internal paths from JS files
"""

import urllib.request
import urllib.error
import re
from utils.display import print_section, ok, warn, info, bug_found

# Patterns for secrets
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Key":         r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Stripe Secret Key":    r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Publishable":   r"pk_live_[0-9a-zA-Z]{24,}",
    "GitHub Token":         r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth":         r"gho_[0-9a-zA-Z]{36}",
    "Private Key":          r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "JWT Token":            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Basic Auth (base64)":  r"Basic [A-Za-z0-9+/]{20,}={0,2}",
    "Bearer Token":         r"Bearer [A-Za-z0-9\-_]{20,}",
    "Generic Password":     r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    "Generic Secret":       r"(?i)(secret|api_key|apikey|access_token|auth_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Hardcoded IP":         r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    "Email in Code":        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
}

# Patterns for interesting endpoints
ENDPOINT_PATTERNS = [
    r"""['"](/api/[a-zA-Z0-9/_\-\.]+)['"]""",
    r"""['"](/v\d+/[a-zA-Z0-9/_\-\.]+)['"]""",
    r"""fetch\s*\(\s*['"]([^'"]+)['"]""",
    r"""axios\.[a-z]+\s*\(\s*['"]([^'"]+)['"]""",
    r"""url\s*[:=]\s*['"]([^'"]{5,})['"]""",
    r"""endpoint\s*[:=]\s*['"]([^'"]{5,})['"]""",
    r"""baseURL\s*[:=]\s*['"]([^'"]{5,})['"]""",
    r"""['"]([^'"]*/(admin|internal|debug|test|dev|backup|config|secret)[^'"]*)['"]""",
]

class JSAnalyzerModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0)"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except:
            return ""

    def _find_js_files(self):
        """Find JS files from homepage HTML"""
        js_files = set()
        for scheme in ["https", "http"]:
            html = self._fetch(f"{scheme}://{self.domain}")
            if not html:
                continue
            # Extract src attributes
            for match in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
                if match.startswith("http"):
                    js_files.add(match)
                elif match.startswith("//"):
                    js_files.add("https:" + match)
                elif match.startswith("/"):
                    js_files.add(f"{scheme}://{self.domain}{match}")
            break

        # Also try common JS file locations
        common = ["/app.js", "/main.js", "/bundle.js", "/app.min.js",
                  "/static/js/main.js", "/assets/js/app.js", "/js/app.js",
                  "/dist/bundle.js", "/build/static/js/main.chunk.js"]
        for path in common:
            js_files.add(f"https://{self.domain}{path}")

        return list(js_files)[:20]  # limit to 20 files

    def run(self):
        print_section("JavaScript File Analyzer")
        bugs = []
        all_endpoints = set()

        js_files = self._find_js_files()
        info(f"JS files to analyze: {len(js_files)}")

        for js_url in js_files:
            content = self._fetch(js_url)
            if not content or len(content) < 50:
                continue

            ok(f"Analyzing: {js_url} ({len(content)//1024}KB)")

            # Secret scanning
            for label, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    # Skip common false positives
                    if label == "Email in Code" and ("example" in match or "test@" in match):
                        continue
                    if label == "Hardcoded IP" and match in ("192.168.0.1", "10.0.0.1"):
                        continue
                    bug_found(f"SECRET FOUND: {label}",
                        f"File: {js_url}\n    Value: {str(match)[:80]}\n    → This may be a real secret exposed in client-side JS!")
                    bugs.append({
                        "type": f"Hardcoded Secret: {label}",
                        "severity": "CRITICAL" if "Key" in label or "Token" in label or "Password" in label else "HIGH",
                        "file": js_url,
                        "match": str(match)[:100],
                    })

            # Endpoint extraction
            for pattern in ENDPOINT_PATTERNS:
                for match in re.findall(pattern, content):
                    ep = match if isinstance(match, str) else match[0]
                    if len(ep) > 3 and not ep.endswith((".png",".jpg",".css",".ico")):
                        all_endpoints.add(ep)

        if all_endpoints:
            info(f"API Endpoints discovered: {len(all_endpoints)}")
            for ep in sorted(all_endpoints)[:30]:
                ok(f"  Endpoint → {ep}")

        if not bugs:
            ok("No hardcoded secrets found in JS files ✓")

        return {
            "bugs": bugs,
            "endpoints_found": sorted(all_endpoints),
            "js_files_analyzed": len(js_files),
        }
