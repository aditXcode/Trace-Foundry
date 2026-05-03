"""
Trace Foundry - HTTP Method Checker
Tests for dangerous enabled HTTP methods: PUT, DELETE, TRACE, OPTIONS
"""

import urllib.request
import urllib.error
from utils.display import print_section, ok, warn, info, bug_found

DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
                     "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]

TEST_PATHS = ["/", "/api", "/api/v1", "/upload", "/files", "/admin"]

class HTTPMethodModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def _test_method(self, url, method):
        try:
            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", "Mozilla/5.0 (TraceFoundry/1.0)")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)
        except:
            return 0, {}

    def run(self):
        print_section("HTTP Methods Checker")
        bugs = []

        for path in TEST_PATHS:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{path}"

                # First check OPTIONS to see what's allowed
                status, headers = self._test_method(url, "OPTIONS")
                if status == 0:
                    continue

                allowed = headers.get("Allow", headers.get("allow", ""))
                if allowed:
                    info(f"OPTIONS {url} → Allow: {allowed}")

                # Test TRACE (XST attack)
                t_status, t_headers = self._test_method(url, "TRACE")
                if t_status in (200, 405):
                    if t_status == 200:
                        bug_found("HTTP TRACE ENABLED",
                            f"URL: {url}\n    Status: {t_status}\n"
                            f"    → TRACE method enabled — Cross-Site Tracing (XST) attack possible!")
                        bugs.append({"type": "HTTP TRACE Enabled", "severity": "LOW",
                            "url": url, "status": t_status})

                # Test PUT (file upload)
                p_status, _ = self._test_method(url, "PUT")
                if p_status in (200, 201, 204):
                    bug_found("HTTP PUT ENABLED",
                        f"URL: {url}\n    Status: {p_status}\n"
                        f"    → PUT method allowed — attacker may be able to upload files!")
                    bugs.append({"type": "HTTP PUT Enabled", "severity": "HIGH",
                        "url": url, "status": p_status})

                # Test DELETE
                d_status, _ = self._test_method(url, "DELETE")
                if d_status in (200, 204):
                    bug_found("HTTP DELETE ENABLED",
                        f"URL: {url}\n    Status: {d_status}\n"
                        f"    → DELETE method allowed on {url}!")
                    bugs.append({"type": "HTTP DELETE Enabled", "severity": "MEDIUM",
                        "url": url, "status": d_status})

                # Check allowed header for dangerous methods
                for method in DANGEROUS_METHODS:
                    if method in allowed.upper():
                        warn(f"Method {method} listed in Allow header: {url}")

                ok(f"Methods checked: {url}")
                break

        if not bugs:
            ok("No dangerous HTTP methods found ✓")
        return bugs
