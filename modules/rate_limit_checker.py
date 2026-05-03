"""
Trace Foundry - Rate Limiting Checker
Tests if login/API endpoints lack brute-force protection
"""

import urllib.request
import urllib.error
import time
from utils.display import print_section, ok, warn, info, bug_found

ENDPOINTS_TO_TEST = [
    {"path": "/login",          "method": "POST", "data": b"username=test&password=test"},
    {"path": "/auth/login",     "method": "POST", "data": b"username=test&password=test"},
    {"path": "/api/login",      "method": "POST", "data": b"username=test&password=test"},
    {"path": "/api/v1/login",   "method": "POST", "data": b"username=test&password=test"},
    {"path": "/signin",         "method": "POST", "data": b"email=test@test.com&password=test"},
    {"path": "/user/login",     "method": "POST", "data": b"username=test&password=test"},
    {"path": "/forgot-password","method": "POST", "data": b"email=test@test.com"},
    {"path": "/api/v1/users",   "method": "GET",  "data": None},
    {"path": "/api/v2/users",   "method": "GET",  "data": None},
    {"path": "/search",         "method": "GET",  "data": None},
]

class RateLimitModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def _send(self, url, method, data):
        try:
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent", "Mozilla/5.0 (TraceFoundry/1.0)")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("X-Forwarded-For", "1.2.3.4")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except:
            return 0

    def _test_endpoint(self, url, method, data):
        responses = []
        blocked = False

        for i in range(10):
            status = self._send(url, method, data)
            if status == 0:
                return None, None  # endpoint not reachable

            responses.append(status)

            # Early detection: if we get 429/403 after a few tries, rate limited
            if status in (429, 503) and i >= 2:
                blocked = True
                break

            time.sleep(0.1)  # small delay, not too aggressive

        return responses, blocked

    def run(self):
        print_section("Rate Limiting & Brute-Force Protection")
        bugs = []

        for endpoint in ENDPOINTS_TO_TEST:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{endpoint['path']}"
                responses, blocked = self._test_endpoint(url, endpoint["method"], endpoint["data"])

                if responses is None:
                    break  # not reachable, try next

                unique = set(responses)
                rate_limited = blocked or (429 in unique) or (503 in unique)

                if rate_limited:
                    ok(f"Rate limited ✓ : {endpoint['path']}  (got {unique})")
                else:
                    # All responses same non-error code = no rate limiting
                    if all(s in (200, 201, 400, 401, 403, 422) for s in responses):
                        bug_found("NO RATE LIMITING",
                            f"Endpoint: {url}\n"
                            f"    Method  : {endpoint['method']}\n"
                            f"    Responses: {responses}\n"
                            f"    → 10 requests sent with no rate limit — brute-force possible!")
                        bugs.append({
                            "type": "Missing Rate Limiting",
                            "severity": "MEDIUM",
                            "url": url,
                            "method": endpoint["method"],
                            "responses": responses,
                        })
                break

        if not bugs:
            ok("Rate limiting appears to be in place ✓")
        return bugs
