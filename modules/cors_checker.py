"""
Trace Foundry - CORS Misconfiguration Checker
Tests for dangerous CORS policies that allow credential theft
"""

import urllib.request
import urllib.error
from utils.display import print_section, ok, warn, info, bug_found

# Origins to test for reflection/wildcard bugs
TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{domain}.evil.com",
    "https://evil{domain}",
]

ENDPOINTS = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/user",
    "/profile",
    "/account",
    "/admin",
    "/auth",
]

class CORSModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def _check(self, url, origin):
        try:
            req = urllib.request.Request(url)
            req.add_header("Origin", origin)
            req.add_header("User-Agent", "Mozilla/5.0 (TraceFoundry/1.0)")
            req.add_header("Cookie", "session=test")  # simulate credentialed request
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                return headers, r.status
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            return headers, e.code
        except:
            return {}, 0

    def run(self):
        print_section("CORS Misconfiguration Checker")
        bugs = []
        tested = 0

        for endpoint in ENDPOINTS:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{endpoint}"
                for raw_origin in TEST_ORIGINS:
                    origin = raw_origin.replace("{domain}", self.domain)
                    headers, status = self._check(url, origin)
                    if not headers:
                        continue

                    tested += 1
                    acao = headers.get("access-control-allow-origin", "")
                    acac = headers.get("access-control-allow-credentials", "")

                    if not acao:
                        continue

                    # Bug: wildcard with credentials
                    if acao == "*" and acac.lower() == "true":
                        bug_found("CORS: WILDCARD + CREDENTIALS",
                            f"{url}\n    Origin: {origin}\n    ACAO: {acao} | ACAC: {acac}\n    → Attacker can make credentialed cross-origin requests!")
                        bugs.append({
                            "type": "CORS Wildcard + Credentials",
                            "severity": "CRITICAL",
                            "url": url, "origin": origin,
                            "acao": acao, "acac": acac,
                        })

                    # Bug: arbitrary origin reflected + credentials
                    elif acao == origin and acac.lower() == "true":
                        bug_found("CORS: ORIGIN REFLECTED + CREDENTIALS",
                            f"{url}\n    Origin: {origin}\n    ACAO: {acao} | ACAC: {acac}\n    → Any attacker origin is trusted with credentials!")
                        bugs.append({
                            "type": "CORS Origin Reflected with Credentials",
                            "severity": "HIGH",
                            "url": url, "origin": origin,
                            "acao": acao, "acac": acac,
                        })

                    # Bug: null origin trusted
                    elif origin == "null" and acao == "null":
                        bug_found("CORS: NULL ORIGIN TRUSTED",
                            f"{url}\n    Null origin accepted — sandbox iframes can exploit this!")
                        bugs.append({
                            "type": "CORS Null Origin Trusted",
                            "severity": "MEDIUM",
                            "url": url, "origin": origin,
                            "acao": acao,
                        })

                    # Info: origin reflected without credentials
                    elif acao == origin:
                        info(f"CORS reflects origin (no credentials): {url} [{origin}]")

                break  # only test first working scheme

        info(f"Tested {tested} combinations across {len(ENDPOINTS)} endpoints")
        if not bugs:
            ok("No dangerous CORS misconfigurations found ✓")
        return bugs
