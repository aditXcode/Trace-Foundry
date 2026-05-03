"""
Trace Foundry - Security Headers Deep Checker
Scores and grades the security posture of HTTP headers
"""

import urllib.request
import urllib.error
from utils.display import print_section, ok, warn, info, bug_found

HEADER_RULES = [
    {
        "header": "Strict-Transport-Security",
        "label": "HSTS",
        "severity": "HIGH",
        "required": True,
        "good_value": "max-age=31536000; includeSubDomains",
        "bad_hints": {
            "max-age=0": "HSTS max-age is 0 — HSTS is effectively disabled!",
            "max-age=1": "HSTS max-age too short",
        }
    },
    {
        "header": "Content-Security-Policy",
        "label": "CSP",
        "severity": "HIGH",
        "required": True,
        "bad_hints": {
            "unsafe-inline": "CSP contains 'unsafe-inline' — XSS protections weakened!",
            "unsafe-eval": "CSP contains 'unsafe-eval' — JS eval allowed!",
            "*": "CSP uses wildcard (*) — overly permissive!",
        }
    },
    {
        "header": "X-Frame-Options",
        "label": "Clickjacking Protection",
        "severity": "MEDIUM",
        "required": True,
        "bad_hints": {
            "ALLOWALL": "X-Frame-Options set to ALLOWALL — clickjacking possible!",
        }
    },
    {
        "header": "X-Content-Type-Options",
        "label": "MIME Sniffing",
        "severity": "LOW",
        "required": True,
        "good_value": "nosniff",
    },
    {
        "header": "Referrer-Policy",
        "label": "Referrer Policy",
        "severity": "LOW",
        "required": True,
        "bad_hints": {
            "unsafe-url": "Referrer-Policy set to unsafe-url — full URL sent to third parties!",
        }
    },
    {
        "header": "Permissions-Policy",
        "label": "Permissions Policy",
        "severity": "LOW",
        "required": True,
    },
    {
        "header": "X-XSS-Protection",
        "label": "Legacy XSS Protection",
        "severity": "INFO",
        "required": False,
        "bad_hints": {
            "0": "X-XSS-Protection: 0 disables the built-in browser XSS filter",
        }
    },
    {
        "header": "Server",
        "label": "Server Banner",
        "severity": "INFO",
        "required": False,
        "version_leak": True,
    },
    {
        "header": "X-Powered-By",
        "label": "Tech Banner",
        "severity": "LOW",
        "required": False,
        "version_leak": True,
    },
]

class HeaderCheckerModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def _fetch_headers(self, url):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0)"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {k.lower(): v for k, v in r.headers.items()}, r.status
        except urllib.error.HTTPError as e:
            return {k.lower(): v for k, v in e.headers.items()}, e.code
        except:
            return {}, 0

    def run(self):
        print_section("Security Headers Deep Audit")
        bugs = []
        score = 100

        headers, status = {}, 0
        for scheme in ["https", "http"]:
            headers, status = self._fetch_headers(f"{scheme}://{self.domain}")
            if headers:
                ok(f"Connected    : {scheme}://{self.domain} [{status}]")
                break

        if not headers:
            warn("Could not fetch headers")
            return {"bugs": [], "score": 0, "grade": "F"}

        print()
        for rule in HEADER_RULES:
            h = rule["header"].lower()
            val = headers.get(h)

            if rule.get("version_leak") and val:
                bug_found(f"VERSION/TECH DISCLOSURE: {rule['label']}",
                    f"Header '{rule['header']}: {val}'\n    → Reveals server technology to attackers")
                bugs.append({"type": f"Tech Disclosure: {rule['header']}", "severity": "LOW",
                    "detail": val})
                score -= 3
                continue

            if val is None and rule["required"]:
                sev = rule["severity"]
                deduction = {"HIGH": 15, "MEDIUM": 10, "LOW": 5, "INFO": 0}.get(sev, 5)
                bug_found(f"MISSING HEADER [{sev}]: {rule['label']}",
                    f"'{rule['header']}' is not set\n    → Recommended value: {rule.get('good_value','set this header')}")
                bugs.append({"type": f"Missing Header: {rule['header']}", "severity": sev})
                score -= deduction

            elif val:
                bad_hints = rule.get("bad_hints", {})
                flagged = False
                for keyword, message in bad_hints.items():
                    if keyword.lower() in val.lower():
                        bug_found(f"WEAK HEADER CONFIG: {rule['label']}",
                            f"'{rule['header']}: {val[:80]}'\n    → {message}")
                        bugs.append({"type": f"Weak Header: {rule['header']}", "severity": rule["severity"],
                            "detail": message})
                        score -= 8
                        flagged = True
                        break
                if not flagged:
                    ok(f"{rule['label']:35s}: {val[:60]} ✓")

        # Grade
        score = max(0, score)
        grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else \
                "C" if score >= 55 else "D" if score >= 40 else "F"

        print()
        info(f"Security Score : {score}/100  →  Grade: {grade}")
        if grade in ("D", "F"):
            bug_found("LOW SECURITY SCORE", f"Score {score}/100 (Grade {grade}) — significant header hardening needed")

        return {"bugs": bugs, "score": score, "grade": grade}
