"""
Trace Foundry - HTTP Header Grabber & Tech Detector
Analyzes security headers, detects tech stack, checks cookies
"""

import urllib.request
import urllib.error
from utils.display import print_section, ok, warn, info

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "X-Frame-Options": "Clickjacking Protection",
    "X-Content-Type-Options": "MIME Sniffing Protection",
    "Content-Security-Policy": "Content Security Policy",
    "X-XSS-Protection": "XSS Protection",
    "Referrer-Policy": "Referrer Policy",
    "Permissions-Policy": "Permissions Policy",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
    "Cross-Origin-Embedder-Policy": "COEP",
}

TECH_SIGNATURES = {
    "x-powered-by": "Backend",
    "server": "Web Server",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal CMS",
    "x-wordpress": "WordPress",
    "x-magento": "Magento",
    "cf-ray": "Cloudflare",
    "x-amz": "Amazon AWS",
    "x-goog": "Google Cloud",
    "x-azure": "Microsoft Azure",
    "x-aspnet": "ASP.NET",
    "x-runtime": "Ruby on Rails",
    "x-laravel": "Laravel PHP",
}

class HeaderModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def run(self):
        print_section("HTTP Headers & Tech Detection")
        result = {}

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.domain}"
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0) Security Research"
                })
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    status = r.status
                    ok(f"URL          : {url}  [{status}]")
                    result["url"] = url
                    result["status"] = status
                    result["headers"] = headers

                    # Security headers
                    print(f"\n  \033[96m► Security Headers\033[0m")
                    missing = []
                    present = []
                    for h, label in SECURITY_HEADERS.items():
                        val = headers.get(h.lower())
                        if val:
                            ok(f"  {label:35s}: {val[:60]}")
                            present.append(h)
                        else:
                            warn(f"  {label:35s}: MISSING ⚠️")
                            missing.append(h)
                    result["missing_security_headers"] = missing
                    result["present_security_headers"] = present

                    # Tech detection
                    print(f"\n  \033[96m► Tech Stack\033[0m")
                    tech = []
                    for sig, label in TECH_SIGNATURES.items():
                        for hkey, hval in headers.items():
                            if sig in hkey:
                                ok(f"  {label:35s}: {hval[:60]}")
                                tech.append({"label": label, "value": hval})
                    result["tech_stack"] = tech

                    # Cookie analysis
                    print(f"\n  \033[96m► Cookie Flags\033[0m")
                    cookies = r.headers.get_all("Set-Cookie") or []
                    cookie_issues = []
                    for cookie in cookies:
                        name = cookie.split("=")[0]
                        issues = []
                        if "httponly" not in cookie.lower():
                            issues.append("Missing HttpOnly")
                        if "secure" not in cookie.lower():
                            issues.append("Missing Secure")
                        if "samesite" not in cookie.lower():
                            issues.append("Missing SameSite")
                        if issues:
                            warn(f"  Cookie '{name}': {', '.join(issues)}")
                            cookie_issues.append({"cookie": name, "issues": issues})
                        else:
                            ok(f"  Cookie '{name}': All flags present ✓")
                    result["cookie_issues"] = cookie_issues
                    break

            except urllib.error.URLError as e:
                warn(f"{scheme.upper()} failed: {e}")
            except Exception as e:
                warn(f"Error: {e}")

        return result
