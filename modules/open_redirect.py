"""
Trace Foundry - Open Redirect Checker
Tests URL parameters for open redirect vulnerabilities
"""

import urllib.request
import urllib.error
from utils.display import print_section, ok, warn, info, bug_found

REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "redirectUrl", "redirectUri",
    "return", "returnUrl", "return_url", "returnTo", "return_to",
    "next", "nextUrl", "next_url",
    "url", "goto", "go", "target", "dest", "destination",
    "forward", "location", "continue", "ref", "referrer",
    "callback", "callbackUrl", "callback_url",
    "out", "view", "from", "src", "source",
    "link", "href", "page",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "\\\\evil.com",
    "/\\evil.com",
    "https://evil.com%2F@{domain}",
    "https://{domain}.evil.com",
    "javascript:alert(1)",
    "%2F%2Fevil.com",
]

TEST_PATHS = ["/", "/login", "/logout", "/auth", "/redirect", "/go", "/out"]

class OpenRedirectModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def _test(self, url):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0)"
            })
            # Don't follow redirects automatically — we want to catch them
            opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None
            no_redirect_opener = urllib.request.build_opener(NoRedirect())
            try:
                resp = no_redirect_opener.open(req, timeout=self.timeout)
                return None, resp.status, {}
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location", "")
                return loc, e.code, dict(e.headers)
        except:
            return None, 0, {}

    def run(self):
        print_section("Open Redirect Checker")
        bugs = []
        tested = 0

        for path in TEST_PATHS:
            for param in REDIRECT_PARAMS[:10]:  # test top 10 params
                for payload in REDIRECT_PAYLOADS[:4]:  # test top 4 payloads
                    p = payload.replace("{domain}", self.domain)
                    for scheme in ["https", "http"]:
                        url = f"{scheme}://{self.domain}{path}?{param}={p}"
                        location, status, headers = self._test(url)
                        tested += 1

                        if status in (301, 302, 303, 307, 308) and location:
                            # Check if redirect goes to our evil domain
                            if "evil.com" in location or location.startswith("//evil"):
                                bug_found("OPEN REDIRECT",
                                    f"URL: {url}\n    Redirects to: {location}\n    Status: {status}\n    → Attacker can redirect users to malicious sites!")
                                bugs.append({
                                    "type": "Open Redirect",
                                    "severity": "MEDIUM",
                                    "url": url,
                                    "redirects_to": location,
                                    "param": param,
                                    "payload": p,
                                })
                                break

                        if bugs:
                            break
                    if bugs:
                        break

        info(f"Tested {tested} redirect parameter combinations")
        if not bugs:
            ok("No open redirects found ✓")
        return bugs
