"""
Trace Foundry V8.5 - OAuth Security Auditor
Tests: redirect_uri bypass, state parameter missing,
       implicit flow, token leakage, open redirect in callback
Anti-FP: Check OAuth endpoints actually exist first
"""
import urllib.request, urllib.error, urllib.parse, re, json
from utils.display import section, ok, info, warn, bug_found
from core.antifp_engines import get_waf_interceptor

OAUTH_ENDPOINTS = [
    "/oauth/authorize", "/oauth2/authorize", "/auth/oauth",
    "/api/oauth/authorize", "/connect/authorize",
    "/oauth/token", "/oauth2/token", "/auth/token",
    "/.well-known/openid-configuration",
    "/api/auth/callback", "/auth/callback",
    "/login/oauth/authorize",  # GitHub style
    "/oauth/v2/auth",          # Google style
]

EVIL_REDIRECTS = [
    "https://evil.com",
    "https://evil.tracefoundry.com",
    "http://evil.com",
    "//evil.com",
    "https://evil.com%2F@{domain}",
    "https://{domain}.evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "/\\/evil.com",
    "https://evil.com?{domain}",
]

class OAuthAuditModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.waf     = get_waf_interceptor()
        self.headers = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.5)"}

    def _fetch(self, url, no_redirect=False):
        try:
            if no_redirect:
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, *a): return None
                opener = urllib.request.build_opener(NoRedirect())
                req = urllib.request.Request(url, headers=self.headers)
                try:
                    with opener.open(req, timeout=self.timeout) as r:
                        return r.read(32768).decode("utf-8",errors="ignore"), r.status, dict(r.headers)
                except urllib.error.HTTPError as e:
                    return "", e.code, dict(e.headers)
            else:
                req = urllib.request.Request(url, headers=self.headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    body = r.read(32768).decode("utf-8",errors="ignore")
                    return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8",errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except: return "", 0, {}

    def _find_oauth_endpoints(self):
        """Discover OAuth endpoints via common paths + OIDC discovery."""
        found = []
        # OIDC discovery
        body, status, _ = self._fetch(
            f"https://{self.domain}/.well-known/openid-configuration")
        if status == 200 and body:
            try:
                config = json.loads(body)
                for key in ["authorization_endpoint","token_endpoint",
                            "userinfo_endpoint","jwks_uri"]:
                    if key in config:
                        found.append(config[key])
                        info(f"OIDC endpoint: {config[key]}")
            except: pass

        # Common paths
        for ep in OAUTH_ENDPOINTS:
            url = f"https://{self.domain}{ep}"
            body, status, headers = self._fetch(url)
            if status in (200, 302, 400, 401):
                if any(kw in body.lower() for kw in
                       ["oauth","client_id","redirect_uri","response_type","scope"]):
                    found.append(url)
                    info(f"OAuth endpoint found: {url}")
        return found

    def _test_redirect_uri_bypass(self, endpoint):
        """Test open redirect in redirect_uri parameter."""
        bugs = []
        for evil_redirect in EVIL_REDIRECTS[:5]:
            evil = evil_redirect.replace("{domain}", self.domain)
            params = urllib.parse.urlencode({
                "client_id":     "test",
                "response_type": "code",
                "redirect_uri":  evil,
                "scope":         "openid profile email",
                "state":         "tftest123",
            })
            url = f"{endpoint}?{params}"
            body, status, headers = self._fetch(url, no_redirect=True)

            location = headers.get("Location", headers.get("location",""))
            if location and "evil.com" in location.lower():
                bugs.append({
                    "type":     "OAuth — Open Redirect via redirect_uri",
                    "severity": "HIGH",
                    "url":      url,
                    "redirect": location,
                    "evil_uri":  evil,
                    "evidence": f"Server redirects to: {location}",
                    "detail":   "redirect_uri not validated — attacker steals auth codes",
                    "impact":   "Authorization code / token theft via open redirect",
                })
                bug_found("OAUTH REDIRECT_URI BYPASS", "HIGH", {
                    "URL":       url,
                    "Evil URI":  evil,
                    "Redirects": location,
                    "Impact":    "Auth code stolen — account takeover possible",
                })
                break
        return bugs

    def _test_missing_state(self, endpoint):
        """Test CSRF via missing state parameter validation."""
        bugs = []
        # Request without state
        params_no_state = urllib.parse.urlencode({
            "client_id":     "test",
            "response_type": "code",
            "redirect_uri":  f"https://{self.domain}/callback",
            "scope":         "openid",
        })
        url = f"{endpoint}?{params_no_state}"
        body, status, headers = self._fetch(url)
        if status in (200, 302):
            # If no error about missing state = vulnerable
            if "state" not in body.lower() and "csrf" not in body.lower():
                bugs.append({
                    "type":     "OAuth — Missing State Parameter (CSRF Risk)",
                    "severity": "MEDIUM",
                    "url":      url,
                    "evidence": "No error for missing 'state' parameter",
                    "detail":   "CSRF attack possible — attacker can initiate OAuth flow for victim",
                    "impact":   "CSRF on OAuth flow — account linking attack",
                })
                bug_found("OAUTH MISSING STATE", "MEDIUM", {
                    "URL":      url,
                    "Evidence": "Request accepted without state param",
                    "Impact":   "CSRF attack on OAuth authorization flow",
                })
        return bugs

    def _test_token_in_url(self, endpoint):
        """Check if tokens appear in URL (implicit flow leak)."""
        bugs = []
        params = urllib.parse.urlencode({
            "client_id":     "test",
            "response_type": "token",  # implicit flow
            "redirect_uri":  f"https://{self.domain}/callback",
            "scope":         "openid",
            "state":         "tftest",
        })
        url = f"{endpoint}?{params}"
        body, status, headers = self._fetch(url)
        location = headers.get("Location", headers.get("location",""))
        if location and ("access_token=" in location or "token=" in location):
            bugs.append({
                "type":     "OAuth — Implicit Flow Token in URL",
                "severity": "MEDIUM",
                "url":      url,
                "location": location[:80],
                "evidence": "access_token found in redirect URL",
                "detail":   "Implicit flow exposes tokens in URL — logged by browsers/proxies",
                "impact":   "Token leakage via browser history, referrer headers, logs",
            })
            bug_found("OAUTH TOKEN IN URL", "MEDIUM", {
                "URL":      url,
                "Location": location[:60],
                "Impact":   "Token exposed in URL — leaks via referrer/logs",
            })
        return bugs

    def run(self):
        section("OAuth Security Auditor (redirect_uri | state | implicit flow)")
        all_bugs = []
        endpoints = self._find_oauth_endpoints()

        if not endpoints:
            info("No OAuth endpoints found on this domain")
            ok("No OAuth endpoints detected ✓")
            return {"bugs": []}

        for ep in endpoints[:5]:
            all_bugs.extend(self._test_redirect_uri_bypass(ep))
            all_bugs.extend(self._test_missing_state(ep))
            all_bugs.extend(self._test_token_in_url(ep))

        info(f"OAuth audit done — {len(all_bugs)} findings")
        if not all_bugs: ok("No OAuth misconfigurations found ✓")
        return {"bugs": all_bugs}
