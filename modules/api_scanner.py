"""
Trace Foundry V5 - API Security Scanner
JWT weakness, GraphQL introspection, mass assignment, broken auth
"""
import urllib.request
import urllib.error
import urllib.parse
import json
import base64
import re
from utils.display import section, ok, warn, info, bug_found

JWT_WEAK_SECRETS = [
    "secret","password","123456","admin","test","key","jwt",
    "your-256-bit-secret","supersecret","mysecret","change_this",
    "","null","undefined","none",
]

GRAPHQL_ENDPOINTS = [
    "/graphql","/api/graphql","/v1/graphql","/query",
    "/api/query","/graph","/gql","/api/gql",
]

API_ENDPOINTS = [
    "/api","/api/v1","/api/v2","/api/v3",
    "/v1","/v2","/v3",
    "/rest","/api/rest",
    "/swagger.json","/openapi.json","/api-docs",
    "/api/swagger.json","/api/openapi.json",
]

class APIScannerModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, */*",
            "Content-Type": "application/json",
        }

    def _fetch(self, url, data=None, extra_headers=None):
        h = {**self.headers, **(extra_headers or {})}
        try:
            post = json.dumps(data).encode() if data else None
            req  = urllib.request.Request(url, data=post, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except:
            return "", 0, {}

    # ── JWT Analysis ────────────────────────────────────────────────────────
    def _find_jwts(self, body):
        pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        )
        return pattern.findall(body)

    def _decode_jwt(self, token):
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None
            # Pad base64
            header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            return header, payload
        except:
            return None, None

    def _test_jwt_alg_none(self, token):
        """Test alg:none attack"""
        try:
            parts   = token.split(".")
            header  = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            # Forge token with alg:none
            header["alg"] = "none"
            new_header  = base64.urlsafe_b64encode(
                json.dumps(header).encode()).decode().rstrip("=")
            new_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()).decode().rstrip("=")
            forged = f"{new_header}.{new_payload}."
            return forged, header, payload
        except:
            return None, None, None

    def _scan_jwt(self):
        bugs = []
        # Fetch homepage and common API endpoints to find JWTs
        for ep in ["/", "/api/v1/me", "/api/user", "/dashboard"]:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{ep}"
                body, status, headers = self._fetch(url)
                if not body:
                    continue

                # Check response headers for JWT
                auth_header = headers.get("Authorization", headers.get("authorization",""))
                all_text = body + auth_header

                jwts = self._find_jwts(all_text)
                for jwt in jwts[:3]:
                    header, payload = self._decode_jwt(jwt)
                    if not header:
                        continue

                    alg = header.get("alg","").upper()
                    info(f"JWT found at {url} — alg: {alg}")

                    # alg:none vulnerability
                    if alg in ("NONE",""):
                        bugs.append({
                            "type":     "JWT — Algorithm None Accepted",
                            "severity": "CRITICAL",
                            "url":      url,
                            "alg":      alg,
                            "evidence": f"JWT uses alg:{alg} — no signature verification!",
                            "impact":   "Attacker can forge any JWT token without knowing secret",
                        })

                    # Weak algorithm
                    if alg in ("HS256","HS384","HS512") and payload:
                        bugs.append({
                            "type":     "JWT — Weak HMAC Algorithm Detected",
                            "severity": "MEDIUM",
                            "url":      url,
                            "alg":      alg,
                            "evidence": f"JWT uses {alg} — susceptible to brute-force if weak secret",
                            "impact":   "If secret is weak, entire auth system can be bypassed",
                        })

                    # Check for sensitive data in payload
                    if payload:
                        sensitive = ["password","pwd","secret","key","admin","role","is_admin"]
                        found_sens = [k for k in payload.keys()
                                      if any(s in k.lower() for s in sensitive)]
                        if found_sens:
                            bugs.append({
                                "type":     "JWT — Sensitive Data in Payload",
                                "severity": "MEDIUM",
                                "url":      url,
                                "evidence": f"Payload contains: {', '.join(found_sens)}",
                                "impact":   "Sensitive fields visible to anyone who decodes token",
                            })

                break
        return bugs

    # ── GraphQL ────────────────────────────────────────────────────────────
    def _scan_graphql(self):
        bugs = []
        introspection_query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }

        for ep in GRAPHQL_ENDPOINTS:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{ep}"
                body, status, _ = self._fetch(url, data=introspection_query)
                if status == 0:
                    continue

                if '"__schema"' in body or '"types"' in body:
                    bugs.append({
                        "type":     "GraphQL — Introspection Enabled",
                        "severity": "MEDIUM",
                        "url":      url,
                        "evidence": "GraphQL introspection query returns schema data",
                        "impact":   "Attacker can enumerate entire API schema, all queries, mutations",
                    })
                    ok(f"GraphQL found: {url}")

                    # Test for debug/playground
                    pg_body, pg_status, _ = self._fetch(url)
                    if pg_status == 200 and any(
                        kw in pg_body.lower() for kw in
                        ["graphiql","playground","voyager","explorer"]
                    ):
                        bugs.append({
                            "type":     "GraphQL — Playground/IDE Exposed",
                            "severity": "MEDIUM",
                            "url":      url,
                            "evidence": "GraphQL IDE/playground accessible publicly",
                            "impact":   "Anyone can query and explore the entire API interactively",
                        })
                    break

        return bugs

    # ── API Endpoint Scan ──────────────────────────────────────────────────
    def _scan_api_endpoints(self):
        bugs = []

        for ep in API_ENDPOINTS:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{ep}"
                body, status, headers = self._fetch(url)
                if status not in (200, 201):
                    continue

                ctype = headers.get("Content-Type", headers.get("content-type",""))

                # OpenAPI/Swagger spec exposed
                if ep in ("/swagger.json","/openapi.json","/api-docs",
                          "/api/swagger.json","/api/openapi.json"):
                    if '"paths"' in body or '"swagger"' in body or '"openapi"' in body:
                        bugs.append({
                            "type":     "API — OpenAPI/Swagger Spec Exposed",
                            "severity": "MEDIUM",
                            "url":      url,
                            "evidence": "Full API specification publicly accessible",
                            "impact":   "Reveals all endpoints, params, auth methods to attacker",
                        })

                # Check for mass assignment indicators
                if "application/json" in ctype and body:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            dangerous = ["role","is_admin","admin","permission",
                                         "privilege","access_level","account_type"]
                            found = [k for k in str(data).lower().split()
                                     if any(d in k for d in dangerous)]
                            if found:
                                bugs.append({
                                    "type":     "API — Mass Assignment Risk",
                                    "severity": "MEDIUM",
                                    "url":      url,
                                    "evidence": f"Response contains privileged fields: {', '.join(set(found[:3]))}",
                                    "impact":   "Sending these fields in requests may escalate privileges",
                                })
                    except:
                        pass

                # Unauthenticated API access
                if status == 200 and "json" in ctype:
                    bugs.append({
                        "type":     "API — Unauthenticated Access",
                        "severity": "MEDIUM",
                        "url":      url,
                        "evidence": f"API endpoint returns 200 JSON without auth header",
                        "impact":   "Public access to potentially sensitive API data",
                    })
                    ok(f"Open API: {url}")

                break

        return bugs

    def run(self):
        section("API Security Scanner (JWT | GraphQL | OpenAPI | Auth)")
        all_bugs = []

        jwt_bugs  = self._scan_jwt()
        for b in jwt_bugs:
            bug_found(b["type"], b["severity"], {
                "URL":      b.get("url",""),
                "Algorithm":b.get("alg",""),
                "Evidence": b["evidence"],
                "Impact":   b["impact"],
            })
        all_bugs.extend(jwt_bugs)

        gql_bugs = self._scan_graphql()
        for b in gql_bugs:
            bug_found(b["type"], b["severity"], {
                "URL":      b["url"],
                "Evidence": b["evidence"],
                "Impact":   b["impact"],
            })
        all_bugs.extend(gql_bugs)

        api_bugs = self._scan_api_endpoints()
        for b in api_bugs:
            bug_found(b["type"], b["severity"], {
                "URL":      b["url"],
                "Evidence": b["evidence"],
                "Impact":   b["impact"],
            })
        all_bugs.extend(api_bugs)

        info(f"API scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No API security issues found ✓")
        return {"bugs": all_bugs}
