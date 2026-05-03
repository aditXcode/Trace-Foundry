"""
Trace Foundry V5 - IDOR / Broken Access Control Engine
Multi-role response comparator, UUID enum, parameter manipulation
"""
import urllib.request
import urllib.error
import urllib.parse
import re
import json
from utils.display import section, ok, warn, info, bug_found

# Common IDOR parameter names
IDOR_PARAMS = [
    "id","user_id","uid","account_id","order_id","invoice_id",
    "file_id","doc_id","report_id","ticket_id","case_id",
    "customer_id","profile_id","member_id","record_id","item_id",
    "uuid","guid","token","ref","reference","key","hash",
]

# Endpoints likely to have IDOR
IDOR_ENDPOINTS = [
    "/api/user/{id}","/api/v1/user/{id}","/api/v2/user/{id}",
    "/api/account/{id}","/api/profile/{id}","/api/order/{id}",
    "/api/invoice/{id}","/api/v1/orders/{id}",
    "/user/{id}","/profile/{id}","/account/{id}",
    "/api/v1/admin/users/{id}","/admin/users/{id}",
    "/api/file/{id}","/download/{id}","/document/{id}",
]

# UUID patterns for enumeration detection
UUID_PATTERN = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I
)
NUMERIC_ID_PATTERN = re.compile(r'"(?:id|user_id|uid)":\s*(\d+)')

class IDORModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/html, */*",
        }

    def _fetch(self, url, headers=None):
        h = {**self.headers, **(headers or {})}
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _find_ids_in_response(self, body):
        """Extract IDs from API responses"""
        ids = set()
        # Numeric IDs
        for m in NUMERIC_ID_PATTERN.findall(body):
            ids.add(m)
        # UUIDs
        for m in UUID_PATTERN.findall(body):
            ids.add(m)
        return list(ids)

    def _compare_responses(self, body1, body2, status1, status2):
        """Check if two responses are meaningfully different"""
        if status1 != status2:
            return True, f"Status codes differ: {status1} vs {status2}"
        len_diff = abs(len(body1) - len(body2))
        if len_diff > 50 and status2 == 200:
            return True, f"Response length diff: {len(body1)} vs {len(body2)} bytes"
        return False, None

    def _test_id_enumeration(self, base_url, id_val):
        """Test if incrementing/decrementing ID reveals other records"""
        bugs = []
        try:
            id_int = int(id_val)
        except:
            return bugs

        url_orig  = base_url.replace("{id}", str(id_int))
        url_other = base_url.replace("{id}", str(id_int + 1))
        url_admin = base_url.replace("{id}", "1")  # Try ID=1 (often admin)

        body_orig,  status_orig  = self._fetch(url_orig)
        body_other, status_other = self._fetch(url_other)
        body_admin, status_admin = self._fetch(url_admin)

        if status_orig == 0:
            return bugs

        # If both return 200, potential IDOR
        if status_orig == 200 and status_other == 200 and body_other != body_orig:
            bugs.append({
                "type":     "IDOR — Sequential ID Enumeration",
                "severity": "HIGH",
                "url":      url_other,
                "base_url": base_url,
                "evidence": f"ID {id_int} and {id_int+1} both return 200 with different data",
                "impact":   "Attacker can enumerate all records by incrementing ID",
            })

        # Admin ID=1 returns data?
        if status_admin == 200 and url_admin != url_orig:
            bugs.append({
                "type":     "IDOR — Admin Record (ID=1) Accessible",
                "severity": "CRITICAL",
                "url":      url_admin,
                "base_url": base_url,
                "evidence": f"GET {url_admin} returns 200 — ID=1 often = admin/first user",
                "impact":   "May expose admin user data without authentication",
            })

        return bugs

    def _test_horizontal_access(self, endpoint):
        """Test horizontal privilege escalation"""
        bugs = []
        test_ids = ["1","2","3","0","-1","99999","admin","test","../admin"]

        for id_val in test_ids:
            url = f"https://{self.domain}{endpoint.replace('{id}', id_val)}"
            body, status = self._fetch(url)
            if status in (200, 201) and body and len(body) > 50:
                # Check if response looks like user data
                if any(kw in body.lower() for kw in
                       ["email","username","password","token","secret","admin","user"]):
                    bugs.append({
                        "type":     "IDOR — Unauthenticated Data Access",
                        "severity": "HIGH",
                        "url":      url,
                        "id_used":  id_val,
                        "evidence": f"GET returned 200 with {len(body)} bytes containing user data fields",
                        "impact":   "Endpoint returns sensitive data without authentication",
                    })
                    break

        return bugs

    def _test_param_tampering(self, base_url):
        """Test GET parameter IDOR"""
        bugs = []
        body_baseline, status_baseline = self._fetch(base_url)
        if status_baseline == 0:
            return bugs

        for param in IDOR_PARAMS[:8]:
            for id_val in ["1","2","0","admin","../admin","-1"]:
                url = f"{base_url}?{param}={id_val}"
                body, status = self._fetch(url)
                if status == 200 and body != body_baseline and len(body) > 100:
                    if any(kw in body.lower() for kw in
                           ["email","user","account","profile","name","password","token"]):
                        bugs.append({
                            "type":     "IDOR — GET Parameter Tampering",
                            "severity": "HIGH",
                            "url":      url,
                            "param":    param,
                            "value":    id_val,
                            "evidence": f"Param '{param}={id_val}' returns different user data (200, {len(body)}b)",
                            "impact":   "Can access other users' data by changing parameter value",
                        })
                        break

        return bugs

    def run(self):
        section("IDOR / Broken Access Control Engine")
        all_bugs = []

        # Test param tampering on common pages
        for ep in ["/","/api","/api/v1","/profile","/account","/user"]:
            for scheme in ["https","http"]:
                url = f"{scheme}://{self.domain}{ep}"
                bugs = self._test_param_tampering(url)
                for b in bugs:
                    bug_found(b["type"], b["severity"], {
                        "URL":      b["url"],
                        "Param":    b.get("param",""),
                        "Value":    b.get("value",""),
                        "Evidence": b["evidence"],
                        "Impact":   b["impact"],
                    })
                all_bugs.extend(bugs)
                break

        # Test REST endpoints with ID patterns
        for endpoint in IDOR_ENDPOINTS:
            bugs = self._test_horizontal_access(endpoint)
            for b in bugs:
                bug_found(b["type"], b["severity"], {
                    "URL":      b["url"],
                    "ID Used":  b.get("id_used",""),
                    "Evidence": b["evidence"],
                    "Impact":   b["impact"],
                })
            all_bugs.extend(bugs)

        info(f"IDOR scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No IDOR found ✓")
        return {"bugs": all_bugs}
