"""
Trace Foundry V7 - Credential & Breach Checker
Checks domain exposure in public breach databases,
leaked config files, exposed credentials in JS/HTML,
and default credential testing
"""
import urllib.request
import urllib.error
import urllib.parse
import re
import json
from utils.display import section, ok, warn, info, bug_found, print_section

# Default credentials to test on login forms
DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "123456"),
    ("admin",     "admin123"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("test",      "test"),
    ("user",      "user"),
    ("guest",     "guest"),
    ("demo",      "demo"),
    ("operator",  "operator"),
]

# Patterns that indicate leaked credentials
CREDENTIAL_PATTERNS = {
    "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
    "AWS Secret":        r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}',
    "GitHub Token":      r'ghp_[0-9a-zA-Z]{36}',
    "Slack Token":       r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "Stripe Key":        r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe PK":         r'pk_live_[0-9a-zA-Z]{24,}',
    "Private Key":       r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "DB Password":       r'(?i)(db_pass|database_password|mysql_password|db_password)\s*[=:]\s*["\'][^"\']{4,}["\']',
    "Generic Password":  r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
    "Generic Secret":    r'(?i)(secret|api_secret|client_secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
    "Basic Auth":        r'Authorization:\s*Basic\s+[A-Za-z0-9+/]{20,}={0,2}',
    "Bearer Token":      r'Authorization:\s*Bearer\s+[A-Za-z0-9\-_.]{20,}',
    "JWT Token":         r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "SSH Key":           r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "NPM Token":         r'npm_[A-Za-z0-9]{36}',
    "Twilio":            r'SK[0-9a-fA-F]{32}',
    "SendGrid":          r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
}

SENSITIVE_ENDPOINTS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.json", "/config.php", "/configuration.php",
    "/settings.py", "/settings.php", "/database.yml",
    "/wp-config.php", "/wp-config.php.bak",
    "/application.properties", "/application.yml",
    "/appsettings.json", "/web.config",
    "/.git/config", "/.git/HEAD",
    "/composer.json", "/package.json",
    "/Gemfile", "/requirements.txt",
    "/docker-compose.yml", "/Dockerfile",
    "/.dockerenv", "/kubernetes.yml",
    "/secrets.yml", "/secrets.json",
    "/credentials.json", "/credentials.xml",
    "/id_rsa", "/id_dsa", "/.ssh/id_rsa",
    "/server.key", "/server.pem",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz",
]

class CredentialModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body    = r.read(65536).decode("utf-8", errors="ignore")
                return body, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def _scan_credentials_in_content(self, url, body):
        """Scan page content for leaked credentials"""
        bugs = []
        for cred_type, pattern in CREDENTIAL_PATTERNS.items():
            matches = re.findall(pattern, body)
            for match in matches:
                match_str = str(match)[:80]
                # Skip obvious false positives
                if any(fp in match_str.lower() for fp in [
                    "example","test123","password123","placeholder",
                    "your-secret","change-me","xxxx","****"
                ]):
                    continue
                bugs.append({
                    "type":     f"Leaked Credential: {cred_type}",
                    "severity": "CRITICAL",
                    "url":      url,
                    "cred_type":cred_type,
                    "evidence": f"Pattern matched: {match_str[:60]}",
                    "detail":   f"Real {cred_type} found in publicly accessible file",
                })
                bug_found(f"LEAKED CREDENTIAL: {cred_type}", "CRITICAL", {
                    "URL":      url,
                    "Type":     cred_type,
                    "Evidence": match_str[:60],
                    "Impact":   "Real credential exposed — attacker can use immediately!",
                })
        return bugs

    def _check_sensitive_files(self):
        """Check for exposed sensitive files"""
        bugs = []
        info(f"Checking {len(SENSITIVE_ENDPOINTS)} sensitive file locations...")

        for path in SENSITIVE_ENDPOINTS:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{path}"
                body, status = self._fetch(url)
                if status != 200 or not body or len(body) < 10:
                    continue

                # Verify it's actually sensitive content
                is_sensitive = False

                if path.endswith(".env") or ".env." in path:
                    if any(kw in body for kw in ["APP_","DB_","SECRET","KEY","PASSWORD","TOKEN"]):
                        is_sensitive = True
                elif path.endswith((".sql",".dump")):
                    if any(kw in body.lower() for kw in ["insert into","create table","--"]):
                        is_sensitive = True
                elif path.endswith(("id_rsa","id_dsa",".key",".pem")):
                    if "PRIVATE KEY" in body or "BEGIN RSA" in body:
                        is_sensitive = True
                elif path.endswith((".json",".yml",".yaml",".xml",".php",".py")):
                    if any(kw in body.lower() for kw in [
                        "password","secret","key","token","credential","database"
                    ]):
                        is_sensitive = True
                elif path == "/.git/HEAD":
                    if "ref:" in body:
                        is_sensitive = True
                elif path.endswith((".zip",".tar.gz",".bak")):
                    is_sensitive = True  # Any backup file accessible is a finding

                if is_sensitive:
                    # Scan content for actual credentials
                    cred_bugs = self._scan_credentials_in_content(url, body)
                    bugs.extend(cred_bugs)

                    if not cred_bugs:
                        # Still report as sensitive file exposure
                        sev = "CRITICAL" if any(p in path for p in [
                            "id_rsa","id_dsa",".key","private","secret",".sql","backup"
                        ]) else "HIGH"
                        bugs.append({
                            "type":     f"Sensitive File Exposed: {path}",
                            "severity": sev,
                            "url":      url,
                            "evidence": f"HTTP 200 — {len(body)} bytes of sensitive content",
                            "detail":   f"File {path} accessible without authentication",
                        })
                        bug_found(f"Sensitive File: {path}", sev, {
                            "URL":     url,
                            "Size":    f"{len(body)} bytes",
                            "Impact":  "Sensitive configuration/credential file exposed",
                        })
                break

        return bugs

    def _test_default_credentials(self):
        """Test default credentials on login endpoints"""
        bugs = []
        login_endpoints = [
            "/login", "/admin/login", "/wp-login.php",
            "/admin", "/administrator", "/signin",
            "/api/login", "/api/v1/login", "/user/login",
            "/auth/login", "/account/login",
        ]

        info("Testing default credentials on login endpoints...")

        for endpoint in login_endpoints:
            url = f"https://{self.domain}{endpoint}"
            body, status = self._fetch(url)
            if status not in (200, 302) or not body:
                continue

            # Check if it's actually a login page
            is_login = any(kw in body.lower() for kw in [
                'type="password"', "type='password'",
                "signin","login","username","password"
            ])
            if not is_login:
                continue

            info(f"  Login form found: {url}")

            for username, password in DEFAULT_CREDS[:6]:
                post_data = urllib.parse.urlencode({
                    "username": username, "password": password,
                    "user": username, "pass": password,
                    "email": f"{username}@{self.domain}",
                    "log": username, "pwd": password,
                }).encode()

                try:
                    req = urllib.request.Request(url, data=post_data,
                                                  headers=self.headers)
                    req.add_header("Content-Type",
                                   "application/x-www-form-urlencoded")
                    with urllib.request.urlopen(req,
                                                timeout=self.timeout) as r:
                        resp_body = r.read(32768).decode("utf-8",
                                                          errors="ignore")
                        resp_url  = r.url

                    # Check for successful login indicators
                    success_indicators = [
                        "dashboard","logout","welcome","profile",
                        "my account","sign out","log out",
                        "/admin/","/dashboard/","?logged_in",
                    ]
                    failed_indicators = [
                        "invalid","incorrect","wrong","failed",
                        "error","denied","unauthorized",
                    ]

                    is_success = any(s in resp_body.lower()
                                     for s in success_indicators)
                    is_failure = any(f in resp_body.lower()
                                     for f in failed_indicators)

                    if is_success and not is_failure:
                        bugs.append({
                            "type":     "Default Credentials Accepted",
                            "severity": "CRITICAL",
                            "url":      url,
                            "username": username,
                            "password": password,
                            "evidence": f"Login with {username}:{password} succeeded",
                            "detail":   "Default credentials work — immediate account takeover",
                        })
                        bug_found("DEFAULT CREDENTIALS ACCEPTED", "CRITICAL", {
                            "URL":      url,
                            "Username": username,
                            "Password": password,
                            "Redirected to": resp_url,
                            "Impact":   "Full account takeover with default credentials!",
                        })
                        break

                except:
                    pass

        return bugs

    def _check_git_exposure(self):
        """Check for exposed .git repository"""
        bugs = []
        for scheme in ["https","http"]:
            url = f"{scheme}://{self.domain}/.git/HEAD"
            body, status = self._fetch(url)
            if status == 200 and "ref:" in body:
                # Try to download index
                idx_url = f"{scheme}://{self.domain}/.git/index"
                _, idx_status = self._fetch(idx_url)

                bugs.append({
                    "type":     "Git Repository Exposed",
                    "severity": "CRITICAL",
                    "url":      url,
                    "evidence": f".git/HEAD accessible: {body[:50].strip()}",
                    "detail":   "Entire source code potentially downloadable via git",
                })
                bug_found("GIT REPOSITORY EXPOSED", "CRITICAL", {
                    "URL":      url,
                    "HEAD":     body[:50].strip(),
                    "Index":    f"HTTP {idx_status}",
                    "Impact":   "Full source code, secrets, history downloadable!",
                    "Tool":     "Use 'git-dumper' to extract: git-dumper " +
                                f"https://{self.domain}/.git/ output/",
                })
                break

        return bugs

    def run(self):
        section("Credential & Breach Scanner (Files|Git|Defaults|Leaks)")
        all_bugs = []

        # 1. Sensitive files
        file_bugs = self._check_sensitive_files()
        all_bugs.extend(file_bugs)

        # 2. Git exposure
        git_bugs = self._check_git_exposure()
        all_bugs.extend(git_bugs)

        # 3. Default credentials
        cred_bugs = self._test_default_credentials()
        all_bugs.extend(cred_bugs)

        info(f"Credential scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No credential leaks found ✓")
        return {"bugs": all_bugs}
