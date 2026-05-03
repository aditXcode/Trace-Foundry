"""
Trace Foundry V7 - CMS Deep Scanner
WordPress: user enum, plugin/theme enum, version detection
Drupal, Joomla, Laravel, Magento, OpenCart deep checks
"""
import urllib.request
import urllib.error
import urllib.parse
import re
import json
import concurrent.futures
from utils.display import section, ok, warn, info, bug_found, print_section

# WordPress known vulnerable plugin versions
WP_PLUGINS_TO_CHECK = [
    "contact-form-7", "woocommerce", "yoast-seo", "elementor",
    "wordfence", "akismet", "jetpack", "wpforms-lite",
    "all-in-one-wp-security-and-firewall", "wp-file-manager",
    "revslider", "gravityforms", "duplicator", "backup-buddy",
    "w3-total-cache", "wp-super-cache", "advanced-custom-fields",
    "ninja-forms", "mailchimp-for-wp", "wp-fastest-cache",
]

WP_THEMES_TO_CHECK = [
    "twentytwentyfour", "twentytwentythree", "divi", "avada",
    "astra", "oceanwp", "flatsome", "jupiter", "betheme",
]

class CMSScannerModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.cms_detected = None

    def _fetch(self, url, allow_redirect=True):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body    = r.read(65536).decode("utf-8", errors="ignore")
                headers = {k.lower(): v for k, v in r.headers.items()}
                return body, r.status, headers, r.url
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, {}, url
        except:
            return "", 0, {}, url

    # ── CMS Detection ────────────────────────────────────────────────────────
    def _detect_cms(self):
        body, status, headers, _ = self._fetch(f"https://{self.domain}")
        if not body:
            body, status, headers, _ = self._fetch(f"http://{self.domain}")

        cms = None
        if "wp-content" in body or "wp-includes" in body:
            cms = "WordPress"
        elif "Drupal" in body or "/sites/default/" in body:
            cms = "Drupal"
        elif "joomla" in body.lower() or "/components/com_" in body:
            cms = "Joomla"
        elif "laravel" in body.lower() or "_token" in body:
            cms = "Laravel"
        elif "Magento" in body or "mage" in body.lower():
            cms = "Magento"
        elif "PrestaShop" in body:
            cms = "PrestaShop"
        elif "x-powered-by" in headers and "wp" in headers.get("x-powered-by","").lower():
            cms = "WordPress"

        if cms:
            ok(f"CMS Detected: {cms}")
        else:
            info("No common CMS detected")

        self.cms_detected = cms
        return cms, body, headers

    # ── WordPress Deep Scan ─────────────────────────────────────────────────
    def _wp_get_version(self, body):
        patterns = [
            r'<meta name="generator" content="WordPress ([0-9.]+)"',
            r'ver=([0-9.]+)" type="text/css',
            r'wp-includes/css/dashicons\.min\.css\?ver=([0-9.]+)',
        ]
        for pat in patterns:
            m = re.search(pat, body)
            if m:
                return m.group(1)
        return None

    def _wp_author_enum(self):
        """WordPress author enumeration — the technique used on NASA"""
        bugs = []
        info("WordPress Author Enumeration...")
        found_authors = []

        def check_author(i):
            url = f"https://{self.domain}/?author={i}"
            body, status, _, final_url = self._fetch(url)
            if status in (200, 301, 302) and "/author/" in final_url:
                # Extract username from URL
                match = re.search(r'/author/([^/]+)/', final_url)
                username = match.group(1) if match else "unknown"
                # Extract display name from page
                name_match = re.search(r'<title>([^<]+)</title>', body)
                display = name_match.group(1).split("–")[0].strip() if name_match else ""
                return {"id": i, "username": username, "display": display, "url": final_url}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(check_author, i): i for i in range(1, 21)}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_authors.append(result)
                    ok(f"  Author ID {result['id']}: {result['username']} → {result['display']}")

        if found_authors:
            # Check for system accounts
            system_accounts = [a for a in found_authors if any(
                kw in a["username"].lower() for kw in
                ["admin","system","migrate","backup","test","service","api","bot"]
            )]

            severity = "HIGH" if system_accounts else "MEDIUM"
            detail   = f"{len(found_authors)} users enumerated"
            if system_accounts:
                detail += f" including system accounts: {[a['username'] for a in system_accounts]}"

            bugs.append({
                "type":     "WordPress User Enumeration via /?author=",
                "severity": severity,
                "url":      f"https://{self.domain}/?author=1",
                "evidence": detail,
                "authors":  found_authors,
                "detail":   "Internal usernames exposed — enables targeted attacks",
            })
            bug_found("WordPress User Enumeration", severity, {
                "URL":           f"https://{self.domain}/?author=1",
                "Users Found":   str(len(found_authors)),
                "System Accounts": str([a["username"] for a in system_accounts]) if system_accounts else "None",
                "Evidence":      detail,
                "Impact":        "Usernames usable for brute-force or social engineering",
            })

        return bugs, found_authors

    def _wp_plugin_scan(self):
        """Scan for exposed WordPress plugins and their versions"""
        bugs  = []
        found = []
        info(f"Scanning {len(WP_PLUGINS_TO_CHECK)} common plugins...")

        def check_plugin(plugin):
            url = f"https://{self.domain}/wp-content/plugins/{plugin}/readme.txt"
            body, status, _, _ = self._fetch(url)
            if status == 200 and body:
                # Extract version
                ver_match = re.search(r'Stable tag:\s*([0-9.]+)', body, re.I)
                version   = ver_match.group(1) if ver_match else "unknown"
                return {"plugin": plugin, "version": version, "url": url}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(check_plugin, p): p for p in WP_PLUGINS_TO_CHECK}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    ok(f"  Plugin: {result['plugin']} v{result['version']}")
                    bugs.append({
                        "type":     f"WordPress Plugin Exposed: {result['plugin']}",
                        "severity": "LOW",
                        "url":      result["url"],
                        "version":  result["version"],
                        "evidence": f"readme.txt accessible — version {result['version']} exposed",
                        "detail":   "Plugin version disclosure helps attacker find known CVEs",
                    })

        return bugs, found

    def _wp_sensitive_paths(self):
        """Check WordPress-specific sensitive paths"""
        paths = [
            ("/wp-json/wp/v2/users",    "WP REST API User List",   "HIGH"),
            ("/wp-json/",               "WP REST API Exposed",     "LOW"),
            ("/wp-config.php",          "WP Config File",          "CRITICAL"),
            ("/wp-config.php.bak",      "WP Config Backup",        "CRITICAL"),
            ("/wp-content/debug.log",   "WP Debug Log",            "MEDIUM"),
            ("/.wp-cli/config.yml",     "WP-CLI Config",           "MEDIUM"),
            ("/wp-content/uploads/",    "Upload Directory Listing","MEDIUM"),
            ("/wp-cron.php",            "WP Cron Exposed",         "LOW"),
            ("/xmlrpc.php",             "XML-RPC Enabled",         "MEDIUM"),
            ("/wp-admin/install.php",   "WP Install Script",       "HIGH"),
            ("/wp-admin/upgrade.php",   "WP Upgrade Script",       "MEDIUM"),
        ]

        bugs = []
        for path, label, severity in paths:
            url = f"https://{self.domain}{path}"
            body, status, _, _ = self._fetch(url)
            if status in (200, 301, 302):
                if path == "/wp-json/wp/v2/users" and body:
                    try:
                        users = json.loads(body)
                        if isinstance(users, list) and users:
                            usernames = [u.get("slug","?") for u in users[:5]]
                            bug_found(f"WP REST API Exposes {len(users)} Users", severity, {
                                "URL":       url,
                                "Usernames": ", ".join(usernames),
                                "Evidence":  f"{len(users)} users returned without auth",
                                "Impact":    "Full username list without authentication",
                            })
                            bugs.append({
                                "type":     f"WordPress {label}",
                                "severity": severity,
                                "url":      url,
                                "evidence": f"{len(users)} users exposed via REST API",
                            })
                    except:
                        pass
                elif status == 200:
                    bugs.append({
                        "type":     f"WordPress {label}",
                        "severity": severity,
                        "url":      url,
                        "evidence": f"HTTP {status} — accessible without authentication",
                        "detail":   f"{label} publicly accessible",
                    })
                    if severity in ("CRITICAL","HIGH"):
                        bug_found(f"WordPress {label}", severity, {
                            "URL":      url,
                            "Status":   str(status),
                            "Impact":   f"{label} accessible without auth",
                        })

        return bugs

    # ── Drupal Scan ──────────────────────────────────────────────────────────
    def _drupal_scan(self):
        bugs = []
        info("Running Drupal-specific checks...")
        paths = [
            ("/CHANGELOG.txt",          "Drupal Version Disclosure",  "LOW"),
            ("/core/CHANGELOG.txt",     "Drupal Core Version",        "LOW"),
            ("/admin/",                 "Drupal Admin Panel",         "HIGH"),
            ("/user/register",          "Drupal User Registration",   "MEDIUM"),
            ("/user/login",             "Drupal Login Page",          "INFO"),
            ("/?q=admin",               "Drupal Admin via q param",   "MEDIUM"),
            ("/sites/default/files/",   "Drupal Files Directory",     "MEDIUM"),
        ]
        for path, label, severity in paths:
            url = f"https://{self.domain}{path}"
            body, status, _, _ = self._fetch(url)
            if status == 200:
                version = None
                if "CHANGELOG" in path:
                    vm = re.search(r'Drupal ([0-9.]+)', body)
                    version = vm.group(1) if vm else None
                bugs.append({
                    "type":     f"Drupal: {label}",
                    "severity": severity,
                    "url":      url,
                    "evidence": f"HTTP 200{' — Version: '+version if version else ''}",
                })
                if severity in ("CRITICAL","HIGH","MEDIUM"):
                    bug_found(f"Drupal: {label}", severity, {
                        "URL":     url,
                        "Version": version or "Unknown",
                    })
        return bugs

    # ── Joomla Scan ─────────────────────────────────────────────────────────
    def _joomla_scan(self):
        bugs = []
        info("Running Joomla-specific checks...")
        paths = [
            ("/administrator/",             "Joomla Admin Panel",    "HIGH"),
            ("/administrator/index.php",    "Joomla Admin Login",    "HIGH"),
            ("/README.txt",                 "Joomla Version Info",   "LOW"),
            ("/configuration.php.bak",      "Joomla Config Backup",  "CRITICAL"),
            ("/web.config.txt",             "Joomla Web Config",     "MEDIUM"),
            ("/htaccess.txt",               "Joomla htaccess",       "LOW"),
        ]
        for path, label, severity in paths:
            url = f"https://{self.domain}{path}"
            body, status, _, _ = self._fetch(url)
            if status == 200 and body:
                bugs.append({
                    "type":     f"Joomla: {label}",
                    "severity": severity,
                    "url":      url,
                    "evidence": f"HTTP 200 — {label} accessible",
                })
                if severity in ("CRITICAL","HIGH"):
                    bug_found(f"Joomla: {label}", severity, {"URL": url})
        return bugs

    # ── Laravel Scan ─────────────────────────────────────────────────────────
    def _laravel_scan(self):
        bugs = []
        info("Running Laravel-specific checks...")
        paths = [
            ("/.env",                   "Laravel .env File",          "CRITICAL"),
            ("/.env.backup",            "Laravel .env Backup",        "CRITICAL"),
            ("/.env.production",        "Laravel .env Production",    "CRITICAL"),
            ("/telescope",              "Laravel Telescope (Debug)",  "HIGH"),
            ("/telescope/requests",     "Laravel Telescope Requests", "HIGH"),
            ("/horizon",                "Laravel Horizon Dashboard",  "HIGH"),
            ("/api/user",               "Laravel API User Endpoint",  "MEDIUM"),
            ("/storage/logs/laravel.log","Laravel Log File",          "HIGH"),
            ("/phpinfo.php",            "PHP Info Page",              "MEDIUM"),
        ]
        for path, label, severity in paths:
            url = f"https://{self.domain}{path}"
            body, status, _, _ = self._fetch(url)
            if status == 200 and body and len(body) > 10:
                # Extra verify for .env
                if ".env" in path:
                    if not any(kw in body for kw in ["APP_","DB_","SECRET","KEY"]):
                        continue
                bugs.append({
                    "type":     f"Laravel: {label}",
                    "severity": severity,
                    "url":      url,
                    "evidence": f"HTTP 200 — {label} accessible",
                })
                if severity in ("CRITICAL","HIGH"):
                    bug_found(f"Laravel: {label}", severity, {
                        "URL":    url,
                        "Impact": f"{label} exposed to public",
                    })
        return bugs

    def run(self):
        section("CMS Deep Scanner (WordPress|Drupal|Joomla|Laravel|Magento)")
        all_bugs = []

        cms, body, headers = self._detect_cms()

        if cms == "WordPress":
            # Version
            version = self._wp_get_version(body)
            if version:
                ok(f"WordPress version: {version}")
                all_bugs.append({
                    "type":     "WordPress Version Disclosed",
                    "severity": "LOW",
                    "url":      f"https://{self.domain}",
                    "evidence": f"WordPress {version} detected via meta generator tag",
                    "detail":   "Version info helps attacker find known CVEs",
                })

            # Author enum
            author_bugs, authors = self._wp_author_enum()
            all_bugs.extend(author_bugs)

            # Plugin scan
            plugin_bugs, plugins = self._wp_plugin_scan()
            all_bugs.extend(plugin_bugs)

            # Sensitive paths
            path_bugs = self._wp_sensitive_paths()
            all_bugs.extend(path_bugs)

        elif cms == "Drupal":
            all_bugs.extend(self._drupal_scan())

        elif cms == "Joomla":
            all_bugs.extend(self._joomla_scan())

        elif cms == "Laravel":
            all_bugs.extend(self._laravel_scan())

        else:
            # Unknown CMS — run generic checks
            info("Running generic CMS checks...")
            all_bugs.extend(self._laravel_scan())  # .env check works for any

        info(f"CMS scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No CMS-specific issues found ✓")

        return {
            "bugs":         all_bugs,
            "cms_detected": cms,
        }
