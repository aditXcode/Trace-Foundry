"""
Trace Foundry - Common Paths & Sensitive File Checker
Detects exposed endpoints, backup files, config leaks
"""

import urllib.request
import urllib.error
import concurrent.futures
from utils.display import print_section, ok, warn, info

PATHS = [
    # Recon basics
    {"path": "/robots.txt",        "label": "Robots.txt",         "sensitive": False},
    {"path": "/sitemap.xml",       "label": "Sitemap",            "sensitive": False},
    {"path": "/.well-known/security.txt", "label": "Security.txt","sensitive": False},
    {"path": "/humans.txt",        "label": "Humans.txt",         "sensitive": False},

    # Admin panels
    {"path": "/admin",             "label": "Admin Panel",        "sensitive": True},
    {"path": "/administrator",     "label": "Admin Panel",        "sensitive": True},
    {"path": "/admin/login",       "label": "Admin Login",        "sensitive": True},
    {"path": "/wp-admin",          "label": "WordPress Admin",    "sensitive": True},
    {"path": "/phpmyadmin",        "label": "phpMyAdmin",         "sensitive": True},
    {"path": "/cpanel",            "label": "cPanel",             "sensitive": True},
    {"path": "/panel",             "label": "Panel",              "sensitive": True},
    {"path": "/dashboard",         "label": "Dashboard",          "sensitive": True},

    # API endpoints
    {"path": "/api",               "label": "API Root",           "sensitive": False},
    {"path": "/api/v1",            "label": "API v1",             "sensitive": False},
    {"path": "/api/v2",            "label": "API v2",             "sensitive": False},
    {"path": "/swagger",           "label": "Swagger UI",         "sensitive": True},
    {"path": "/swagger-ui.html",   "label": "Swagger UI (HTML)",  "sensitive": True},
    {"path": "/api-docs",          "label": "API Docs",           "sensitive": True},
    {"path": "/openapi.json",      "label": "OpenAPI Spec",       "sensitive": True},
    {"path": "/graphql",           "label": "GraphQL",            "sensitive": True},

    # Config & sensitive files
    {"path": "/.env",              "label": ".env File",          "sensitive": True},
    {"path": "/.env.backup",       "label": ".env Backup",        "sensitive": True},
    {"path": "/.env.local",        "label": ".env Local",         "sensitive": True},
    {"path": "/config.php",        "label": "Config PHP",         "sensitive": True},
    {"path": "/config.json",       "label": "Config JSON",        "sensitive": True},
    {"path": "/wp-config.php",     "label": "WordPress Config",   "sensitive": True},
    {"path": "/database.yml",      "label": "Database Config",    "sensitive": True},
    {"path": "/settings.py",       "label": "Django Settings",    "sensitive": True},

    # Git & dev artifacts
    {"path": "/.git/HEAD",         "label": "Git Repo Exposed",   "sensitive": True},
    {"path": "/.git/config",       "label": "Git Config",         "sensitive": True},
    {"path": "/.svn/entries",      "label": "SVN Exposed",        "sensitive": True},
    {"path": "/.DS_Store",         "label": "DS_Store",           "sensitive": True},

    # Backup files
    {"path": "/backup.zip",        "label": "Backup Archive",     "sensitive": True},
    {"path": "/backup.tar.gz",     "label": "Backup Archive",     "sensitive": True},
    {"path": "/dump.sql",          "label": "SQL Dump",           "sensitive": True},
    {"path": "/db.sql",            "label": "SQL Dump",           "sensitive": True},

    # Debug & info
    {"path": "/phpinfo.php",       "label": "PHP Info",           "sensitive": True},
    {"path": "/info.php",          "label": "PHP Info",           "sensitive": True},
    {"path": "/server-status",     "label": "Apache Status",      "sensitive": True},
    {"path": "/server-info",       "label": "Apache Info",        "sensitive": True},
    {"path": "/.htaccess",         "label": "htaccess",           "sensitive": True},

    # Login pages
    {"path": "/login",             "label": "Login Page",         "sensitive": False},
    {"path": "/signin",            "label": "Sign In",            "sensitive": False},
    {"path": "/register",          "label": "Register",           "sensitive": False},
    {"path": "/forgot-password",   "label": "Forgot Password",    "sensitive": False},
]

class PathModule:
    def __init__(self, domain, timeout=4, threads=20):
        self.domain = domain
        self.timeout = timeout
        self.threads = threads

    def _check_path(self, entry):
        path = entry["path"]
        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.domain}{path}"
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0) Security Research"
                })
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return {
                        "path": path,
                        "url": url,
                        "status": r.status,
                        "label": entry["label"],
                        "sensitive": entry["sensitive"]
                    }
            except urllib.error.HTTPError as e:
                if e.code not in (404, 410):
                    return {
                        "path": path,
                        "url": url,
                        "status": e.code,
                        "label": entry["label"],
                        "sensitive": entry["sensitive"]
                    }
            except:
                pass
        return None

    def run(self):
        print_section("Path & File Discovery")
        info(f"Checking {len(PATHS)} paths...")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check_path, e): e for e in PATHS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    if result["sensitive"]:
                        warn(f"SENSITIVE  [{result['status']}]  {result['label']:30s} → {result['url']}")
                    else:
                        ok(f"Found      [{result['status']}]  {result['label']:30s} → {result['url']}")
                    found.append(result)

        sensitive_count = sum(1 for f in found if f["sensitive"])
        info(f"Paths found  : {len(found)} ({sensitive_count} sensitive)")
        return sorted(found, key=lambda x: x["path"])
