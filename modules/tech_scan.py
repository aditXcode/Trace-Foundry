"""
Trace Foundry V3 - Technology & Language Deep Scanner
Detects PHP, Python, Java, Node.js, Ruby, .NET, CMS, Frameworks
and scans for language-specific vulnerabilities
"""

import urllib.request
import urllib.error
import re
import socket
from utils.display import print_section, ok, warn, info, bug_found

# ── Technology Fingerprints ──────────────────────────────────────────────────
TECH_FINGERPRINTS = {
    # Backend Languages
    "PHP": {
        "headers":  ["x-powered-by:php", "server:php"],
        "paths":    ["/index.php", "/wp-login.php", "/config.php", "/info.php"],
        "cookies":  ["phpsessid"],
        "body":     ["<?php", "Fatal error:", "Parse error:", "Warning: include"],
        "extensions": [".php", ".phtml", ".php3", ".php5"],
    },
    "Python / Django": {
        "headers":  ["x-powered-by:django", "server:waitress", "server:gunicorn"],
        "paths":    ["/admin/", "/api/", "/static/admin/"],
        "cookies":  ["csrftoken", "sessionid", "django"],
        "body":     ["django", "DisallowedHost", "CSRF verification failed"],
        "extensions": [".py"],
    },
    "Python / Flask": {
        "headers":  ["server:werkzeug", "x-powered-by:flask"],
        "paths":    ["/api/", "/_debug_toolbar/"],
        "cookies":  ["session", "flask"],
        "body":     ["werkzeug", "Traceback (most recent call last)", "Flask"],
        "extensions": [".py"],
    },
    "Node.js / Express": {
        "headers":  ["x-powered-by:express", "server:node"],
        "paths":    ["/api/", "/graphql"],
        "cookies":  ["connect.sid", "express:sess"],
        "body":     ["Cannot GET", "SyntaxError:", "ReferenceError:"],
        "extensions": [".js", ".mjs"],
    },
    "Java / Spring": {
        "headers":  ["x-powered-by:servlet", "server:tomcat", "server:jetty", "server:jboss"],
        "paths":    ["/actuator", "/actuator/env", "/actuator/health",
                     "/actuator/mappings", "/swagger-ui.html", "/WEB-INF/"],
        "cookies":  ["jsessionid"],
        "body":     ["java.lang.", "org.springframework", "javax.servlet"],
        "extensions": [".jsp", ".jsf", ".do", ".action"],
    },
    "Ruby on Rails": {
        "headers":  ["x-runtime", "x-powered-by:phusion passenger", "server:passenger"],
        "paths":    ["/rails/info", "/rails/mailers"],
        "cookies":  ["_session_id", "_rails_session"],
        "body":     ["ActionController::", "ActiveRecord::", "Ruby on Rails"],
        "extensions": [".rb", ".erb"],
    },
    ".NET / ASP.NET": {
        "headers":  ["x-powered-by:asp.net", "x-aspnet-version", "server:microsoft-iis"],
        "paths":    ["/web.config", "/elmah.axd", "/trace.axd", "/ScriptResource.axd"],
        "cookies":  ["asp.net_sessionid", ".aspxauth", "__requestverificationtoken"],
        "body":     ["ASP.NET", "__VIEWSTATE", "__EVENTVALIDATION", "Microsoft.CSharp"],
        "extensions": [".aspx", ".asp", ".ashx", ".asmx", ".axd"],
    },
    "WordPress": {
        "headers":  [],
        "paths":    ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-json/wp/v2/users"],
        "cookies":  ["wordpress_", "wp-settings"],
        "body":     ["wp-content", "wp-includes", "WordPress"],
        "extensions": [".php"],
    },
    "Laravel": {
        "headers":  ["x-powered-by:php"],
        "paths":    ["/.env", "/api/user", "/telescope"],
        "cookies":  ["laravel_session", "xsrf-token"],
        "body":     ["laravel", "Illuminate\\", "SQLSTATE"],
        "extensions": [".php"],
    },
    "React / Next.js": {
        "headers":  ["x-powered-by:next.js"],
        "paths":    ["/_next/static/", "/_next/data/"],
        "cookies":  [],
        "body":     ["__NEXT_DATA__", "next/dist", "_next/static"],
        "extensions": [".jsx", ".tsx", ".js"],
    },
    "Vue.js / Nuxt": {
        "headers":  ["x-powered-by:nuxt"],
        "paths":    ["/_nuxt/", "/nuxt/"],
        "cookies":  [],
        "body":     ["__nuxt", "__vue", "vue-router"],
        "extensions": [".vue", ".js"],
    },
    "Go / Golang": {
        "headers":  ["server:go", "x-powered-by:go"],
        "paths":    ["/debug/pprof/", "/debug/vars"],
        "cookies":  [],
        "body":     ["gorilla/mux", "gin-gonic"],
        "extensions": [".go"],
    },
    "Nginx": {
        "headers":  ["server:nginx"],
        "paths":    [],
        "cookies":  [],
        "body":     ["nginx", "Welcome to nginx"],
        "extensions": [],
    },
    "Apache": {
        "headers":  ["server:apache"],
        "paths":    ["/server-status", "/server-info"],
        "cookies":  [],
        "body":     ["Apache", "It works!"],
        "extensions": [],
    },
}

# ── Language-Specific Vulnerability Checks ───────────────────────────────────
LANG_VULN_CHECKS = {
    "PHP": [
        {
            "name": "PHP Error Disclosure",
            "paths": ["/index.php?debug=1", "/?XDEBUG_SESSION_START=1",
                      "/index.php?id=1'", "/?page=../etc/passwd"],
            "body_patterns": ["Fatal error", "Parse error", "Warning:", "Notice:",
                              "mysql_fetch", "on line", "stack trace"],
            "severity": "MEDIUM",
            "detail": "PHP error messages exposed — reveals file paths and code structure",
        },
        {
            "name": "PHP LFI (Local File Inclusion)",
            "paths": ["/?page=../etc/passwd", "/?file=../../../etc/passwd",
                      "/?include=../etc/passwd", "/?path=../etc/passwd"],
            "body_patterns": ["root:x:", "bin:x:", "daemon:x:", "/bin/bash"],
            "severity": "CRITICAL",
            "detail": "Local File Inclusion detected — attacker can read server files!",
        },
        {
            "name": "phpMyAdmin Exposed",
            "paths": ["/phpmyadmin", "/pma", "/phpMyAdmin", "/phpmyadmin/index.php"],
            "body_patterns": ["phpMyAdmin", "pma_username", "Welcome to phpMyAdmin"],
            "severity": "HIGH",
            "detail": "phpMyAdmin panel accessible — direct DB access risk!",
        },
        {
            "name": "PHP Info Exposed",
            "paths": ["/phpinfo.php", "/info.php", "/php_info.php", "/?phpinfo=1"],
            "body_patterns": ["PHP Version", "phpinfo()", "PHP License"],
            "severity": "MEDIUM",
            "detail": "phpinfo() page exposed — reveals full server configuration!",
        },
    ],
    "Python / Django": [
        {
            "name": "Django Debug Mode ON",
            "paths": ["/", "/?debug=1", "/nonexistent-page-xyz"],
            "body_patterns": ["DEBUG = True", "You're seeing this error because you have",
                              "Django Version", "Exception Value:", "Traceback"],
            "severity": "HIGH",
            "detail": "Django DEBUG=True in production — full stack trace exposed to public!",
        },
        {
            "name": "Django Admin Exposed",
            "paths": ["/admin/", "/admin/login/"],
            "body_patterns": ["Django administration", "Log in | Django site admin"],
            "severity": "MEDIUM",
            "detail": "Django admin panel publicly accessible!",
        },
        {
            "name": "Django Secret Key Exposed",
            "paths": ["/.env", "/settings.py", "/config/settings.py"],
            "body_patterns": ["SECRET_KEY", "DJANGO_SECRET", "django-insecure"],
            "severity": "CRITICAL",
            "detail": "Django SECRET_KEY found — attacker can forge session cookies!",
        },
    ],
    "Python / Flask": [
        {
            "name": "Flask Debug Mode / Werkzeug Console",
            "paths": ["/console", "/?__debugger__=yes", "/_debug_toolbar/"],
            "body_patterns": ["Werkzeug Debugger", "Interactive Console",
                              "WERKZEUG_DEBUG_PIN", "Traceback (most recent call last)"],
            "severity": "CRITICAL",
            "detail": "Flask/Werkzeug debugger ON — attacker gets Python console on server!",
        },
    ],
    "Java / Spring": [
        {
            "name": "Spring Actuator Exposed",
            "paths": ["/actuator", "/actuator/env", "/actuator/health",
                      "/actuator/mappings", "/actuator/dump", "/actuator/heapdump",
                      "/actuator/logfile", "/actuator/trace", "/actuator/beans"],
            "body_patterns": ["actuator", "\"status\":\"UP\"", "systemProperties",
                              "applicationConfig", "endpoints"],
            "severity": "HIGH",
            "detail": "Spring Boot Actuator exposed — leaks env vars, configs, heap dump!",
        },
        {
            "name": "Java Stack Trace Exposed",
            "paths": ["/?id=1'", "/api/test", "/nonexistent"],
            "body_patterns": ["java.lang.NullPointerException", "at org.springframework",
                              "java.sql.SQLException", "Caused by:"],
            "severity": "MEDIUM",
            "detail": "Java stack traces visible — reveals internal code structure!",
        },
        {
            "name": "JSP/Servlet Error Pages",
            "paths": ["/WEB-INF/web.xml", "/WEB-INF/classes/", "/META-INF/"],
            "body_patterns": ["web-app", "<servlet>", "WEB-INF"],
            "severity": "HIGH",
            "detail": "WEB-INF directory accessible — Java config files exposed!",
        },
    ],
    ".NET / ASP.NET": [
        {
            "name": "ASP.NET Error Disclosure",
            "paths": ["/trace.axd", "/elmah.axd", "/ScriptResource.axd?d=error"],
            "body_patterns": ["Server Error in", "ASP.NET is configured",
                              "Stack Trace:", "Source Error:", "Version Information:"],
            "severity": "MEDIUM",
            "detail": "ASP.NET detailed error pages exposed — reveals server info!",
        },
        {
            "name": "Web.config Exposed",
            "paths": ["/web.config", "/Web.config", "/app.config"],
            "body_patterns": ["<configuration>", "connectionStrings", "appSettings",
                              "machineKey", "decryptionKey"],
            "severity": "CRITICAL",
            "detail": "web.config accessible — may contain DB passwords and crypto keys!",
        },
        {
            "name": "ELMAH Log Viewer Exposed",
            "paths": ["/elmah.axd", "/admin/elmah.axd", "/errors/elmah.axd"],
            "body_patterns": ["Error Log for", "ELMAH", "All Exceptions"],
            "severity": "HIGH",
            "detail": "ELMAH error log viewer exposed — full exception logs with sensitive data!",
        },
    ],
    "Ruby on Rails": [
        {
            "name": "Rails Debug Info Exposed",
            "paths": ["/rails/info/properties", "/rails/info/routes"],
            "body_patterns": ["Rails version", "Ruby version", "RubyGems version"],
            "severity": "MEDIUM",
            "detail": "Rails debug endpoint accessible — exposes framework and Ruby versions!",
        },
    ],
    "WordPress": [
        {
            "name": "WordPress User Enumeration",
            "paths": ["/wp-json/wp/v2/users", "/?author=1", "/?author=2"],
            "body_patterns": ["\"slug\":", "\"name\":", "\"link\":", "author"],
            "severity": "MEDIUM",
            "detail": "WordPress user list exposed via REST API — enables targeted attacks!",
        },
        {
            "name": "WordPress xmlrpc.php Enabled",
            "paths": ["/xmlrpc.php"],
            "body_patterns": ["XML-RPC server accepts POST requests only",
                              "xmlrpc", "methodCall"],
            "severity": "MEDIUM",
            "detail": "xmlrpc.php enabled — can be abused for brute-force and DDoS amplification!",
        },
        {
            "name": "WordPress Readme/Version Exposed",
            "paths": ["/readme.html", "/license.txt", "/wp-includes/version.php"],
            "body_patterns": ["WordPress", "Version", "Semantic Versioning"],
            "severity": "LOW",
            "detail": "WordPress version number exposed — helps attackers find known CVEs!",
        },
    ],
    "Node.js / Express": [
        {
            "name": "Express Stack Trace",
            "paths": ["/api/undefined", "/?__proto__[x]=1", "/api/test?id=undefined"],
            "body_patterns": ["Cannot GET", "TypeError:", "ReferenceError:",
                              "at Object.<anonymous>", "node_modules"],
            "severity": "MEDIUM",
            "detail": "Node.js/Express error stack trace visible — reveals file paths!",
        },
    ],
    "Go / Golang": [
        {
            "name": "Go pprof Debug Exposed",
            "paths": ["/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/goroutine"],
            "body_patterns": ["goroutine", "heap profile", "Types of profiles"],
            "severity": "HIGH",
            "detail": "Go pprof profiling endpoint exposed — memory/goroutine info leaked!",
        },
    ],
}

# ── HTML/CSS/JS Static Issues ─────────────────────────────────────────────────
STATIC_CHECKS = {
    "HTML Comment Leak": {
        "patterns": [
            r"<!--.*?(password|secret|key|token|api|todo|fixme|hack|bug|debug|test|admin|internal).*?-->",
            r"<!--\s*[A-Za-z0-9+/]{20,}={0,2}\s*-->",  # base64 in comments
        ],
        "severity": "LOW",
        "detail": "Sensitive info found in HTML comments — visible in page source!",
    },
    "Exposed Internal Path in HTML": {
        "patterns": [
            r'(?:src|href|action)=["\'](?:/var/|/etc/|/home/|C:\\|D:\\|/root/)',
            r'value=["\'][A-Za-z]:\\\\[^"\']+["\']',
        ],
        "severity": "LOW",
        "detail": "Server file paths exposed in HTML — reveals directory structure!",
    },
    "Inline Credential in HTML": {
        "patterns": [
            r'(?:password|passwd|secret|token|api_key)\s*=\s*["\'][^"\']{4,}["\']',
            r'data-(?:key|token|secret|password)=["\'][^"\']{6,}["\']',
        ],
        "severity": "HIGH",
        "detail": "Credentials found hardcoded in HTML — visible to anyone who views source!",
    },
}


class TechScanModule:
    def __init__(self, domain, timeout=5):
        self.domain  = domain
        self.timeout = timeout
        self.detected_techs = []

    def _fetch(self, url, return_headers=False):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TraceFoundry/3.0) Security Research"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body    = r.read(32768).decode("utf-8", errors="ignore")
                headers = {k.lower(): v.lower() for k, v in r.headers.items()}
                cookies = r.headers.get("Set-Cookie", "").lower()
                return body, headers, cookies, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(8192).decode("utf-8", errors="ignore")
            except: body = ""
            headers = {k.lower(): v.lower() for k, v in e.headers.items()}
            cookies = e.headers.get("Set-Cookie","").lower()
            return body, headers, cookies, e.code
        except:
            return "", {}, "", 0

    def _detect_technologies(self):
        print_section("Technology & Language Detection")
        detected = []

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.domain}"
            body, headers, cookies, status = self._fetch(url)
            if not body and status == 0:
                continue

            header_str = str(headers)

            for tech, sigs in TECH_FINGERPRINTS.items():
                score = 0
                evidence = []

                for h in sigs["headers"]:
                    parts = h.split(":")
                    hname, hval = parts[0], parts[1] if len(parts) > 1 else ""
                    if hname in headers and (not hval or hval in headers.get(hname,"")):
                        score += 3
                        evidence.append(f"header:{hname}")

                for c in sigs["cookies"]:
                    if c in cookies:
                        score += 2
                        evidence.append(f"cookie:{c}")

                for b in sigs["body"]:
                    if b.lower() in body.lower():
                        score += 2
                        evidence.append(f"body:{b[:30]}")

                if score >= 2:
                    ok(f"Detected     : {tech:25s} (confidence: {'HIGH' if score>=6 else 'MEDIUM' if score>=3 else 'LOW'})")
                    for ev in evidence[:3]:
                        info(f"  Evidence   : {ev}")
                    detected.append({"tech": tech, "score": score, "evidence": evidence})

            break  # use first working scheme

        return detected

    def _check_paths(self, vuln_name, paths, body_patterns, severity):
        for path in paths:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{self.domain}{path}"
                body, headers, cookies, status = self._fetch(url)
                if status in (200, 500, 403) and body:
                    for pattern in body_patterns:
                        if pattern.lower() in body.lower():
                            return url, body[:200], status
                break
        return None, None, None

    def _scan_language_vulns(self):
        print_section("Language-Specific Vulnerability Scan")
        bugs = []

        techs_to_scan = [t["tech"] for t in self.detected_techs]
        # Always scan WordPress and PHP checks regardless
        if not any("PHP" in t for t in techs_to_scan):
            techs_to_scan.append("PHP")
        if not any("Java" in t for t in techs_to_scan):
            techs_to_scan.append("Java / Spring")

        for tech in techs_to_scan:
            checks = LANG_VULN_CHECKS.get(tech, [])
            if not checks:
                continue

            info(f"Scanning {tech} vulnerabilities ({len(checks)} checks)...")

            for check in checks:
                url, snippet, status = self._check_paths(
                    check["name"], check["paths"],
                    check["body_patterns"], check["severity"]
                )
                if url:
                    bug_found(
                        f"[{check['severity']}] {check['name']}",
                        f"URL      : {url}\n"
                        f"Status   : {status}\n"
                        f"Tech     : {tech}\n"
                        f"Detail   : {check['detail']}\n"
                        f"Snippet  : {snippet[:80] if snippet else 'N/A'}"
                    )
                    bugs.append({
                        "type":     check["name"],
                        "severity": check["severity"],
                        "tech":     tech,
                        "url":      url,
                        "detail":   check["detail"],
                        "snippet":  snippet[:100] if snippet else "",
                    })

        return bugs

    def _scan_static_issues(self):
        print_section("HTML/CSS/JS Static Analysis")
        bugs = []

        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.domain}"
            body, headers, cookies, status = self._fetch(url)
            if not body:
                continue

            for check_name, check in STATIC_CHECKS.items():
                for pattern in check["patterns"]:
                    matches = re.findall(pattern, body, re.IGNORECASE | re.DOTALL)
                    for match in matches[:3]:
                        snippet = str(match)[:100].strip()
                        bug_found(
                            f"[{check['severity']}] {check_name}",
                            f"URL      : {url}\n"
                            f"Detail   : {check['detail']}\n"
                            f"Found    : {snippet}"
                        )
                        bugs.append({
                            "type":     check_name,
                            "severity": check["severity"],
                            "url":      url,
                            "detail":   check["detail"],
                            "found":    snippet,
                        })
            break

        if not bugs:
            ok("No static HTML/JS credential leaks found ✓")
        return bugs

    def run(self):
        result = {"bugs": [], "detected_techs": [], "static_bugs": []}

        self.detected_techs = self._detect_technologies()
        result["detected_techs"] = self.detected_techs

        if not self.detected_techs:
            warn("Could not fingerprint technology stack")
        else:
            info(f"Technologies : {', '.join(t['tech'] for t in self.detected_techs)}")

        lang_bugs   = self._scan_language_vulns()
        static_bugs = self._scan_static_issues()

        result["bugs"]        = lang_bugs + static_bugs
        result["static_bugs"] = static_bugs

        info(f"Tech bugs found : {len(lang_bugs)}")
        info(f"Static bugs     : {len(static_bugs)}")
        return result
