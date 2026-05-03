"""
Trace Foundry - Subdomain Takeover Checker
Checks if discovered subdomains point to unclaimed cloud services
"""

import socket
import urllib.request
import urllib.error
from utils.display import print_section, ok, warn, info, bug_found

# Fingerprints for dangling cloud services
TAKEOVER_SIGNATURES = {
    "GitHub Pages":      ["There isn't a GitHub Pages site here", "For root URLs"],
    "Heroku":            ["No such app", "herokuapp.com", "no app configured"],
    "Netlify":           ["Not Found - Request ID", "netlify"],
    "Vercel":            ["The deployment could not be found", "vercel.app"],
    "AWS S3":            ["NoSuchBucket", "The specified bucket does not exist"],
    "AWS CloudFront":    ["ERROR: The request could not be satisfied"],
    "Fastly":            ["Fastly error: unknown domain"],
    "Ghost":             ["The thing you were looking for is no longer here"],
    "Tumblr":            ["There's nothing here", "Whatever you were looking for doesn't live here"],
    "WordPress.com":     ["Do you want to register"],
    "Shopify":           ["Sorry, this shop is currently unavailable"],
    "Zendesk":           ["Help Center Closed"],
    "Freshdesk":         ["We could not find what you're looking for"],
    "HubSpot":           ["Domain not found", "does not exist in our system"],
    "Unbounce":          ["The requested URL was not found on this server"],
    "Pantheon":          ["The gods are wise", "404 error unknown site"],
    "Azure":             ["404 Web Site not found"],
    "ReadTheDocs":       ["unknown to Read the Docs"],
    "Surge.sh":          ["project not found"],
    "Cargo":             ["If you're moving your domain away from Cargo"],
    "Webflow":           ["The page you are looking for doesn't exist or has been moved"],
    "Intercom":          ["This page is reserved for artistic dogs"],
    "Cargocollective":   ["404 Not Found"],
    "Statuspage.io":     ["You are being redirected"],
}

# CNAME patterns that indicate cloud services
CLOUD_CNAME_PATTERNS = {
    "github.io":         "GitHub Pages",
    "herokuapp.com":     "Heroku",
    "netlify.app":       "Netlify",
    "vercel.app":        "Vercel",
    "s3.amazonaws.com":  "AWS S3",
    "cloudfront.net":    "AWS CloudFront",
    "azurewebsites.net": "Azure Web Apps",
    "azurestaticapps.net": "Azure Static",
    "ghostio":           "Ghost",
    "tumblr.com":        "Tumblr",
    "wordpress.com":     "WordPress.com",
    "myshopify.com":     "Shopify",
    "zendesk.com":       "Zendesk",
    "freshdesk.com":     "Freshdesk",
    "hubspot.com":       "HubSpot",
    "surge.sh":          "Surge.sh",
    "pantheonsite.io":   "Pantheon",
    "webflow.io":        "Webflow",
    "readthedocs.io":    "ReadTheDocs",
}

class TakeoverModule:
    def __init__(self, domain, subdomains, timeout=5):
        self.domain = domain
        self.subdomains = subdomains  # list from subdomain enum
        self.timeout = timeout

    def _get_cname(self, host):
        import subprocess
        try:
            result = subprocess.run(
                ["nslookup", "-type=CNAME", host],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if "canonical name" in line.lower():
                    return line.split("=")[-1].strip().rstrip(".")
        except:
            pass
        return None

    def _check_response(self, url):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0)"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(4096).decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            try: body = e.read(4096).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def run(self):
        print_section("Subdomain Takeover Checker")
        bugs = []

        targets = [s["subdomain"] for s in self.subdomains]
        if not targets:
            warn("No subdomains to check — run subdomain enumeration first")
            return bugs

        info(f"Checking {len(targets)} subdomains for takeover...")

        for subdomain in targets:
            # Step 1: Check CNAME
            cname = self._get_cname(subdomain)
            if cname:
                for pattern, service in CLOUD_CNAME_PATTERNS.items():
                    if pattern in cname:
                        info(f"Cloud CNAME: {subdomain} → {cname} ({service})")
                        # Step 2: Check if service is unclaimed
                        body, status = self._check_response(f"https://{subdomain}")
                        if not body:
                            body, status = self._check_response(f"http://{subdomain}")

                        for svc_name, fingerprints in TAKEOVER_SIGNATURES.items():
                            if service in svc_name or svc_name in service:
                                for fp in fingerprints:
                                    if fp.lower() in body.lower():
                                        bug_found("SUBDOMAIN TAKEOVER POSSIBLE",
                                            f"Subdomain : {subdomain}\n"
                                            f"    CNAME     : {cname}\n"
                                            f"    Service   : {service}\n"
                                            f"    Fingerprint: '{fp}'\n"
                                            f"    → This subdomain points to an unclaimed {service} resource!\n"
                                            f"    → Register the service to claim this subdomain!")
                                        bugs.append({
                                            "type": "Subdomain Takeover",
                                            "severity": "HIGH",
                                            "subdomain": subdomain,
                                            "cname": cname,
                                            "service": service,
                                            "fingerprint": fp,
                                        })
                                        break
                        break

            # Step 3: NXDOMAIN check — dangling DNS
            try:
                socket.gethostbyname(subdomain)
            except socket.gaierror:
                info(f"NXDOMAIN: {subdomain} — DNS record exists but resolves to nothing (possible dangling)")

        if not bugs:
            ok("No subdomain takeover vulnerabilities found ✓")
        return bugs
