"""
Trace Foundry - Email Harvester Module
Finds emails exposed in robots.txt, security.txt, and page source
"""

import urllib.request
import urllib.error
import re
from utils.display import print_section, ok, warn, info

class EmailModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout
        self.found = set()

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (TraceFoundry/1.0) Security Research"
            })
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read().decode("utf-8", errors="ignore")
        except:
            return ""

    def _extract_emails(self, text):
        pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        return set(re.findall(pattern, text))

    def run(self):
        print_section("Email Harvester")
        results = []

        sources = [
            f"https://{self.domain}",
            f"https://{self.domain}/robots.txt",
            f"https://{self.domain}/.well-known/security.txt",
            f"https://{self.domain}/security.txt",
            f"https://{self.domain}/contact",
            f"https://{self.domain}/about",
            f"https://{self.domain}/team",
        ]

        for url in sources:
            content = self._fetch(url)
            if content:
                emails = self._extract_emails(content)
                for email in emails:
                    # Filter out common false positives
                    skip = ["example.com", "sentry.io", "jquery", "schema.org",
                            "w3.org", "png", "jpg", "gif", "svg"]
                    if any(s in email.lower() for s in skip):
                        continue
                    if email not in self.found:
                        self.found.add(email)
                        ok(f"Email found  : {email}  (from {url})")
                        results.append({"email": email, "source": url})

        if not results:
            warn("No emails found in public pages")
        else:
            info(f"Total emails : {len(results)}")

        return results
