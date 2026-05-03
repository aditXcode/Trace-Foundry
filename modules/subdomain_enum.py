"""
Trace Foundry - Subdomain Enumeration Module
Brute-force subdomains using wordlist + threading
"""

import socket
import concurrent.futures
import os
from utils.display import print_section, ok, warn, info

class SubdomainModule:
    def __init__(self, domain, wordlist_file=None, threads=30, timeout=3):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist = self._load_wordlist(wordlist_file)

    def _load_wordlist(self, path):
        # Try custom wordlist first
        if path and os.path.exists(path):
            with open(path) as f:
                return [line.strip() for line in f if line.strip()]

        # Try built-in wordlist
        builtin = os.path.join(os.path.dirname(__file__), "../wordlists/subdomains.txt")
        if os.path.exists(builtin):
            with open(builtin) as f:
                return [line.strip() for line in f if line.strip()]

        # Fallback to default list
        return [
            "www","mail","ftp","admin","api","dev","staging","test","portal",
            "vpn","remote","blog","shop","app","m","mobile","cdn","static",
            "assets","media","img","images","login","auth","sso","id","account",
            "dashboard","panel","cpanel","webmail","smtp","pop","imap","ns1",
            "ns2","mx","beta","old","new","secure","internal","intranet","git",
            "gitlab","github","jira","confluence","jenkins","monitor","status",
            "help","support","docs","wiki","forum","community","store","payment",
            "pay","checkout","cart","billing","invoice","api2","v1","v2","v3",
            "sandbox","uat","prod","production","db","database","sql","mysql",
            "redis","cache","search","elastic","kibana","grafana","prometheus",
            "ci","cd","deploy","build","release","preview","demo","trial","poc",
            "cloud","aws","azure","gcp","k8s","kubernetes","docker","registry"
        ]

    def _check(self, sub):
        target = f"{sub}.{self.domain}"
        try:
            socket.setdefaulttimeout(self.timeout)
            ip = socket.gethostbyname(target)
            return {"subdomain": target, "ip": ip}
        except:
            return None

    def run(self):
        print_section("Subdomain Enumeration")
        info(f"Wordlist size : {len(self.wordlist)} entries")
        info(f"Threads       : {self.threads}")

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._check, sub): sub for sub in self.wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    ok(f"Found → {result['subdomain']}  ({result['ip']})")
                    found.append(result)

        info(f"Total found   : {len(found)}")
        if not found:
            warn("No subdomains discovered")
        return sorted(found, key=lambda x: x["subdomain"])
