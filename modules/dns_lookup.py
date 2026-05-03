"""
Trace Foundry - DNS Lookup Module
Resolves DNS records: A, MX, NS, TXT, CNAME
"""

import socket
import subprocess
from utils.display import print_section, ok, warn, info

class DNSModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def run(self):
        print_section("DNS Lookup")
        results = {}

        # A record
        try:
            ip = socket.gethostbyname(self.domain)
            ok(f"A Record     : {ip}")
            results["ip"] = ip
        except socket.gaierror as e:
            warn(f"A record failed: {e}")
            results["ip"] = None

        # All IPs (round-robin)
        try:
            _, aliases, ips = socket.gethostbyname_ex(self.domain)
            results["all_ips"] = ips
            results["aliases"] = aliases
            if len(ips) > 1:
                ok(f"All IPs      : {', '.join(ips)}")
            if aliases:
                ok(f"CNAME/Alias  : {', '.join(aliases)}")
        except:
            pass

        # MX records via nslookup fallback
        mx = self._get_mx()
        if mx:
            results["mx"] = mx
            for m in mx:
                ok(f"MX Record    : {m}")

        # TXT records (useful for finding SPF, DKIM, verification tokens)
        txt = self._get_txt()
        if txt:
            results["txt"] = txt
            for t in txt[:5]:  # show first 5
                ok(f"TXT Record   : {t[:80]}")

        # Reverse DNS
        if results.get("ip"):
            try:
                rdns = socket.gethostbyaddr(results["ip"])[0]
                ok(f"Reverse DNS  : {rdns}")
                results["reverse_dns"] = rdns
            except:
                results["reverse_dns"] = None

        return results

    def _get_mx(self):
        """Get MX records using socket/nslookup"""
        try:
            result = subprocess.run(
                ["nslookup", "-type=MX", self.domain],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.splitlines()
            mx = []
            for line in lines:
                if "mail exchanger" in line.lower():
                    parts = line.split("=")
                    if len(parts) > 1:
                        mx.append(parts[1].strip())
            return mx
        except:
            return []

    def _get_txt(self):
        """Get TXT records"""
        try:
            result = subprocess.run(
                ["nslookup", "-type=TXT", self.domain],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.splitlines()
            txt = []
            for line in lines:
                if '"' in line:
                    txt.append(line.strip().strip('"'))
            return txt
        except:
            return []
