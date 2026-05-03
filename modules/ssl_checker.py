"""
Trace Foundry - SSL/TLS Checker Module
Audits SSL certificate validity, expiry, weak ciphers, and misconfigurations
"""

import ssl
import socket
import datetime
from utils.display import print_section, ok, warn, info, bug_found

class SSLModule:
    def __init__(self, domain, timeout=5):
        self.domain = domain
        self.timeout = timeout

    def run(self):
        print_section("SSL/TLS Certificate Audit")
        result = {"bugs": []}

        try:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.create_connection((self.domain, 443), timeout=self.timeout),
                server_hostname=self.domain
            )
            cert = conn.getpeercert()
            cipher = conn.cipher()
            protocol = conn.version()
            conn.close()

            # ── Basic Info ──
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            cn      = subject.get("commonName", "N/A")
            org     = issuer.get("organizationName", "N/A")

            ok(f"Common Name  : {cn}")
            ok(f"Issuer       : {org}")
            ok(f"Protocol     : {protocol}")
            ok(f"Cipher Suite : {cipher[0]}")

            result.update({
                "common_name": cn,
                "issuer": org,
                "protocol": protocol,
                "cipher": cipher[0],
            })

            # ── Expiry Check ──
            raw_expiry = cert.get("notAfter", "")
            expiry = ssl.cert_time_to_seconds(raw_expiry)
            expiry_dt = datetime.datetime.fromtimestamp(expiry)
            days_left = (expiry_dt - datetime.datetime.now()).days

            result["expiry"] = str(expiry_dt.date())
            result["days_left"] = days_left

            if days_left < 0:
                bug_found("CERT EXPIRED", f"Certificate expired {abs(days_left)} days ago!")
                result["bugs"].append({"type": "Expired Certificate", "severity": "CRITICAL",
                    "detail": f"Expired {abs(days_left)} days ago"})
            elif days_left < 14:
                bug_found("CERT EXPIRING SOON", f"Only {days_left} days left!")
                result["bugs"].append({"type": "Certificate Expiring Soon", "severity": "HIGH",
                    "detail": f"{days_left} days remaining"})
            else:
                ok(f"Expiry       : {expiry_dt.date()} ({days_left} days left) ✓")

            # ── Weak Protocol ──
            weak_protos = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
            if any(w in protocol for w in weak_protos):
                bug_found("WEAK TLS PROTOCOL", f"Server uses {protocol} — deprecated and vulnerable!")
                result["bugs"].append({"type": "Weak TLS Protocol", "severity": "HIGH",
                    "detail": f"Protocol: {protocol}"})
            else:
                ok(f"Protocol OK  : {protocol} is modern ✓")

            # ── Weak Cipher ──
            weak_ciphers = ["RC4","DES","3DES","MD5","NULL","EXPORT","anon"]
            for w in weak_ciphers:
                if w in cipher[0]:
                    bug_found("WEAK CIPHER SUITE", f"{cipher[0]} contains weak component: {w}")
                    result["bugs"].append({"type": "Weak Cipher Suite", "severity": "MEDIUM",
                        "detail": cipher[0]})
                    break
            else:
                ok(f"Cipher OK    : No weak ciphers detected ✓")

            # ── Wildcard / SAN ──
            san = cert.get("subjectAltName", [])
            san_list = [v for t, v in san if t == "DNS"]
            result["san"] = san_list
            wildcards = [s for s in san_list if s.startswith("*")]
            if wildcards:
                info(f"Wildcard SANs: {', '.join(wildcards)}")
                result["wildcards"] = wildcards

            # ── Self-Signed ──
            if subject == issuer:
                bug_found("SELF-SIGNED CERTIFICATE", "Certificate is self-signed — not trusted by browsers!")
                result["bugs"].append({"type": "Self-Signed Certificate", "severity": "MEDIUM",
                    "detail": "Self-signed cert detected"})

        except ssl.SSLCertVerificationError as e:
            bug_found("SSL VERIFICATION FAILED", str(e))
            result["bugs"].append({"type": "SSL Verification Failed", "severity": "HIGH", "detail": str(e)})
        except ssl.SSLError as e:
            bug_found("SSL ERROR", str(e))
            result["bugs"].append({"type": "SSL Error", "severity": "MEDIUM", "detail": str(e)})
        except ConnectionRefusedError:
            warn("Port 443 not open — HTTPS not available")
            result["bugs"].append({"type": "No HTTPS", "severity": "MEDIUM",
                "detail": "Port 443 refused — site may not support HTTPS"})
        except Exception as e:
            warn(f"SSL check error: {e}")

        if not result["bugs"]:
            ok("SSL/TLS looks solid — no obvious issues found ✓")
        return result
