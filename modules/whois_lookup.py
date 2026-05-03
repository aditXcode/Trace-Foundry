"""
Trace Foundry - WHOIS Lookup Module
Gets domain registration info via whois command
"""

import subprocess
import re
from utils.display import print_section, ok, warn, info

class WhoisModule:
    def __init__(self, domain):
        self.domain = domain

    def run(self):
        print_section("WHOIS Lookup")
        result = {}

        try:
            out = subprocess.run(
                ["whois", self.domain],
                capture_output=True, text=True, timeout=10
            ).stdout

            fields = {
                "registrar":        r"Registrar:\s*(.+)",
                "registered":       r"Creation Date:\s*(.+)",
                "expires":          r"Registry Expiry Date:\s*(.+)",
                "updated":          r"Updated Date:\s*(.+)",
                "registrant_org":   r"Registrant Organization:\s*(.+)",
                "registrant_email": r"Registrant Email:\s*(.+)",
                "admin_email":      r"Admin Email:\s*(.+)",
                "tech_email":       r"Tech Email:\s*(.+)",
                "name_servers":     r"Name Server:\s*(.+)",
                "status":           r"Domain Status:\s*(.+)",
                "dnssec":           r"DNSSEC:\s*(.+)",
            }

            ns_list = []
            for key, pattern in fields.items():
                matches = re.findall(pattern, out, re.IGNORECASE)
                if matches:
                    if key == "name_servers":
                        ns_list = [m.strip().lower() for m in matches]
                        result[key] = ns_list
                        ok(f"Name Servers : {', '.join(ns_list[:4])}")
                    else:
                        val = matches[0].strip()
                        result[key] = val
                        label = key.replace("_", " ").title()
                        ok(f"{label:20s}: {val[:70]}")

            # Privacy check
            if "registrantprivacy" in out.lower() or "redacted" in out.lower():
                info("Registrant info is privacy-protected / redacted")
                result["privacy_protected"] = True
            else:
                result["privacy_protected"] = False

        except FileNotFoundError:
            warn("whois command not found — install with: apt install whois")
            result["error"] = "whois not installed"
        except subprocess.TimeoutExpired:
            warn("WHOIS lookup timed out")
            result["error"] = "timeout"
        except Exception as e:
            warn(f"WHOIS error: {e}")
            result["error"] = str(e)

        return result
