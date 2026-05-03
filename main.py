#!/usr/bin/env python3
"""
TraceFoundry V8.5 — Professional Bug Bounty Scanner
40 Modules | 8 Anti-FP Engines | HTTP/2 | Rich Output
"""
import sys, re
from core.engine import ReconEngine
from utils.display import banner, print_info

ALL_MODULES = [
    "passive_recon",
    "dns","whois","ssl","waf",
    "subdomains","ports",
    "cms_scanner",
    "headers","header_audit",
    "paths","emails",
    "credential_checker",
    "js_entropy",
    "cors","sqli","xss",
    "lfi_rfi","cmdi_ssti","xxe","ssrf",
    "idor","api_scanner",
    "graphql_scanner","oob_server",
    "proto_pollute","dom_sink_scan",
    "dep_confuse","oauth_audit",
    "cloud_takeover",
    "redirect","ratelimit",
    "methods","tech_scan",
    "takeover","race_condition",
    "cache_poison","file_upload",
]

PRESETS = {
    "start":   ALL_MODULES,
    "quick":   ["dns","ssl","waf","headers","header_audit","paths",
                "cms_scanner","tech_scan","sqli","xss","cors",
                "credential_checker","js_entropy"],
    "recon":   ["passive_recon","dns","whois","subdomains","ports",
                "emails","waf","ssl","tech_scan","takeover",
                "cms_scanner","cloud_takeover"],
    "vuln":    ["sqli","xss","lfi_rfi","cmdi_ssti","xxe","ssrf",
                "idor","cors","redirect","ratelimit","methods",
                "header_audit","paths","tech_scan","race_condition",
                "cache_poison","file_upload","credential_checker",
                "graphql_scanner","oob_server","proto_pollute",
                "dom_sink_scan","oauth_audit","cloud_takeover"],
    "stealth": ["passive_recon","dns","whois","ssl","headers",
                "header_audit","paths","waf","tech_scan","cms_scanner"],
    "api":     ["api_scanner","graphql_scanner","cors","sqli","xss",
                "ssrf","idor","ratelimit","methods","race_condition",
                "oauth_audit","proto_pollute"],
    "inject":  ["sqli","xss","lfi_rfi","cmdi_ssti","xxe",
                "ssrf","file_upload","oob_server","proto_pollute"],
    "passive": ["passive_recon"],
    "cms":     ["cms_scanner","credential_checker","paths","tech_scan"],
    "creds":   ["credential_checker","cms_scanner","js_entropy","paths"],
    "oob":     ["oob_server","ssrf","xxe","cmdi_ssti"],
    "cloud":   ["cloud_takeover","passive_recon","subdomains","takeover"],
    "js":      ["js_entropy","dom_sink_scan","dep_confuse","cors"],
    "oauth":   ["oauth_audit","cors","redirect","ratelimit"],
}

def usage():
    print("""
  ─────────────────────────────────────────────────────
  TRACE FOUNDRY V8.5  |  40 Modules  |  8 Anti-FP Engines
  ─────────────────────────────────────────────────────
  python3 main.py <domain> start      Full scan (40 modul)
  python3 main.py <domain> quick      ~3 menit
  python3 main.py <domain> recon      Recon + passive + cloud
  python3 main.py <domain> vuln       Semua vuln scan
  python3 main.py <domain> stealth    Low-noise
  python3 main.py <domain> api        API + GraphQL + OAuth
  python3 main.py <domain> inject     Injection attacks
  python3 main.py <domain> passive    Passive only
  python3 main.py <domain> cms        CMS deep scan
  python3 main.py <domain> creds      Credential check
  python3 main.py <domain> oob        OOB blind testing
  python3 main.py <domain> cloud      Cloud storage check
  python3 main.py <domain> js         JS entropy + DOM + deps
  python3 main.py <domain> oauth      OAuth security audit

  Domain: nasa.gov | target.com | site.my | sub.target.go.id

  Options:
    --threads <n>        Default: 40
    --timeout <n>        Default: 6
    --wordlist <file>    Custom subdomain list
    --out json|html|both Default: both
    --resume             Resume from last saved state

  Contoh:
    python3 main.py nasa.gov start
    python3 main.py target.com vuln --threads 60
    python3 main.py site.gov.my recon --resume
  ─────────────────────────────────────────────────────
""")

def clean_domain(d):
    d = d.strip()
    d = re.sub(r'^https?://','',d)
    d = re.sub(r'^www\.','',d)
    return d.split('/')[0].split('?')[0].split('#')[0].lower()

def parse_args(argv):
    if len(argv) < 3: return None, None, {}
    domain  = clean_domain(argv[1])
    command = argv[2].lower()
    opts    = {"threads":40,"timeout":6,"wordlist":None,"out":"both","resume":False}
    i = 3
    while i < len(argv):
        a = argv[i]
        if   a=="--threads"  and i+1<len(argv): opts["threads"]  = int(argv[i+1]); i+=2
        elif a=="--timeout"  and i+1<len(argv): opts["timeout"]  = int(argv[i+1]); i+=2
        elif a=="--wordlist" and i+1<len(argv): opts["wordlist"] = argv[i+1];      i+=2
        elif a=="--out"      and i+1<len(argv): opts["out"]      = argv[i+1];      i+=2
        elif a=="--resume":                      opts["resume"]   = True;           i+=1
        else: i+=1
    return domain, command, opts

def main():
    banner()
    domain, command, opts = parse_args(sys.argv)
    if not domain or command not in PRESETS:
        usage(); sys.exit(0)
    modules = PRESETS[command]
    print_info(f"Domain   : {domain}")
    print_info(f"Mode     : {command.upper()}  ({len(modules)} modules)")
    print_info(f"Threads  : {opts['threads']}  |  Timeout: {opts['timeout']}s")
    print_info(f"Anti-FP  : Baseline+TripleGate+DiffEngine+Jitter+WAF+RateLimit")
    if opts["resume"]: print_info("Resume   : ON — skipping completed modules")
    print()
    ReconEngine(
        domain=domain, modules=modules,
        wordlist_file=opts["wordlist"],
        output_format=opts["out"],
        threads=opts["threads"],
        timeout=opts["timeout"],
        resume=opts["resume"],
    ).run()

if __name__ == "__main__":
    main()
