"""TraceFoundry V8.5 - Core Engine with State Persistence + Resume"""
import json, os, time, re
from datetime import datetime
from utils.display import (ok, warn, info, print_info, print_final_summary,
                           module_start, R, B, CY, GR, YL, RD, BL, WH, DM)
from core.system_components import get_state

from modules.dns_lookup          import DNSModule
from modules.subdomain_enum      import SubdomainModule
from modules.port_scanner        import PortModule
from modules.header_grabber      import HeaderModule
from modules.header_checker      import HeaderCheckerModule
from modules.path_checker        import PathModule
from modules.whois_lookup        import WhoisModule
from modules.email_harvester     import EmailModule
from modules.waf_detector        import WAFModule
from modules.ssl_checker         import SSLModule
from modules.cors_checker        import CORSModule
from modules.js_analyzer         import JSAnalyzerModule
from modules.sqli                import SQLiModule
from modules.xss                 import XSSModule
from modules.lfi_rfi             import LFIModule
from modules.cmdi_ssti           import CMDIModule
from modules.xxe                 import XXEModule
from modules.ssrf                import SSRFModule
from modules.idor                import IDORModule
from modules.api_scanner         import APIScannerModule
from modules.open_redirect       import OpenRedirectModule
from modules.rate_limit_checker  import RateLimitModule
from modules.http_method_checker import HTTPMethodModule
from modules.tech_scan           import TechScanModule
from modules.takeover_checker    import TakeoverModule
from modules.race_condition      import RaceConditionModule
from modules.cache_poison        import CachePoisonModule
from modules.file_upload         import FileUploadModule
from modules.passive_recon       import PassiveReconModule
from modules.cms_scanner         import CMSScannerModule
from modules.credential_checker  import CredentialModule
from modules.graphql_scanner     import GraphQLModule
from modules.oob_server          import OOBModule
from modules.proto_pollute       import ProtoPollutionModule
from modules.js_entropy          import JSEntropyModule
from modules.dom_sink_scan       import DOMSinkModule
from modules.dep_confuse         import DepConfuseModule
from modules.oauth_audit         import OAuthAuditModule
from modules.cloud_takeover      import CloudTakeoverModule
from utils.report_html           import generate_html_report

MODULE_LABELS = {
    "dns":"DNS Lookup","whois":"WHOIS Info","ssl":"SSL/TLS Audit",
    "waf":"WAF Detection","subdomains":"Subdomain Enum","ports":"Port Scan",
    "headers":"HTTP Headers","header_audit":"Security Headers",
    "paths":"Sensitive Paths","emails":"Email Harvest","cors":"CORS Check",
    "js_scanner":"JS Secret Scan","js_entropy":"JS Entropy + Secrets",
    "sqli":"SQLi (Anti-FP Triple Gate)","xss":"XSS Scan",
    "lfi_rfi":"LFI/RFI","cmdi_ssti":"CMDi/SSTI","xxe":"XXE Injection",
    "ssrf":"SSRF Scan","idor":"IDOR/BAC","api_scanner":"API Security",
    "graphql_scanner":"GraphQL Analyzer","oob_server":"OOB Blind Server",
    "proto_pollute":"Prototype Pollution","dom_sink_scan":"DOM Sink (Browser)",
    "dep_confuse":"Dependency Confusion","oauth_audit":"OAuth Audit",
    "cloud_takeover":"Cloud Storage Takeover",
    "redirect":"Open Redirect","ratelimit":"Rate Limiting",
    "methods":"HTTP Methods","tech_scan":"Tech Vuln Scan",
    "takeover":"Subdomain Takeover","race_condition":"Race Condition",
    "cache_poison":"Cache Poisoning","file_upload":"File Upload",
    "passive_recon":"Passive Recon (crt.sh|Wayback)",
    "cms_scanner":"CMS Deep Scanner","credential_checker":"Credential Checker",
}

INFO_ONLY = {"dns","whois","subdomains","ports","emails","headers","waf"}

def clean_domain(domain):
    domain = domain.strip()
    domain = re.sub(r'^https?://','',domain)
    domain = re.sub(r'^www\.','',domain)
    return domain.split('/')[0].split('?')[0].split('#')[0].lower()

class ReconEngine:
    def __init__(self, domain, modules, wordlist_file=None,
                 output_format="both", threads=40, timeout=6, resume=False):
        self.domain        = clean_domain(domain)
        self.modules       = modules
        self.wordlist_file = wordlist_file
        self.output_format = output_format
        self.threads       = threads
        self.timeout       = timeout
        self.resume        = resume
        self.all_bugs      = []
        self.start_time    = time.time()
        self.state         = get_state(self.domain)
        self.report = {
            "tool":"Trace Foundry","version":"8.5.0",
            "target":self.domain,
            "timestamp":datetime.now().isoformat(),
            "results":{}
        }

    def _ip(self):
        import socket
        ip = self.report["results"].get("dns",{}).get("ip")
        if not ip:
            try: ip = socket.gethostbyname(self.domain)
            except: ip = self.domain
        return ip

    def _collect(self, key, data):
        if key in INFO_ONLY: return
        bugs = data if isinstance(data,list) else \
               data.get("bugs",[]) if isinstance(data,dict) else []
        for b in bugs:
            if isinstance(b,dict) and b.get("type","") not in ("","?"):
                b.setdefault("module", key)
                self.all_bugs.append(b)
                self.state.save_bug(key, b)

    def _run(self, key):
        label = MODULE_LABELS.get(key, key)

        # Resume: skip completed modules
        if self.resume and self.state.is_done(key):
            info(f"SKIP (resume): {label}")
            result = self.state.load_result(key)
            return result

        spinner = module_start(label)
        runners = {
            "dns":               lambda: DNSModule(self.domain,self.timeout).run(),
            "whois":             lambda: WhoisModule(self.domain).run(),
            "ssl":               lambda: SSLModule(self.domain,self.timeout).run(),
            "waf":               lambda: WAFModule(self.domain,self.timeout).run(),
            "subdomains":        lambda: SubdomainModule(self.domain,self.wordlist_file,self.threads,self.timeout).run(),
            "ports":             lambda: PortModule(self._ip(),None,self.threads,self.timeout).run(),
            "headers":           lambda: HeaderModule(self.domain,self.timeout).run(),
            "header_audit":      lambda: HeaderCheckerModule(self.domain,self.timeout).run(),
            "paths":             lambda: PathModule(self.domain,self.timeout).run(),
            "emails":            lambda: EmailModule(self.domain,self.timeout).run(),
            "cors":              lambda: CORSModule(self.domain,self.timeout).run(),
            "js_scanner":        lambda: JSAnalyzerModule(self.domain,self.timeout).run(),
            "js_entropy":        lambda: JSEntropyModule(self.domain,self.timeout).run(),
            "sqli":              lambda: SQLiModule(self.domain,self.timeout).run(),
            "xss":               lambda: XSSModule(self.domain,self.timeout).run(),
            "lfi_rfi":           lambda: LFIModule(self.domain,self.timeout).run(),
            "cmdi_ssti":         lambda: CMDIModule(self.domain,self.timeout).run(),
            "xxe":               lambda: XXEModule(self.domain,self.timeout).run(),
            "ssrf":              lambda: SSRFModule(self.domain,self.timeout).run(),
            "idor":              lambda: IDORModule(self.domain,self.timeout).run(),
            "api_scanner":       lambda: APIScannerModule(self.domain,self.timeout).run(),
            "graphql_scanner":   lambda: GraphQLModule(self.domain,self.timeout).run(),
            "oob_server":        lambda: OOBModule(self.domain,self.timeout).run(),
            "proto_pollute":     lambda: ProtoPollutionModule(self.domain,self.timeout).run(),
            "dom_sink_scan":     lambda: DOMSinkModule(self.domain,self.timeout).run(),
            "dep_confuse":       lambda: DepConfuseModule(self.domain,self.timeout).run(),
            "oauth_audit":       lambda: OAuthAuditModule(self.domain,self.timeout).run(),
            "cloud_takeover":    lambda: CloudTakeoverModule(self.domain,self.timeout).run(),
            "redirect":          lambda: OpenRedirectModule(self.domain,self.timeout).run(),
            "ratelimit":         lambda: RateLimitModule(self.domain,self.timeout).run(),
            "methods":           lambda: HTTPMethodModule(self.domain,self.timeout).run(),
            "tech_scan":         lambda: TechScanModule(self.domain,self.timeout).run(),
            "takeover":          lambda: TakeoverModule(self.domain,
                                     self.report["results"].get("subdomains",[]),
                                     self.timeout).run(),
            "race_condition":    lambda: RaceConditionModule(self.domain,self.timeout).run(),
            "cache_poison":      lambda: CachePoisonModule(self.domain,self.timeout).run(),
            "file_upload":       lambda: FileUploadModule(self.domain,self.timeout).run(),
            "passive_recon":     lambda: PassiveReconModule(self.domain,self.timeout).run(),
            "cms_scanner":       lambda: CMSScannerModule(self.domain,self.timeout).run(),
            "credential_checker":lambda: CredentialModule(self.domain,self.timeout).run(),
        }

        if key not in runners:
            spinner.stop(skipped=True); return {}

        try:
            result = runners[key]()
        except Exception as e:
            spinner.stop(skipped=True); return {}

        # Save state
        self.state.save_result(key, result)

        if key in INFO_ONLY:
            spinner.stop(bugs=0)
        else:
            bugs = result if isinstance(result,list) else \
                   result.get("bugs",[]) if isinstance(result,dict) else []
            real = [b for b in bugs if isinstance(b,dict) and b.get("type","") not in ("","?")]
            spinner.stop(bugs=len(real))

        return result

    def run(self):
        total = len(self.modules)
        print(f"  {DM}Running {total} modules on {CY}{self.domain}{R}")
        print(f"  {DM}Anti-FP: Baseline+TripleGate+Diff+Jitter+WAF+RateLimit{R}\n")

        for mod in self.modules:
            result = self._run(mod)
            self.report["results"][mod] = result
            self._collect(mod, result)

        self.report["all_bugs"] = self.all_bugs
        self._save()
        self._summary()

    def _save(self):
        os.makedirs("reports", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"reports/{self.domain}_{ts}"
        if self.output_format in ("json","both"):
            with open(f"{base}.json","w") as f:
                json.dump(self.report, f, indent=2)
            ok(f"JSON saved: {base}.json")
        if self.output_format in ("html","both"):
            try:
                generate_html_report(self.report, f"{base}.html")
                ok(f"HTML saved: {base}.html")
            except Exception as e:
                warn(f"HTML error: {e}")

    def _summary(self):
        elapsed = time.time() - self.start_time
        r  = self.report["results"]
        techs     = r.get("tech_scan",{}).get("detected_techs",[])
        cms       = r.get("cms_scanner",{}).get("cms_detected","")
        tech_str  = cms or (", ".join(t["tech"] for t in techs[:3]) if techs else "Unknown")
        ports     = r.get("ports",[])
        subs      = r.get("subdomains",[])
        cert_subs = r.get("passive_recon",{}).get("cert_subdomains",[])
        wb_urls   = r.get("passive_recon",{}).get("wayback_urls",[])
        gql       = r.get("graphql_scanner",{}).get("bugs",[])
        cloud_bugs= r.get("cloud_takeover",{}).get("bugs",[])

        meta = {
            "IP":             r.get("dns",{}).get("ip","N/A"),
            "Registrar":      str(r.get("whois",{}).get("registrar","N/A"))[:30],
            "WAF":            r.get("waf",{}).get("waf_name","None") or "None",
            "SSL":            f"Grade {r.get('ssl',{}).get('grade','?')}  {r.get('ssl',{}).get('protocol','?')}",
            "Sec Headers":    f"{r.get('header_audit',{}).get('score','?')}/100  Grade:{r.get('header_audit',{}).get('grade','?')}",
            "CMS/Tech":       tech_str,
            "Subdomains":     f"{len(subs)} active + {len(cert_subs)} from certs",
            "Open Ports":     ", ".join(str(p["port"]) for p in ports[:6]) or "None",
            "Wayback URLs":   f"{len(wb_urls)} historical URLs",
            "GraphQL Issues": f"{len(gql)} found" if gql else "None",
            "Cloud Issues":   f"{len(cloud_bugs)} found" if cloud_bugs else "None",
            "JS Endpoints":   str(len(r.get("js_entropy",{}).get("endpoints_found",[]))),
            "Duration":       f"{elapsed:.0f}s",
        }
        print_final_summary(self.domain, meta, self.all_bugs, elapsed)
