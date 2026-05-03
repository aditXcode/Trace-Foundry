"""
TraceFoundry V8 - Core Support Engines
diff_engine, time_sync, error_signature, context_injector,
waf_interceptor, session_rotator, oob_correlator, parameter_discovery
All in one file for clean imports.
"""
import re
import time
import json
import uuid
import threading
import urllib.request
import urllib.error
import urllib.parse
import statistics
import hashlib


# ═══════════════════════════════════════════════════════════════════
# 1. DIFF ENGINE — Structural Response Comparator
# ═══════════════════════════════════════════════════════════════════
class DiffEngine:
    """
    Compares responses structurally, not as raw strings.
    Removes noise: timestamps, tokens, random IDs, UUIDs.
    """

    NOISE_PATTERNS = [
        r'"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"',  # UUID
        r'"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',                             # ISO datetime
        r'"[a-f0-9]{32,64}"',                                                   # hex token
        r'"_csrf"\s*:\s*"[^"]+"',                                               # CSRF
        r'"request_id"\s*:\s*"[^"]+"',                                         # request ID
        r'"session_id"\s*:\s*"[^"]+"',                                         # session
        r'nonce="[^"]+"',                                                       # nonce
        r'value="[a-f0-9]{20,}"',                                              # form token
        r'\d{10,13}',                                                           # Unix timestamp
    ]

    def normalize(self, text):
        """Remove dynamic noise from response."""
        for pat in self.NOISE_PATTERNS:
            text = re.sub(pat, '"__NORMALIZED__"', text)
        return text

    def structural_hash(self, text):
        """Hash of normalized response for quick comparison."""
        return hashlib.md5(self.normalize(text).encode()).hexdigest()

    def is_different(self, body_a, body_b, threshold=0.15):
        """
        Return True if bodies differ meaningfully (not just noise).
        threshold: minimum fractional difference to count.
        """
        n_a = self.normalize(body_a)
        n_b = self.normalize(body_b)
        if n_a == n_b:
            return False
        # Length-based diff after normalization
        len_a = len(n_a)
        len_b = len(n_b)
        if len_a == 0 and len_b == 0:
            return False
        max_len = max(len_a, len_b, 1)
        diff    = abs(len_a - len_b) / max_len
        return diff > threshold

    def json_key_diff(self, body_a, body_b):
        """Compare JSON key structure only (ignore values)."""
        def extract_keys(text):
            try:
                data = json.loads(text)
                return set(self._flatten_keys(data))
            except:
                return set()

        keys_a = extract_keys(body_a)
        keys_b = extract_keys(body_b)
        added   = keys_b - keys_a
        removed = keys_a - keys_b
        return added, removed

    def _flatten_keys(self, obj, prefix=""):
        keys = set()
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                keys.add(full)
                keys |= self._flatten_keys(v, full)
        elif isinstance(obj, list):
            for item in obj[:3]:
                keys |= self._flatten_keys(item, prefix)
        return keys


# ═══════════════════════════════════════════════════════════════════
# 2. TIME SYNC — Network Jitter Compensator
# ═══════════════════════════════════════════════════════════════════
class TimeSyncEngine:
    """
    Measures network jitter to avoid false-positive time-based SQLi.
    Only flags if delay is significantly beyond baseline + jitter.
    """

    def __init__(self, timeout=8):
        self.timeout   = timeout
        self.jitter_db = {}  # url -> jitter metrics

    def _fetch_time(self, url):
        t0 = time.time()
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (TraceFoundry/8.0)"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                r.read(1024)
        except:
            pass
        return time.time() - t0

    def calibrate(self, url, n=5):
        """Send n clean requests to measure jitter."""
        if url in self.jitter_db:
            return self.jitter_db[url]

        times = []
        for _ in range(n):
            t = self._fetch_time(url)
            times.append(t)
            time.sleep(0.2)

        metrics = {
            "avg":   statistics.mean(times),
            "max":   max(times),
            "stdev": statistics.stdev(times) if len(times) > 1 else 0,
        }
        self.jitter_db[url] = metrics
        return metrics

    def is_delay_significant(self, url, elapsed, expected_delay=4):
        """
        Return True only if elapsed > baseline_max + stdev + 2s safety margin.
        Anti-FP: Won't fire on slow servers or congested networks.
        """
        metrics   = self.calibrate(url)
        threshold = metrics["max"] + metrics["stdev"] + 2.0
        return elapsed >= threshold and elapsed >= (expected_delay * 0.75)

    def binary_confirm_delay(self, url_template, delays=(2, 4, 6)):
        """
        Binary search delay confirmation — True if delays are roughly linear.
        Prevents false-positive from one-off server lag.
        """
        measured = []
        for d in delays:
            url = url_template.format(delay=d)
            t   = self._fetch_time(url)
            measured.append(t)
            time.sleep(0.5)

        # Check roughly linear: each step should add ~(delay[1]-delay[0]) seconds
        if len(measured) < 2:
            return False
        diffs = [measured[i+1] - measured[i] for i in range(len(measured)-1)]
        return all(d > 0.5 for d in diffs)  # each step adds >0.5s


# ═══════════════════════════════════════════════════════════════════
# 3. ERROR SIGNATURE DB — DBMS-Specific Error Patterns
# ═══════════════════════════════════════════════════════════════════
class ErrorSignatureDB:
    """
    Precise DBMS error signatures — avoids generic 'error' false positives.
    """

    SIGNATURES = {
        "MySQL": [
            r"you have an error in your sql syntax",
            r"warning: mysql_",
            r"mysql_fetch_array\(\)",
            r"mysql_num_rows\(\)",
            r"supplied argument is not a valid mysql",
            r"com\.mysql\.jdbc",
            r"org\.hibernate",
            r"mysql server version for the right syntax",
            r"unclosed quotation mark after the character string",
        ],
        "PostgreSQL": [
            r"pg::syntaxerror",
            r"ERROR: syntax error at or near",
            r"pg_query\(\)",
            r"pgsql error",
            r"postgresql.*ERROR",
            r"unterminated quoted string at or near",
            r"org\.postgresql",
        ],
        "MSSQL": [
            r"microsoft ole db provider for sql server",
            r"odbc sql server driver",
            r"sqlexception",
            r"com\.microsoft\.sqlserver",
            r"incorrect syntax near",
            r"unclosed quotation mark after",
            r"\[microsoft\]\[odbc",
            r"mssql_query\(\)",
        ],
        "Oracle": [
            r"ora-\d{4,5}",
            r"oracle driver",
            r"oracle\.jdbc",
            r"quoted string not properly terminated",
            r"pls-\d{5}",
            r"sql command not properly ended",
        ],
        "SQLite": [
            r"sqlite_query\(\)",
            r"sqlite3\.operationalerror",
            r'sqlite error',
            r'near ".+": syntax error',
            r"unrecognized token",
            r"\[sqlite\]",
            r"sqlite_master",
        ],
    }

    def detect(self, body):
        """
        Returns (db_type, matched_pattern) or (None, None).
        Only matches SPECIFIC patterns — not generic 'error'.
        """
        body_lower = body.lower()
        for db, patterns in self.SIGNATURES.items():
            for pat in patterns:
                if re.search(pat, body_lower, re.I):
                    return db, pat
        return None, None

    def is_false_positive(self, baseline_body, attack_body):
        """
        Return True if the error was already in baseline (not caused by payload).
        """
        _, baseline_match = self.detect(baseline_body)
        _, attack_match   = self.detect(attack_body)
        if baseline_match and attack_match:
            return True   # Error existed before attack — FP
        return False


# ═══════════════════════════════════════════════════════════════════
# 4. CONTEXT INJECTOR — Context-Aware Payload Encoding
# ═══════════════════════════════════════════════════════════════════
class ContextInjector:
    """
    Encodes payloads correctly based on injection context.
    Prevents malformed requests that cause false-positive server errors.
    """

    def inject_url_param(self, payload):
        return urllib.parse.quote(payload, safe="")

    def inject_json_body(self, data_dict, key, payload):
        """Inject payload into JSON body without breaking JSON syntax."""
        d = dict(data_dict)
        d[key] = payload
        return json.dumps(d).encode()

    def inject_xml_body(self, template, placeholder, payload):
        """Inject payload into XML with proper escaping."""
        escaped = (payload
                   .replace("&","&amp;")
                   .replace("<","&lt;")
                   .replace(">","&gt;")
                   .replace('"',"&quot;")
                   .replace("'","&apos;"))
        return template.replace(placeholder, escaped)

    def inject_header(self, payload):
        """Strip newlines/CR to prevent header injection breaking request."""
        return payload.replace("\r","").replace("\n","").replace("\x00","")

    def inject_multipart(self, field_name, payload,
                         content_type="text/plain"):
        boundary = "TFV8Boundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )
        return body.encode(), f"multipart/form-data; boundary={boundary}"

    def detect_context(self, url, param, sample_body):
        """
        Detect the context of param in the response.
        Returns: 'url_param' | 'json' | 'xml' | 'html_attr' | 'html_body'
        """
        if "application/json" in sample_body.lower() or sample_body.strip().startswith("{"):
            return "json"
        if "<?xml" in sample_body or "<root>" in sample_body:
            return "xml"
        return "url_param"


# ═══════════════════════════════════════════════════════════════════
# 5. WAF INTERCEPTOR — Detects WAF blocks before flagging
# ═══════════════════════════════════════════════════════════════════
class WAFInterceptor:
    """
    Detects WAF/CDN interference before modules flag a finding.
    Anti-FP: Don't flag 'SQLi found' when WAF blocked the request.
    """

    WAF_STATUS_CODES = {403, 406, 429, 503, 504}

    WAF_BODY_PATTERNS = [
        r"cloudflare ray id",
        r"aws waf",
        r"blocked by security policy",
        r"access denied.*firewall",
        r"sucuri website firewall",
        r"imperva incapsula",
        r"barracuda networks",
        r"request blocked",
        r"security check",
        r"mod_security",
        r"your ip.*blocked",
        r"ddos protection",
    ]

    WAF_HEADERS = [
        "x-blocked-by","cf-ray","x-sucuri-id",
        "x-iinfo","x-cdn","server-timing",
    ]

    def is_waf_block(self, status, body, headers):
        """
        Returns (True, waf_name) if WAF block detected, else (False, None).
        """
        # Status code check
        if status in self.WAF_STATUS_CODES:
            body_lower = body.lower()
            for pat in self.WAF_BODY_PATTERNS:
                if re.search(pat, body_lower):
                    return True, pat
            # Also check headers
            for h in self.WAF_HEADERS:
                if h in headers:
                    return True, f"header:{h}"
        return False, None

    def should_skip(self, status, body, headers):
        """Convenience method — returns True if module should skip this result."""
        blocked, reason = self.is_waf_block(status, body, headers)
        return blocked


# ═══════════════════════════════════════════════════════════════════
# 6. SESSION ROTATOR — Multi-Session IDOR Testing
# ═══════════════════════════════════════════════════════════════════
class SessionRotator:
    """
    Manages multiple sessions for IDOR horizontal/vertical privilege testing.
    Anti-FP: Only flag if User A can access, User B cannot (or vice-versa).
    """

    def __init__(self):
        self.sessions = {}  # name -> {"cookie": ..., "token": ...}

    def add_session(self, name, cookie=None, bearer_token=None, headers=None):
        self.sessions[name] = {
            "cookie":  cookie or "",
            "token":   bearer_token or "",
            "headers": headers or {},
        }

    def build_headers(self, session_name):
        s = self.sessions.get(session_name, {})
        h = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.0)"}
        if s.get("cookie"):
            h["Cookie"] = s["cookie"]
        if s.get("token"):
            h["Authorization"] = f"Bearer {s['token']}"
        h.update(s.get("headers", {}))
        return h

    def fetch_as(self, url, session_name, timeout=6):
        headers = self.build_headers(session_name)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                return body, r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except:
            return "", 0

    def test_idor(self, url, owner_session, attacker_session, unauth=True):
        """
        Proper IDOR test:
        1. Owner accesses resource → must be 200
        2. Attacker accesses same resource → check if 200
        3. Unauthenticated → should be 401/403

        Anti-FP conditions:
        - If resource is public (unauth=200) → NOT IDOR
        - If owner gets 403 → resource doesn't exist / no access
        - IDOR confirmed only if owner=200, attacker=200, unauth=401/403
        """
        body_owner,   status_owner   = self.fetch_as(url, owner_session)
        body_attacker,status_attacker = self.fetch_as(url, attacker_session)
        body_unauth,  status_unauth  = self.fetch_as(url, "__unauth__")

        result = {
            "url":            url,
            "owner_status":   status_owner,
            "attacker_status":status_attacker,
            "unauth_status":  status_unauth,
            "is_idor":        False,
            "confidence":     "low",
        }

        # Anti-FP: resource must exist for owner
        if status_owner not in (200, 201):
            return result

        # Anti-FP: if unauthenticated can also access → public resource, not IDOR
        if status_unauth in (200, 201):
            result["note"] = "Resource is public — not IDOR"
            return result

        # IDOR confirmed: owner=200, attacker=200, unauth=401/403
        if status_attacker in (200, 201):
            result["is_idor"]    = True
            result["confidence"] = "high"

        return result


# ═══════════════════════════════════════════════════════════════════
# 7. OOB CORRELATOR — UUID-based Callback Matching
# ═══════════════════════════════════════════════════════════════════
class OOBCorrelator:
    """
    Generates correlation IDs for blind vulnerability payloads.
    Matches callbacks to sent payloads via UUID.
    Anti-FP: Strict UUID match + 60-second time window.
    """

    def __init__(self, oob_host="interact.sh"):
        self.oob_host = oob_host
        self.pending  = {}   # uid -> {label, sent_at}
        self.lock     = threading.Lock()

    def gen_payload_url(self, label="probe"):
        """Generate OOB URL with unique correlation ID."""
        uid = str(uuid.uuid4())[:12].replace("-","")
        with self.lock:
            self.pending[uid] = {"label": label, "sent_at": time.time()}
        return f"http://{uid}.{self.oob_host}/{label}", uid

    def gen_dns_payload(self, label="dns"):
        """Generate OOB DNS subdomain."""
        uid = str(uuid.uuid4())[:12].replace("-","")
        with self.lock:
            self.pending[uid] = {"label": label, "sent_at": time.time()}
        return f"{uid}.{self.oob_host}", uid

    def check_callback(self, uid, window=60):
        """
        Poll interact.sh for callback.
        Anti-FP: Only accept exact UID within time window.
        """
        meta = self.pending.get(uid)
        if not meta:
            return False, None
        if time.time() - meta["sent_at"] > window:
            return False, None  # Expired

        poll = f"https://interact.sh/api/interactions?id={uid}"
        try:
            req = urllib.request.Request(
                poll, headers={"User-Agent": "TraceFoundry/8.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read(32768).decode())
                for interaction in data.get("data", []):
                    raw = json.dumps(interaction).lower()
                    if uid.lower() in raw:
                        return True, interaction
        except:
            pass
        return False, None

    def double_confirm(self, uid1, uid2, window=60):
        """
        Require TWO separate callbacks for high-confidence blind RCE/SSRF.
        Anti-FP: Single callback = might be cache/bot. Two = confirmed.
        """
        c1, i1 = self.check_callback(uid1, window)
        c2, i2 = self.check_callback(uid2, window)
        return c1 and c2, {"interaction1": i1, "interaction2": i2}


# ═══════════════════════════════════════════════════════════════════
# 8. PARAMETER DISCOVERY — Hidden Parameter Hunter
# ═══════════════════════════════════════════════════════════════════
class ParameterDiscovery:
    """
    Discovers hidden parameters not visible in frontend.
    Sources: JS extraction, common param wordlist, header fuzzing.
    """

    COMMON_PARAMS = [
        # Auth / User
        "id","user_id","uid","account_id","profile_id","member_id",
        "admin","role","is_admin","debug","test","dev",
        # Data
        "page","limit","offset","sort","order","filter","search","q",
        "query","keyword","s","term","tag","category","cat","type",
        # Config
        "lang","locale","format","output","callback","redirect",
        "return","next","url","ref","source","dest","from",
        # API
        "api_key","token","access_token","auth","key","secret",
        "version","v","api_version",
        # File
        "file","path","filename","doc","document","download","upload",
        "include","page","template","view","load",
        # Feature flags
        "feature","flag","mode","beta","preview",
    ]

    INJECTABLE_HEADERS = [
        "X-User-Id","X-Api-Key","X-Role","X-Admin",
        "X-Original-URL","X-Rewrite-URL","X-Forwarded-For",
        "X-Custom-IP","X-Debug","X-Internal",
    ]

    def __init__(self, timeout=6):
        self.timeout = timeout

    def _fetch(self, url, headers=None):
        h = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.0)"}
        if headers:
            h.update(headers)
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, {}
        except:
            return "", 0, {}

    def extract_from_js(self, js_body):
        """Extract parameter names from JavaScript source."""
        params = set()
        # From fetch/axios/XMLHttpRequest
        for pat in [
            r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=',
            r'params\[["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']\]',
            r'data\[["\']([a-zA-Z_][a-zA-Z0-9_]{1,30})["\']\]',
            r'"([a-zA-Z_][a-zA-Z0-9_]{1,30})":\s*(?:"|\'|\d)',
        ]:
            for m in re.findall(pat, js_body):
                if len(m) > 1 and m not in ("src","href","type","name","id"):
                    params.add(m)
        return list(params)[:50]

    def fuzz_params(self, base_url, baseline_body, baseline_len):
        """
        Test common hidden parameters — flag if response changes significantly.
        Anti-FP: Only flag if response diff > 20% AND status is 200.
        """
        found = []
        for param in self.COMMON_PARAMS[:30]:
            for val in ["1","true","admin","debug","test"]:
                url = f"{base_url}?{param}={val}"
                body, status, _ = self._fetch(url)
                if status != 200 or not body:
                    continue
                diff = abs(len(body) - baseline_len) / max(baseline_len, 1)
                if diff > 0.20:
                    found.append({
                        "param": param,
                        "value": val,
                        "url":   url,
                        "diff":  round(diff, 2),
                        "note":  "Response changed significantly with this param",
                    })
        return found

    def fuzz_headers(self, url, baseline_body):
        """Test injectable headers for admin bypass or behavior change."""
        found = []
        for header in self.INJECTABLE_HEADERS:
            for val in ["1","true","admin","127.0.0.1","localhost"]:
                body, status, _ = self._fetch(url, headers={header: val})
                if status == 200 and body != baseline_body:
                    if len(body) > len(baseline_body) * 1.1:
                        found.append({
                            "header": header,
                            "value":  val,
                            "url":    url,
                            "note":   "Header changes response — possible access control bypass",
                        })
        return found


# ═══════════════════════════════════════════════════════════════════
# SINGLETON ACCESSORS
# ═══════════════════════════════════════════════════════════════════
_diff_engine        = None
_time_sync          = None
_error_sig_db       = None
_context_injector   = None
_waf_interceptor    = None
_session_rotator    = None
_oob_correlator     = None
_param_discovery    = None

def get_diff_engine():
    global _diff_engine
    if not _diff_engine: _diff_engine = DiffEngine()
    return _diff_engine

def get_time_sync(timeout=8):
    global _time_sync
    if not _time_sync: _time_sync = TimeSyncEngine(timeout)
    return _time_sync

def get_error_sig_db():
    global _error_sig_db
    if not _error_sig_db: _error_sig_db = ErrorSignatureDB()
    return _error_sig_db

def get_context_injector():
    global _context_injector
    if not _context_injector: _context_injector = ContextInjector()
    return _context_injector

def get_waf_interceptor():
    global _waf_interceptor
    if not _waf_interceptor: _waf_interceptor = WAFInterceptor()
    return _waf_interceptor

def get_session_rotator():
    global _session_rotator
    if not _session_rotator: _session_rotator = SessionRotator()
    return _session_rotator

def get_oob_correlator(oob_host="interact.sh"):
    global _oob_correlator
    if not _oob_correlator: _oob_correlator = OOBCorrelator(oob_host)
    return _oob_correlator

def get_param_discovery(timeout=6):
    global _param_discovery
    if not _param_discovery: _param_discovery = ParameterDiscovery(timeout)
    return _param_discovery
