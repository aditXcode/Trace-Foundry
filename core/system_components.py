"""
Trace Foundry V8.5 - Core System Components
1. Adaptive Rate Limiter (aiolimiter + exponential backoff)
2. Smart Jitter (randomized timing)
3. HTTP/2 Fetcher (httpx fallback to urllib)
4. WAF Fingerprint (wafw00f logic)
5. Header Rotation (fake-useragent style)
6. State Persistence (SQLite)
"""
import time, random, re, json, sqlite3, os, threading
import urllib.request, urllib.error
from utils.display import info, warn

# ═══════════════════════════════════════════════════════════════════
# 1. ADAPTIVE RATE LIMITER
# ═══════════════════════════════════════════════════════════════════
class AdaptiveRateLimiter:
    """
    Tracks server responses. If 429/503 received:
    - Increase delay exponentially
    - Add jitter to avoid bot detection
    If responses healthy: slowly decrease delay (backoff recovery)
    """
    def __init__(self, initial_rps=10, min_delay=0.05, max_delay=30.0):
        self.delay     = 1.0 / initial_rps
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.backoff   = 1.0
        self.lock      = threading.Lock()
        self._last     = 0.0

    def wait(self):
        with self.lock:
            now     = time.time()
            elapsed = now - self._last
            jitter  = random.uniform(0.5, 2.0)  # Smart Jitter
            sleep_t = max(0, (self.delay * jitter) - elapsed)
            if sleep_t > 0:
                time.sleep(sleep_t)
            self._last = time.time()

    def on_success(self):
        """Slowly reduce delay on success."""
        with self.lock:
            self.backoff = max(1.0, self.backoff * 0.9)
            self.delay   = max(self.min_delay, self.delay * 0.95)

    def on_rate_limit(self, status=429):
        """Exponential backoff on 429/503."""
        with self.lock:
            self.backoff = min(self.backoff * 2.0, 32.0)
            self.delay   = min(self.max_delay, self.delay * self.backoff)
            jitter       = random.uniform(0.8, 1.2)
            sleep_t      = self.delay * jitter
            warn(f"Rate limit ({status}) — backing off {sleep_t:.1f}s")
            time.sleep(sleep_t)

    def on_block(self):
        """Hard block — wait longer."""
        wait = random.uniform(10, 20)
        warn(f"Blocked — waiting {wait:.0f}s")
        time.sleep(wait)


# ═══════════════════════════════════════════════════════════════════
# 2. HTTP/2 FETCHER (httpx with fallback)
# ═══════════════════════════════════════════════════════════════════
class HTTP2Fetcher:
    """
    Uses httpx[http2] when available for HTTP/2 connections.
    Falls back to urllib for HTTP/1.1.
    Anti-bypass: HTTP/2 connections bypass some WAF rules.
    """
    def __init__(self, timeout=8, rate_limiter=None):
        self.timeout      = timeout
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter()
        self._httpx_available = False
        try:
            import httpx
            self._httpx = httpx
            self._httpx_available = True
        except ImportError:
            self._httpx = None

    def fetch(self, url, method="GET", headers=None, data=None,
              use_http2=True):
        """
        Fetch URL with HTTP/2 if available.
        Returns (body, status, headers_dict, http_version)
        """
        self.rate_limiter.wait()
        h = self._default_headers()
        if headers:
            h.update(headers)

        if self._httpx_available and use_http2:
            return self._fetch_httpx(url, method, h, data)
        return self._fetch_urllib(url, method, h, data)

    def _default_headers(self):
        return {
            "User-Agent": HeaderRotator().get(),
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        }

    def _fetch_httpx(self, url, method, headers, data):
        try:
            with self._httpx.Client(http2=True, verify=False,
                                     timeout=self.timeout,
                                     follow_redirects=True) as client:
                resp = client.request(method, url,
                                      headers=headers,
                                      content=data)
                self.rate_limiter.on_success()
                return (resp.text[:65536], resp.status_code,
                        dict(resp.headers), "HTTP/2" if resp.http_version == "HTTP/2" else "HTTP/1.1")
        except Exception as e:
            return self._fetch_urllib(url, method, headers, data)

    def _fetch_urllib(self, url, method, headers, data):
        try:
            req = urllib.request.Request(url, data=data,
                                          headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                self.rate_limiter.on_success()
                return body, r.status, dict(r.headers), "HTTP/1.1"
        except urllib.error.HTTPError as e:
            status = e.code
            if status in (429, 503):
                self.rate_limiter.on_rate_limit(status)
            elif status == 403:
                self.rate_limiter.on_block()
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, status, dict(e.headers), "HTTP/1.1"
        except Exception:
            return "", 0, {}, "error"


# ═══════════════════════════════════════════════════════════════════
# 3. HEADER ROTATOR
# ═══════════════════════════════════════════════════════════════════
class HeaderRotator:
    """
    Rotates User-Agent and other headers to evade WAF fingerprinting.
    """
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    ]

    ACCEPT_HEADERS = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "application/json, text/plain, */*",
        "*/*",
    ]

    def get(self):
        return random.choice(self.USER_AGENTS)

    def full_headers(self):
        return {
            "User-Agent":      random.choice(self.USER_AGENTS),
            "Accept":          random.choice(self.ACCEPT_HEADERS),
            "Accept-Language": random.choice(["en-US,en;q=0.9","en-GB,en;q=0.8","id-ID,id;q=0.9,en;q=0.8"]),
            "Cache-Control":   random.choice(["no-cache","max-age=0",""]),
            "DNT":             random.choice(["1","0"]),
        }


# ═══════════════════════════════════════════════════════════════════
# 4. WAF FINGERPRINTER (wafw00f-inspired)
# ═══════════════════════════════════════════════════════════════════
class WAFFingerprinter:
    """
    Advanced WAF detection. Returns WAF name + confidence + evasion hints.
    """
    SIGNATURES = {
        "Cloudflare": {
            "headers":  ["cf-ray","cf-cache-status","cf-request-id"],
            "body":     ["cloudflare","attention required | cloudflare","ray id:"],
            "cookies":  ["__cfduid","cf_clearance"],
            "status":   [403,503],
        },
        "AWS WAF": {
            "headers":  ["x-amzn-requestid","x-amz-cf-id","x-amz-cf-pop"],
            "body":     ["request blocked","aws"],
            "cookies":  [],
            "status":   [403],
        },
        "Akamai": {
            "headers":  ["x-akamai-transformed","akamai-origin-hop","x-check-cacheable"],
            "body":     ["access denied","reference #","akamai"],
            "cookies":  ["ak_bmsc","bm_sz"],
            "status":   [403],
        },
        "Imperva": {
            "headers":  ["x-iinfo","x-cdn"],
            "body":     ["incapsula","_incap_ses"],
            "cookies":  ["incap_ses","visid_incap"],
            "status":   [403],
        },
        "ModSecurity": {
            "headers":  [],
            "body":     ["mod_security","modsecurity","this error was generated by mod_security"],
            "cookies":  [],
            "status":   [403,406],
        },
        "F5 BIG-IP": {
            "headers":  ["x-cnection","ts"],
            "body":     ["the requested url was rejected","please consult with your administrator"],
            "cookies":  ["ts","bigipserver"],
            "status":   [403],
        },
        "Sucuri": {
            "headers":  ["x-sucuri-id","x-sucuri-cache"],
            "body":     ["sucuri","access denied - sucuri"],
            "cookies":  [],
            "status":   [403,503],
        },
        "Fastly": {
            "headers":  ["x-fastly-request-id","fastly-restarts","x-served-by"],
            "body":     [],
            "cookies":  [],
            "status":   [],
        },
        "Barracuda": {
            "headers":  ["barra_counter_session"],
            "body":     ["barracuda","barracuda networks"],
            "cookies":  ["barra_counter_session"],
            "status":   [403],
        },
    }

    def detect(self, status, body, headers, cookies=""):
        body_l    = body.lower()
        headers_l = {k.lower(): v.lower() for k, v in headers.items()}
        best_waf  = None
        best_score = 0

        for waf_name, sigs in self.SIGNATURES.items():
            score = 0
            for h in sigs["headers"]:
                if h.lower() in headers_l:
                    score += 3
            for b in sigs["body"]:
                if b.lower() in body_l:
                    score += 2
            for c in sigs["cookies"]:
                if c.lower() in cookies.lower():
                    score += 2
            if status in sigs.get("status",[]):
                score += 1

            if score > best_score:
                best_score = score
                best_waf   = waf_name

        if best_score >= 2:
            confidence = "HIGH" if best_score >= 5 else "MEDIUM"
            return best_waf, confidence
        return None, None

    def get_evasion_hints(self, waf_name):
        hints = {
            "Cloudflare": ["Use HTTP/2","Rotate User-Agent","Add CF-Connecting-IP header"],
            "AWS WAF":    ["Use HTTP/2","Fragment payloads","Try JSON encoding"],
            "Akamai":     ["Slow down requests","Use chunked encoding"],
            "ModSecurity":["Use case variations","URL double-encoding","Whitespace insertion"],
            "Imperva":    ["Use HTTP/2","Rotate IPs via headers"],
        }
        return hints.get(waf_name, ["Use HTTP/2", "Rotate User-Agent", "Add Smart Jitter"])


# ═══════════════════════════════════════════════════════════════════
# 5. STATE PERSISTENCE (SQLite)
# ═══════════════════════════════════════════════════════════════════
class StatePersistence:
    """
    Pause/Resume scan state using SQLite.
    Saves: completed modules, found bugs, recon data.
    """
    def __init__(self, domain, db_path=None):
        self.domain  = domain
        safe_domain  = re.sub(r'[^a-z0-9_]', '_', domain)
        self.db_path = db_path or f"reports/{safe_domain}_state.db"
        os.makedirs("reports", exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS module_state (
                    module TEXT PRIMARY KEY,
                    status TEXT,
                    result TEXT,
                    timestamp REAL
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bugs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT,
                    type TEXT,
                    severity TEXT,
                    url TEXT,
                    data TEXT,
                    timestamp REAL
                )""")
            conn.commit()

    def is_done(self, module):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT status FROM module_state WHERE module=?",
                (module,)).fetchone()
            return row and row[0] == "done"

    def save_result(self, module, result):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO module_state
                (module, status, result, timestamp)
                VALUES (?,?,?,?)""",
                (module, "done", json.dumps(result, default=str),
                 time.time()))
            conn.commit()

    def load_result(self, module):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT result FROM module_state WHERE module=?",
                (module,)).fetchone()
            if row:
                try: return json.loads(row[0])
                except: return {}
        return {}

    def save_bug(self, module, bug):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO bugs
                (module, type, severity, url, data, timestamp)
                VALUES (?,?,?,?,?,?)""",
                (module, bug.get("type",""),
                 bug.get("severity",""),
                 bug.get("url",""),
                 json.dumps(bug, default=str),
                 time.time()))
            conn.commit()

    def load_all_bugs(self):
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT data FROM bugs ORDER BY timestamp").fetchall()
            bugs = []
            for row in rows:
                try: bugs.append(json.loads(row[0]))
                except: pass
            return bugs

    def reset(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM module_state")
            conn.execute("DELETE FROM bugs")
            conn.commit()
        info(f"State cleared for {self.domain}")


# ═══════════════════════════════════════════════════════════════════
# SINGLETONS
# ═══════════════════════════════════════════════════════════════════
_rate_limiter = None
_http2_fetcher = None
_header_rotator = None
_waf_fingerprinter = None

def get_rate_limiter():
    global _rate_limiter
    if not _rate_limiter: _rate_limiter = AdaptiveRateLimiter()
    return _rate_limiter

def get_http2_fetcher(timeout=8):
    global _http2_fetcher
    if not _http2_fetcher:
        _http2_fetcher = HTTP2Fetcher(timeout, get_rate_limiter())
    return _http2_fetcher

def get_header_rotator():
    global _header_rotator
    if not _header_rotator: _header_rotator = HeaderRotator()
    return _header_rotator

def get_waf_fingerprinter():
    global _waf_fingerprinter
    if not _waf_fingerprinter: _waf_fingerprinter = WAFFingerprinter()
    return _waf_fingerprinter

def get_state(domain):
    return StatePersistence(domain)
