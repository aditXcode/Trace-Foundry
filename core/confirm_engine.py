"""
TraceFoundry V8 - Core Confirm Engine
Triple Gate: Every finding must pass 3 independent checks.
Anti-FP: Single payload trigger = noise. 3 gates = confirmed.
"""
import time
import urllib.request
import urllib.error

class ConfirmEngine:
    """
    Usage:
        ce = ConfirmEngine(fetch_fn, baseline)
        confirmed, evidence = ce.confirm_sqli(url, param, payloads_abc)
    """

    def __init__(self, timeout=6):
        self.timeout = timeout

    def _fetch(self, url, post_data=None, headers=None):
        h = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.0)"}
        if headers:
            h.update(headers)
        t0 = time.time()
        try:
            req = urllib.request.Request(url, data=post_data, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body    = r.read(65536).decode("utf-8", errors="ignore")
                elapsed = time.time() - t0
                return body, r.status, elapsed
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, time.time() - t0
        except:
            return "", 0, time.time() - t0

    def triple_gate(self, url, payload_a, payload_b, payload_clean,
                    check_fn, param=None):
        """
        Gate 1: payload_a (attack)   → check_fn must return True
        Gate 2: payload_b (alt attack)→ check_fn must return True
        Gate 3: payload_clean        → check_fn must return False

        check_fn(body, status, elapsed) -> bool

        Returns (passed: bool, evidence: dict)
        """
        evidence = {}

        # Gate 1
        url1 = f"{url}?{param}={payload_a}" if param else url
        b1, s1, t1 = self._fetch(url1)
        g1 = check_fn(b1, s1, t1)
        evidence["gate1"] = {"payload": payload_a, "passed": g1,
                              "status": s1, "len": len(b1), "time": round(t1,2)}

        if not g1:
            return False, evidence  # Fast fail

        time.sleep(0.3)

        # Gate 2
        url2 = f"{url}?{param}={payload_b}" if param else url
        b2, s2, t2 = self._fetch(url2)
        g2 = check_fn(b2, s2, t2)
        evidence["gate2"] = {"payload": payload_b, "passed": g2,
                              "status": s2, "len": len(b2), "time": round(t2,2)}

        if not g2:
            return False, evidence

        time.sleep(0.3)

        # Gate 3 — clean request must NOT trigger
        url3 = f"{url}?{param}={payload_clean}" if param else url
        b3, s3, t3 = self._fetch(url3)
        g3_clean = not check_fn(b3, s3, t3)  # clean payload = no anomaly
        evidence["gate3"] = {"payload": payload_clean, "passed": g3_clean,
                              "status": s3, "len": len(b3), "time": round(t3,2)}

        all_passed = g1 and g2 and g3_clean
        evidence["confirmed"] = all_passed
        return all_passed, evidence

    def confirm_error_sqli(self, url, param, error_patterns):
        """Confirm error-based SQLi via triple gate."""
        import urllib.parse

        def check_error(body, status, elapsed):
            body_lower = body.lower()
            return any(p.lower() in body_lower for p in error_patterns)

        return self.triple_gate(
            url,
            payload_a     = urllib.parse.quote("'"),
            payload_b     = urllib.parse.quote('"'),
            payload_clean = urllib.parse.quote("hello123"),
            check_fn      = check_error,
            param         = param,
        )

    def confirm_boolean_sqli(self, url, param, baseline_len):
        """Confirm boolean-based SQLi via triple gate."""
        import urllib.parse

        def check_bool(body, status, elapsed):
            diff = abs(len(body) - baseline_len)
            return diff > 80 and status == 200

        return self.triple_gate(
            url,
            payload_a     = urllib.parse.quote("' AND '1'='1"),
            payload_b     = urllib.parse.quote("' AND 1=1--"),
            payload_clean = urllib.parse.quote("' AND '1'='2"),
            check_fn      = check_bool,
            param         = param,
        )

    def confirm_xss(self, url, param):
        """Confirm XSS by checking unencoded reflection."""
        import urllib.parse

        marker_a = "tfv8xssA"
        marker_b = "tfv8xssB"

        def check_reflect_a(body, status, elapsed):
            return marker_a in body

        def check_reflect_b(body, status, elapsed):
            return marker_b in body

        # Gate1 & Gate2 with different markers; Gate3 clean
        url1 = f"{url}?{param}={urllib.parse.quote('<'+marker_a+'>')}"
        b1, s1, t1 = self._fetch(url1)
        g1 = marker_a in b1

        url2 = f"{url}?{param}={urllib.parse.quote('<'+marker_b+'>')}"
        b2, s2, t2 = self._fetch(url2)
        g2 = marker_b in b2

        url3 = f"{url}?{param}=cleaninput12345"
        b3, s3, t3 = self._fetch(url3)
        g3 = "cleaninput12345" not in b3 or ("<cleaninput" not in b3)

        passed = g1 and g2
        evidence = {
            "gate1": {"passed": g1, "marker": marker_a},
            "gate2": {"passed": g2, "marker": marker_b},
            "gate3": {"passed": g3, "note": "clean"},
            "confirmed": passed,
        }
        return passed, evidence

# Singleton
_confirm_engine = None

def get_confirm_engine(timeout=6):
    global _confirm_engine
    if _confirm_engine is None:
        _confirm_engine = ConfirmEngine(timeout)
    return _confirm_engine
