"""
TraceFoundry V8 - Core Baseline Engine
Builds response baseline before sending attack payloads.
Anti-FP: Never flag anomalies that exist in normal responses.
"""
import time
import urllib.request
import urllib.error
import statistics
import re

class BaselineEngine:
    def __init__(self, timeout=6):
        self.timeout   = timeout
        self.baselines = {}  # url -> metrics

    def _fetch(self, url, headers=None):
        h = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.0)"}
        if headers:
            h.update(headers)
        t0 = time.time()
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body    = r.read(65536).decode("utf-8", errors="ignore")
                elapsed = time.time() - t0
                return body, r.status, elapsed
        except urllib.error.HTTPError as e:
            elapsed = time.time() - t0
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, elapsed
        except Exception:
            return "", 0, time.time() - t0

    def build(self, url, n=4):
        """
        Send n benign requests and record baseline metrics.
        Returns baseline dict.
        """
        if url in self.baselines:
            return self.baselines[url]

        lengths  = []
        times    = []
        statuses = []
        errors   = []

        benign_params = ["", "?id=1", "?page=1", "?q=hello"]
        for i in range(n):
            probe = url + benign_params[i % len(benign_params)]
            body, status, elapsed = self._fetch(probe)
            lengths.append(len(body))
            times.append(elapsed)
            statuses.append(status)
            # Collect baseline error patterns
            for err in ["error","warning","exception","notice","fatal"]:
                if err in body.lower():
                    errors.append(err)
            time.sleep(0.2)

        baseline = {
            "url":         url,
            "len_min":     min(lengths) if lengths else 0,
            "len_max":     max(lengths) if lengths else 0,
            "len_avg":     statistics.mean(lengths) if lengths else 0,
            "len_stdev":   statistics.stdev(lengths) if len(lengths) > 1 else 0,
            "time_avg":    statistics.mean(times) if times else 0,
            "time_max":    max(times) if times else 0,
            "time_stdev":  statistics.stdev(times) if len(times) > 1 else 0,
            "status_mode": max(set(statuses), key=statuses.count) if statuses else 0,
            "baseline_errors": list(set(errors)),
            "sample_n":    n,
        }
        self.baselines[url] = baseline
        return baseline

    def is_anomalous_length(self, baseline, response_len, threshold=0.35):
        """Return True if length deviates significantly from baseline."""
        avg = baseline.get("len_avg", 0)
        if avg == 0:
            return False
        stdev = baseline.get("len_stdev", 0)
        # If baseline is already fluctuating >30%, skip length comparison
        if avg > 0 and stdev / avg > 0.30:
            return False
        deviation = abs(response_len - avg) / avg
        return deviation > threshold

    def is_anomalous_time(self, baseline, elapsed, delay_expected=4):
        """
        Return True if elapsed time suggests time-based injection.
        Uses jitter compensation.
        """
        avg     = baseline.get("time_avg", 0)
        max_jit = baseline.get("time_max", 0)
        stdev   = baseline.get("time_stdev", 0)
        # Threshold = baseline_max + stdev + 2s margin
        threshold = max_jit + stdev + 2.0
        return elapsed >= threshold and elapsed >= (delay_expected * 0.75)

    def has_new_error(self, baseline, response_body):
        """Return True if response has DB/app errors not in baseline."""
        body_lower = response_body.lower()
        for err in baseline.get("baseline_errors", []):
            # Already present in baseline — skip
            if err in body_lower:
                return False
        # Check for specific DB errors
        db_errors = [
            "sql syntax","mysql_fetch","pg::","ora-0","sqlite error",
            "sqlexception","odbc driver","microsoft ole db",
            "unclosed quotation","invalid query","syntax error near",
        ]
        return any(e in body_lower for e in db_errors)

# Singleton
_baseline_engine = None

def get_baseline_engine(timeout=6):
    global _baseline_engine
    if _baseline_engine is None:
        _baseline_engine = BaselineEngine(timeout)
    return _baseline_engine
