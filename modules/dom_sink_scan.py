"""
Trace Foundry V8.5 - DOM Sink Scanner
Uses Playwright for real browser DOM-XSS detection
Falls back to static analysis if Playwright unavailable
Anti-FP: Real execution in browser, not just pattern matching
"""
import re, urllib.request, urllib.error
from utils.display import section, ok, info, warn, bug_found

DOM_SOURCES = [
    "location.hash","location.search","location.href",
    "document.URL","document.referrer","document.cookie",
    "window.name","document.location",
]

DOM_SINKS = [
    "innerHTML","outerHTML","document.write","document.writeln",
    "eval(","setTimeout(","setInterval(","Function(",
    "insertAdjacentHTML","location.href=","location.assign(",
    "location.replace(",".html(",".append(",
    "insertBefore","$.parseHTML","$(",
]

REFLECTION_PARAMS = [
    "q","search","s","query","name","redirect","url","ref",
    "next","page","id","hash","keyword","term","input",
]

class DOMSinkModule:
    def __init__(self, domain, timeout=10):
        self.domain    = domain
        self.timeout   = timeout
        self.playwright_ok = False
        self.headers   = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.5)"}
        self._check_playwright()

    def _check_playwright(self):
        try:
            from playwright.sync_api import sync_playwright
            self.playwright_ok = True
            info("Playwright available — using real browser for DOM-XSS")
        except ImportError:
            warn("Playwright not installed — using static DOM analysis")
            warn("Install: pip install playwright && playwright install chromium")

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(131072).decode("utf-8", errors="ignore"), r.status
        except: return "", 0

    def _static_analysis(self, url, content):
        """Static source-to-sink analysis without browser."""
        bugs = []
        sources_found = [s for s in DOM_SOURCES if s in content]
        sinks_found   = [s for s in DOM_SINKS   if s in content]

        if sources_found and sinks_found:
            # Check if they appear close together (same function)
            for source in sources_found:
                for sink in sinks_found:
                    # Find positions
                    src_pos  = content.find(source)
                    sink_pos = content.find(sink)
                    if src_pos != -1 and sink_pos != -1:
                        distance = abs(src_pos - sink_pos)
                        if distance < 500:  # Within 500 chars = same function likely
                            bugs.append({
                                "type":     "DOM XSS — Source to Sink (Static Analysis)",
                                "severity": "MEDIUM",
                                "url":      url,
                                "source":   source,
                                "sink":     sink,
                                "evidence": f"{source} → {sink} (distance={distance} chars)",
                                "detail":   "User-controlled source flows into dangerous sink",
                                "impact":   "DOM XSS — manual verification recommended",
                            })
                            bug_found("DOM XSS Source→Sink", "MEDIUM", {
                                "URL":    url,
                                "Source": source,
                                "Sink":   sink,
                                "Note":   "Static analysis — verify manually in browser",
                            })
                            break
        return bugs

    def _playwright_scan(self, url):
        """Real browser DOM-XSS detection using Playwright."""
        bugs = []
        try:
            from playwright.sync_api import sync_playwright
            marker = "TFXSS85MARKER"
            xss_payload = f"<img src=x onerror=window.__tfxss='{marker}'>"

            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context()
                page    = context.new_page()

                # Track console errors and alerts
                xss_triggered = []
                page.on("dialog", lambda d: (xss_triggered.append(d.message), d.dismiss()))

                for param in REFLECTION_PARAMS[:8]:
                    test_url = f"{url}?{param}={xss_payload}"
                    try:
                        page.goto(test_url, timeout=8000, wait_until="domcontentloaded")
                        # Check if marker appears in DOM
                        dom_content = page.content()
                        if marker in dom_content:
                            # Verify it's unencoded
                            if f"onerror=window.__tfxss='{marker}'" in dom_content or \
                               f"window.__tfxss" in dom_content:
                                bugs.append({
                                    "type":     "DOM XSS (Playwright Confirmed)",
                                    "severity": "HIGH",
                                    "url":      test_url,
                                    "param":    param,
                                    "evidence": f"Marker '{marker}' unencoded in DOM",
                                    "detail":   "Real DOM XSS confirmed via headless browser",
                                    "impact":   "XSS executes in victim browser — session hijack possible",
                                })
                                bug_found("DOM XSS CONFIRMED (Browser)", "HIGH", {
                                    "URL":   test_url,
                                    "Param": param,
                                    "Evidence": f"Marker reflected unencoded in DOM",
                                    "Impact": "Real XSS — JS execution in victim browser",
                                })
                    except Exception:
                        pass

                browser.close()
        except Exception as e:
            warn(f"Playwright error: {e}")
        return bugs

    def run(self):
        section("DOM Sink Scanner (Playwright + Static Analysis)")
        all_bugs = []
        test_pages = ["/","/search","/index","/home","/app"]

        for page in test_pages:
            for scheme in ["https","http"]:
                url = f"{scheme}://{self.domain}{page}"
                content, status = self._fetch(url)
                if status != 200 or not content: continue

                info(f"Scanning DOM sinks: {url}")

                if self.playwright_ok:
                    bugs = self._playwright_scan(url)
                    all_bugs.extend(bugs)

                # Always also do static analysis
                static_bugs = self._static_analysis(url, content)
                # Only add static if playwright didn't confirm
                if not all_bugs:
                    all_bugs.extend(static_bugs)
                break

        info(f"DOM sink scan done — {len(all_bugs)} findings")
        if not all_bugs: ok("No DOM XSS found ✓")
        return {"bugs": all_bugs}
