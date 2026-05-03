"""
Trace Foundry V8.5 - JS Entropy Scanner
Shannon Entropy analysis on strings in .js files
High entropy = likely secret/token/key
Anti-FP: Entropy threshold + pattern match + length filter
"""
import urllib.request, urllib.error, re, math, json
from utils.display import section, ok, info, warn, bug_found

# Known false positive patterns to skip
FP_PATTERNS = [
    r'^[a-f0-9]{6}$',           # hex color
    r'^#[a-f0-9]{3,6}$',        # CSS color
    r'example|test|sample|demo|placeholder|lorem|ipsum',
    r'^[0-9.]+$',               # version numbers
    r'node_modules|webpack|babel|eslint',
]

SECRET_PATTERNS = {
    "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
    "AWS Secret":        r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}',
    "GitHub Token":      r'ghp_[0-9a-zA-Z]{36}',
    "GitHub OAuth":      r'gho_[0-9a-zA-Z]{36}',
    "Slack Token":       r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase":          r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "Stripe Secret":     r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Public":     r'pk_live_[0-9a-zA-Z]{24,}',
    "SendGrid":          r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    "Twilio":            r'SK[0-9a-fA-F]{32}',
    "NPM Token":         r'npm_[A-Za-z0-9]{36}',
    "JWT Token":         r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Private Key":       r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    "SSH Key":           r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Generic Secret":    r'(?i)(secret|api_secret|client_secret)\s*[:=]\s*["\'][^"\']{10,}["\']',
    "Generic Password":  r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']',
    "Bearer Token":      r'[Bb]earer\s+[A-Za-z0-9\-_.]{20,}',
    "Basic Auth":        r'[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}',
    "Heroku API Key":    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "Mailgun":           r'key-[0-9a-zA-Z]{32}',
    "Mapbox Token":      r'pk\.[a-zA-Z0-9]{60,}',
    "Cloudinary":        r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@',
}

def shannon_entropy(s):
    """Calculate Shannon entropy of a string."""
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    ln = len(s)
    for count in freq.values():
        p = count / ln
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(s, threshold=4.2):
    """High entropy strings (>4.2 bits) likely contain secrets."""
    if len(s) < 16: return False
    return shannon_entropy(s) >= threshold

def is_false_positive(s):
    """Skip known non-secret patterns."""
    for pat in FP_PATTERNS:
        if re.search(pat, s, re.I):
            return True
    # Skip if mostly same character
    if len(set(s)) < 4: return True
    return False

class JSEntropyModule:
    def __init__(self, domain, timeout=6):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.5)"}

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(524288).decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(131072).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except: return "", 0

    def _find_js_files(self):
        js_files = set()
        for scheme in ["https","http"]:
            html, status = self._fetch(f"{scheme}://{self.domain}")
            if not html: continue
            for match in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html):
                if match.startswith("http"):
                    js_files.add(match)
                elif match.startswith("//"):
                    js_files.add("https:" + match)
                elif match.startswith("/"):
                    js_files.add(f"{scheme}://{self.domain}{match}")
            break

        # Common JS paths
        for path in ["/app.js","/main.js","/bundle.js","/app.min.js",
                     "/static/js/main.js","/assets/js/app.js",
                     "/js/app.js","/dist/bundle.js",
                     "/build/static/js/main.chunk.js",
                     "/static/js/bundle.js","/js/main.js",
                     "/assets/app.js","/public/js/app.js"]:
            js_files.add(f"https://{self.domain}{path}")

        return list(js_files)[:25]

    def _scan_entropy(self, content, js_url):
        """Find high-entropy strings in JS content."""
        bugs = []
        # Extract all quoted strings
        strings = re.findall(r'["\']([A-Za-z0-9+/=_\-]{16,120})["\']', content)
        seen = set()
        for s in strings:
            if s in seen: continue
            seen.add(s)
            if is_false_positive(s): continue
            if is_high_entropy(s, threshold=4.2):
                entropy_val = shannon_entropy(s)
                bugs.append({
                    "type":     "High-Entropy String in JS (Possible Secret)",
                    "severity": "MEDIUM",
                    "url":      js_url,
                    "value":    s[:60],
                    "entropy":  round(entropy_val, 2),
                    "evidence": f"Shannon entropy={entropy_val:.2f} bits (threshold=4.2)",
                    "detail":   "High-entropy string may be API key, token, or secret",
                    "impact":   "Exposed credential in client-side JS",
                })
        return bugs

    def _scan_patterns(self, content, js_url):
        """Regex pattern matching for known secret formats."""
        bugs = []
        for label, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                val = str(match)[:80]
                # Skip obvious test values
                if any(fp in val.lower() for fp in [
                    "example","test","your-","change-me","xxx","****","placeholder"
                ]): continue
                bugs.append({
                    "type":     f"Hardcoded Secret: {label}",
                    "severity": "CRITICAL" if label in (
                        "AWS Access Key","GitHub Token","Stripe Secret",
                        "Private Key","SSH Key","Firebase") else "HIGH",
                    "url":      js_url,
                    "secret_type": label,
                    "value":    val,
                    "evidence": f"Pattern match: {label}",
                    "detail":   f"Real {label} found in public JS file",
                    "impact":   "Secret exposed to anyone who views JS source",
                })
                bug_found(f"SECRET IN JS: {label}",
                    "CRITICAL" if "Key" in label or "Token" in label else "HIGH", {
                    "File":    js_url,
                    "Type":    label,
                    "Value":   val[:50],
                    "Impact":  "Real credential exposed in client-side JavaScript",
                })
        return bugs

    def run(self):
        section("JS Entropy Scanner (Shannon + Pattern Matching)")
        all_bugs = []
        js_files = self._find_js_files()
        info(f"JS files to analyze: {len(js_files)}")
        endpoints_found = []

        for js_url in js_files:
            content, status = self._fetch(js_url)
            if not content or len(content) < 50 or status not in (200,):
                continue

            info(f"Analyzing: {js_url} ({len(content)//1024}KB)")

            # Pattern-based (high priority)
            bugs = self._scan_patterns(content, js_url)
            all_bugs.extend(bugs)

            # Entropy-based (medium priority) — only if no pattern hit
            if not bugs:
                entropy_bugs = self._scan_entropy(content, js_url)
                # Only keep top 3 highest entropy per file
                entropy_bugs.sort(key=lambda x: x.get("entropy",0), reverse=True)
                all_bugs.extend(entropy_bugs[:3])

            # Extract API endpoints
            for pat in [
                r'["\](/api/[a-zA-Z0-9/_\-\.]+)["\']',
                r'fetch\s*\(\s*["\']([^"\']+)["\']',
                r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
                r'baseURL\s*[:=]\s*["\']([^"\']{5,})["\']',
            ]:
                for match in re.findall(pat, content):
                    ep = match if isinstance(match, str) else match[0]
                    if len(ep) > 3 and not ep.endswith((".png",".jpg",".css",".ico")):
                        endpoints_found.append(ep)

        deduped = list(dict.fromkeys(endpoints_found))
        if deduped:
            info(f"API endpoints from JS: {len(deduped)}")

        # Deduplicate bugs
        seen = set()
        final = []
        for b in all_bugs:
            k = b.get("url","") + b.get("value","")[:20]
            if k not in seen:
                seen.add(k)
                final.append(b)

        info(f"JS entropy scan done — {len(final)} findings")
        if not final: ok("No secrets found in JS files ✓")
        return {"bugs": final, "endpoints_found": deduped}
