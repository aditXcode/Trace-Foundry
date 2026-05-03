"""
Trace Foundry V8.5 - Dependency Confusion Scanner
Checks DNS/Registry for internal package names that may be
vulnerable to dependency confusion attacks
Anti-FP: Must verify package exists internally AND not on public registry
"""
import urllib.request, urllib.error, json, re
from utils.display import section, ok, info, warn, bug_found

PUBLIC_REGISTRIES = {
    "npm":    "https://registry.npmjs.org/{package}",
    "pypi":   "https://pypi.org/pypi/{package}/json",
    "rubygems": "https://rubygems.org/api/v1/gems/{package}.json",
}

INTERNAL_PACKAGE_PATTERNS = [
    # JS/Node package files
    r'"name"\s*:\s*"(@[a-z0-9_\-]+/[a-z0-9_\-]+)"',   # scoped @company/pkg
    r'"dependencies"\s*:\s*\{([^}]+)\}',                  # deps block
    r'"devDependencies"\s*:\s*\{([^}]+)\}',
    r'require\s*\(\s*["\'](@[^"\']+)["\']',               # require('@company/pkg')
    r'from\s+["\'](@[^"\']+)["\']',                       # import from '@company/pkg'
    # Python
    r'(?m)^([a-z][a-z0-9_\-]{2,})\s*(?:==|>=|<=|~=)',   # requirements.txt
    r'install_requires\s*=\s*\[([^\]]+)\]',               # setup.py
]

class DepConfuseModule:
    def __init__(self, domain, timeout=8):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.5)"}

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read(131072).decode("utf-8", errors="ignore"), r.status
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code
        except: return "", 0

    def _extract_packages(self, content, file_type="js"):
        """Extract package names from package.json, requirements.txt, etc."""
        packages = set()
        for pat in INTERNAL_PACKAGE_PATTERNS:
            matches = re.findall(pat, content, re.I)
            for m in matches:
                if isinstance(m, str):
                    # Clean up
                    pkgs = re.split(r'[,\s"\'\n]+', m)
                    for p in pkgs:
                        p = p.strip().strip('"\'').split('@')[0].split('>')[0].split('<')[0].split('=')[0].strip()
                        if len(p) >= 3 and not p.startswith('#'):
                            packages.add(p)
        return packages

    def _check_public_registry(self, package, registry="npm"):
        """Check if package exists on public registry."""
        url = PUBLIC_REGISTRIES.get(registry,"").replace("{package}", package)
        if not url: return False
        body, status = self._fetch(url)
        if status == 200 and body:
            try:
                data = json.loads(body)
                return bool(data.get("name") or data.get("info"))
            except: return len(body) > 50
        return False

    def _is_internal_package(self, package):
        """Heuristics to identify likely internal packages."""
        # Scoped packages with company-like names
        if package.startswith("@") and "/" in package:
            return True
        # Internal naming conventions
        internal_hints = ["internal","private","corp","company","org","local",
                          "sdk","cli","lib","utils","common","shared","core","api"]
        pkg_lower = package.lower()
        if any(hint in pkg_lower for hint in internal_hints):
            return True
        # Very short names or names with domain fragments
        if self.domain.split(".")[0] in pkg_lower:
            return True
        return False

    def run(self):
        section("Dependency Confusion Scanner (npm|pypi|rubygems)")
        all_bugs = []

        # Files to check for package dependencies
        dep_files = [
            ("/package.json",       "npm"),
            ("/package-lock.json",  "npm"),
            ("/requirements.txt",   "pypi"),
            ("/setup.py",           "pypi"),
            ("/Pipfile",            "pypi"),
            ("/Gemfile",            "rubygems"),
            ("/composer.json",      "composer"),
            ("/yarn.lock",          "npm"),
            ("/pom.xml",            "maven"),
        ]

        for path, registry in dep_files:
            for scheme in ["https","http"]:
                url = f"{scheme}://{self.domain}{path}"
                content, status = self._fetch(url)
                if status != 200 or not content: continue

                info(f"Found: {url} — scanning for packages...")
                packages = self._extract_packages(content, registry)

                for pkg in list(packages)[:30]:
                    if not self._is_internal_package(pkg): continue

                    # Check if on public registry
                    on_public = self._check_public_registry(pkg, registry)
                    if not on_public:
                        all_bugs.append({
                            "type":     "Dependency Confusion — Internal Package Not on Public Registry",
                            "severity": "HIGH",
                            "url":      url,
                            "package":  pkg,
                            "registry": registry,
                            "evidence": f"Package '{pkg}' appears internal but not found on {registry}",
                            "detail":   "Attacker can publish malicious package with same name to public registry",
                            "impact":   "Supply chain attack — attacker code executes during npm install / pip install",
                        })
                        bug_found("DEPENDENCY CONFUSION", "HIGH", {
                            "Package":   pkg,
                            "Registry":  registry,
                            "File":      url,
                            "Evidence":  f"Not found on public {registry}",
                            "Impact":    "Publish same package name publicly → RCE during install",
                        })
                    else:
                        info(f"  {pkg} exists on {registry} — safe")
                break

        info(f"Dep confusion scan done — {len(all_bugs)} findings")
        if not all_bugs: ok("No dependency confusion vulnerabilities found ✓")
        return {"bugs": all_bugs}
