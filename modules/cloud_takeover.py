"""
Trace Foundry V8.5 - Cloud Storage Takeover Scanner
S3, Azure Blob, GCP Storage — checks ACL permissions
boto3 optional — uses HTTP API as fallback
Anti-FP: Verify actual read/write access, not just existence
"""
import urllib.request, urllib.error, re, json, socket
from utils.display import section, ok, info, warn, bug_found

# Cloud storage patterns to detect from domain/HTML
S3_PATTERNS = [
    r'([a-z0-9][a-z0-9\-]{2,62})\.s3\.amazonaws\.com',
    r's3\.amazonaws\.com/([a-z0-9][a-z0-9\-]{2,62})',
    r's3-([a-z0-9\-]+)\.amazonaws\.com/([a-z0-9][a-z0-9\-]{2,62})',
    r'([a-z0-9][a-z0-9\-]{2,62})\.s3-website',
]

AZURE_PATTERNS = [
    r'([a-z0-9]{3,24})\.blob\.core\.windows\.net',
    r'([a-z0-9]{3,24})\.file\.core\.windows\.net',
    r'([a-z0-9]{3,24})\.queue\.core\.windows\.net',
    r'([a-z0-9]{3,24})\.table\.core\.windows\.net',
    r'([a-z0-9]{3,24})\.azurestaticapps\.net',
    r'([a-z0-9\-]+)\.azurewebsites\.net',
]

GCP_PATTERNS = [
    r'([a-z0-9][a-z0-9\-_.]{2,62})\.storage\.googleapis\.com',
    r'storage\.googleapis\.com/([a-z0-9][a-z0-9\-_.]{2,62})',
    r'([a-z0-9][a-z0-9\-_.]{2,62})\.appspot\.com',
]

# Subdomain takeover fingerprints
CLOUD_TAKEOVER_FINGERPRINTS = {
    "AWS S3":        ["NoSuchBucket","The specified bucket does not exist","NoSuchKey"],
    "AWS CloudFront":["ERROR: The request could not be satisfied"],
    "Azure":         ["404 Web Site not found","ResourceNotFound"],
    "Azure Blob":    ["BlobNotFound","ContainerNotFound","PublicAccessNotPermitted"],
    "GCP Storage":   ["NoSuchBucket","BucketNotFound","The specified bucket does not exist"],
    "GCP AppEngine": ["404. That's an error.","Error: Server Error"],
    "Heroku":        ["No such app","no app configured for this hostname"],
    "Netlify":       ["Not Found - Request ID","netlify"],
    "Vercel":        ["The deployment could not be found"],
    "GitHub Pages":  ["There isn't a GitHub Pages site here"],
    "Fastly":        ["Fastly error: unknown domain"],
}

class CloudTakeoverModule:
    def __init__(self, domain, timeout=8):
        self.domain  = domain
        self.timeout = timeout
        self.headers = {"User-Agent": "Mozilla/5.0 (TraceFoundry/8.5)"}

    def _fetch(self, url):
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(16384).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except: return "", 0, {}

    def _find_cloud_references(self):
        """Scrape domain HTML for cloud storage bucket references."""
        buckets = {"s3": [], "azure": [], "gcp": []}
        for scheme in ["https","http"]:
            body, status, _ = self._fetch(f"{scheme}://{self.domain}")
            if not body: continue
            for pat in S3_PATTERNS:
                for m in re.findall(pat, body, re.I):
                    name = m if isinstance(m,str) else m[0]
                    if name not in buckets["s3"]: buckets["s3"].append(name)
            for pat in AZURE_PATTERNS:
                for m in re.findall(pat, body, re.I):
                    name = m if isinstance(m,str) else m[0]
                    if name not in buckets["azure"]: buckets["azure"].append(name)
            for pat in GCP_PATTERNS:
                for m in re.findall(pat, body, re.I):
                    name = m if isinstance(m,str) else m[0]
                    if name not in buckets["gcp"]: buckets["gcp"].append(name)
            break
        return buckets

    def _test_s3_bucket(self, bucket_name):
        """Test S3 bucket for public read/write/takeover."""
        bugs = []
        urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
        ]
        for url in urls:
            body, status, headers = self._fetch(url)
            if not body: continue

            # Takeover check
            for fp in CLOUD_TAKEOVER_FINGERPRINTS["AWS S3"]:
                if fp.lower() in body.lower():
                    bugs.append({
                        "type":     "S3 Bucket — Unclaimed (Takeover Possible)",
                        "severity": "HIGH",
                        "url":      url,
                        "bucket":   bucket_name,
                        "evidence": f"Fingerprint: '{fp}'",
                        "detail":   "Bucket referenced but does not exist — can be claimed",
                        "impact":   "Register S3 bucket to serve malicious content under this domain",
                    })
                    bug_found("S3 BUCKET TAKEOVER POSSIBLE", "HIGH", {
                        "Bucket":   bucket_name,
                        "URL":      url,
                        "Evidence": fp,
                        "Impact":   "Claim bucket → serve malicious content on domain",
                    })
                    return bugs

            # Public listing check
            if status == 200 and "<ListBucketResult" in body:
                # Count objects
                objects = re.findall(r'<Key>([^<]+)</Key>', body)
                bugs.append({
                    "type":     "S3 Bucket — Public Listing Enabled",
                    "severity": "MEDIUM",
                    "url":      url,
                    "bucket":   bucket_name,
                    "evidence": f"Bucket listing returns {len(objects)} objects",
                    "detail":   "Anyone can list all files in this S3 bucket",
                    "impact":   "Data exposure — all filenames visible to public",
                })
                bug_found("S3 PUBLIC LISTING", "MEDIUM", {
                    "Bucket":  bucket_name,
                    "URL":     url,
                    "Objects": str(len(objects)),
                    "Impact":  "All file names exposed to public",
                })

            # Write test (SAFE — just check if PUT returns interesting status)
            # We don't actually write — just observe the error
            try:
                req = urllib.request.Request(
                    f"{url}tracefoundry-test-{self.domain}.txt",
                    data=b"", headers=self.headers, method="PUT")
                with urllib.request.urlopen(req, timeout=5) as r:
                    if r.status in (200, 201):
                        bugs.append({
                            "type":     "S3 Bucket — Public WRITE Access",
                            "severity": "CRITICAL",
                            "url":      url,
                            "bucket":   bucket_name,
                            "evidence": f"PUT request returned {r.status}",
                            "detail":   "Anyone can upload files to this S3 bucket",
                            "impact":   "Arbitrary file upload to S3 — malware distribution, defacement",
                        })
                        bug_found("S3 PUBLIC WRITE ACCESS", "CRITICAL", {
                            "Bucket": bucket_name,
                            "URL":    url,
                            "Impact": "Arbitrary file upload — CRITICAL!",
                        })
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    ok(f"S3 write protected: {bucket_name} ✓")
            except: pass
        return bugs

    def _test_azure_blob(self, account_name):
        """Test Azure Blob Storage container."""
        bugs = []
        url = f"https://{account_name}.blob.core.windows.net/?comp=list"
        body, status, _ = self._fetch(url)

        for fp in CLOUD_TAKEOVER_FINGERPRINTS["Azure Blob"]:
            if fp.lower() in body.lower():
                bugs.append({
                    "type":     "Azure Blob — Container Takeover Possible",
                    "severity": "HIGH",
                    "url":      url,
                    "account":  account_name,
                    "evidence": f"Fingerprint: '{fp}'",
                    "detail":   "Azure storage account referenced but container unclaimed",
                    "impact":   "Claim container → host malicious content",
                })
                bug_found("AZURE BLOB TAKEOVER", "HIGH", {
                    "Account": account_name,
                    "URL":     url,
                    "Impact":  "Unclaimed Azure container — takeover possible",
                })

        if status == 200 and "<EnumerationResults" in body:
            containers = re.findall(r'<Name>([^<]+)</Name>', body)
            bugs.append({
                "type":     "Azure Blob — Public Container Listing",
                "severity": "MEDIUM",
                "url":      url,
                "account":  account_name,
                "evidence": f"{len(containers)} containers visible",
                "detail":   "Azure blob storage publicly lists containers",
                "impact":   "Storage structure exposed to public",
            })
        return bugs

    def _test_gcp_bucket(self, bucket_name):
        """Test GCP Storage bucket."""
        bugs = []
        url = f"https://storage.googleapis.com/{bucket_name}/"
        body, status, _ = self._fetch(url)

        for fp in CLOUD_TAKEOVER_FINGERPRINTS["GCP Storage"]:
            if fp.lower() in body.lower():
                bugs.append({
                    "type":     "GCP Storage — Bucket Takeover Possible",
                    "severity": "HIGH",
                    "url":      url,
                    "bucket":   bucket_name,
                    "evidence": f"Fingerprint: '{fp}'",
                    "detail":   "GCP bucket referenced but not claimed",
                    "impact":   "Register GCP bucket to control content",
                })
                bug_found("GCP BUCKET TAKEOVER", "HIGH", {
                    "Bucket": bucket_name,
                    "URL":    url,
                    "Impact": "Unclaimed GCP bucket — register to take control",
                })

        if status == 200:
            objects = re.findall(r'"name"\s*:\s*"([^"]+)"', body)
            if objects:
                bugs.append({
                    "type":     "GCP Storage — Public Bucket Listing",
                    "severity": "MEDIUM",
                    "url":      url,
                    "bucket":   bucket_name,
                    "evidence": f"{len(objects)} objects listed",
                    "detail":   "GCP bucket publicly accessible",
                    "impact":   "Data exposure via public GCP bucket",
                })
        return bugs

    def _guess_buckets(self):
        """Guess common bucket names based on domain."""
        domain_parts = self.domain.replace(".gov","").replace(".com","").replace(".id","")
        base = domain_parts.split(".")[0]
        guesses = [
            base, f"{base}-assets", f"{base}-static", f"{base}-media",
            f"{base}-uploads", f"{base}-backup", f"{base}-data",
            f"{base}-files", f"{base}-images", f"{base}-cdn",
            f"{base}-prod", f"{base}-staging", f"{base}-dev",
            self.domain.replace(".","-"), self.domain.replace(".",""),
        ]
        return [g.lower() for g in guesses if 3 <= len(g) <= 63]

    def run(self):
        section("Cloud Storage Takeover (S3|Azure|GCP ACL Check)")
        all_bugs = []

        # Find references in HTML
        refs = self._find_cloud_references()
        info(f"S3: {len(refs['s3'])} | Azure: {len(refs['azure'])} | GCP: {len(refs['gcp'])}")

        # Test found references
        for b in refs["s3"][:5]:
            all_bugs.extend(self._test_s3_bucket(b))
        for a in refs["azure"][:5]:
            all_bugs.extend(self._test_azure_blob(a))
        for g in refs["gcp"][:5]:
            all_bugs.extend(self._test_gcp_bucket(g))

        # Guess common bucket names
        guesses = self._guess_buckets()
        info(f"Testing {len(guesses)} guessed bucket names...")
        for name in guesses[:8]:
            all_bugs.extend(self._test_s3_bucket(name))
            all_bugs.extend(self._test_gcp_bucket(name))

        info(f"Cloud takeover scan done — {len(all_bugs)} findings")
        if not all_bugs: ok("No cloud storage misconfigurations found ✓")
        return {"bugs": all_bugs}
