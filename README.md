# Trace Foundry V8.5

Bug Bounty Reconnaissance and Vulnerability Scanner

Trace Foundry is an open-source security research tool designed for authorized bug bounty hunting and penetration testing. It combines 40 specialized scanning modules with 8 Anti-False-Positive engines to deliver accurate, actionable findings across any web target.

---

## Table of Contents

1. Requirements
2. Installation
3. Quick Start
4. Commands
5. Scan Modes
6. Options
7. Modules
8. Anti-FP Engine Architecture
9. Output and Reports
10. Legal Disclaimer

---

## Requirements

- Python 3.8 or higher
- pip (Python package manager)
- Internet connection
- Chromium — required only for DOM-XSS scanning via Playwright

---

## Installation

Install Python dependencies:

    pip install -r requirements.txt

Install Chromium for the DOM-XSS module:

    playwright install chromium

Verify installation:

    python3 main.py --help

Note: All core modules work without external dependencies using the Python standard library. External libraries such as httpx, playwright, and rich enhance functionality but are optional. The tool falls back to stdlib equivalents when they are not installed.

---

## Quick Start

    python3 main.py target.com start
    python3 main.py target.com quick
    python3 main.py target.com start --resume

---

## Commands

    python3 main.py <domain> <mode> [options]

Examples:

    python3 main.py nasa.gov start
    python3 main.py globe.gov vuln --threads 60
    python3 main.py nsc.nasa.gov stealth --timeout 10
    python3 main.py nspires.nasaprs.com api
    python3 main.py target.go.id recon --out json
    python3 main.py app.target.ac.id cms --resume

Domain format — all TLDs are supported:

    target.com
    target.gov
    target.my
    target.go.id
    sub.target.ac.id
    sub.target.co.uk

---

## Scan Modes

    Mode        Modules   Description
    --------    -------   --------------------------------------------------
    start       40        Complete scan — recon and all vulnerability checks
    quick       13        Fast scan, approximately 3 minutes
    recon       12        Reconnaissance, passive recon, and cloud discovery
    vuln        23        All vulnerability scanning modules
    stealth      9        Low-noise scan with minimal footprint on target
    api         12        API security — REST, GraphQL, and OAuth
    inject       9        Injection attacks — SQLi, XSS, LFI, CMDi, XXE, SSRF
    passive      1        Passive only — crt.sh, Wayback Machine, DNS history
    cms          4        CMS deep scan — WordPress, Drupal, Joomla, Laravel
    creds        4        Credential and secret leak detection
    oob          4        Out-of-band blind vulnerability testing
    cloud        4        Cloud storage misconfiguration — S3, Azure, GCP
    js           4        JavaScript analysis — entropy, DOM sinks, dependencies
    oauth        4        OAuth 2.0 security audit

---

## Options

    Option               Default    Description
    ------------------   -------    ----------------------------------------
    --threads <n>        40         Number of concurrent threads
    --timeout <n>        6          Request timeout in seconds
    --wordlist <file>    built-in   Custom subdomain wordlist file path
    --out json|html|both both       Output report format
    --resume             off        Resume scan from last saved state

---

## Modules

### Reconnaissance Modules

    passive_recon
        Subdomains via certificate transparency logs (crt.sh)
        Historical URLs via Wayback Machine CDX API
        DNS history via HackerTarget
        Google dork query suggestions for manual investigation

    dns
        A records, MX records, TXT records
        Reverse DNS lookup, CNAME aliases

    whois
        Registrar information, expiry date
        Name servers, registrant contact data

    ssl
        Expired or near-expiry certificates
        Weak TLS protocols (TLS 1.0, TLS 1.1)
        Self-signed certificates, weak cipher suites

    waf
        WAF detection with confidence scoring
        Supported: Cloudflare, AWS WAF, Akamai, Imperva,
        ModSecurity, F5 BIG-IP, Sucuri, Fastly, Barracuda

    subdomains
        Brute-force enumeration using 200+ entry built-in wordlist
        Parallel threading with configurable thread count

    ports
        28 common ports with TCP banner grabbing
        Service identification and version detection

    headers
        HTTP response header analysis
        Technology stack fingerprinting

    emails
        Email addresses from homepage, robots.txt, security.txt
        Contact and about pages

### Discovery Modules

    cms_scanner
        WordPress: user enumeration (ID 1 to 20), plugin version
        disclosure via readme.txt, REST API user listing
        Drupal: admin panel, changelog version disclosure
        Joomla: administrator panel, configuration backup files
        Laravel: .env file, Telescope and Horizon dashboards

    header_audit
        Security header presence and configuration scoring (grade A to F)
        Checks: HSTS, CSP (unsafe-inline detection), X-Frame-Options,
        X-Content-Type-Options, Referrer-Policy, Permissions-Policy

    paths
        50+ sensitive paths: .env, .git/HEAD, phpinfo.php
        Backup archives, admin panels, Swagger/OpenAPI docs
        Debug endpoints, configuration files

    credential_checker
        Leaked credentials in 50+ file types
        Exposed .git repository with full source download risk
        Default credential testing on login endpoints
        Hardcoded secrets: AWS keys, GitHub tokens, JWT tokens

    js_entropy
        Shannon entropy analysis — strings above 4.2 bits flagged
        Regex pattern matching for 20+ secret types
        Covers: AWS keys, GitHub tokens, Stripe keys, JWT, SSH keys,
        Google API keys, SendGrid, Twilio, Mapbox, Cloudinary
        API endpoint extraction from JS source

### Vulnerability Modules

    sqli
        Error-based: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
        Boolean-based blind: response length differential analysis
        Time-based blind: SLEEP / pg_sleep / WAITFOR delay confirmation
        All findings require Triple Gate confirmation before reporting

    xss
        Reflected XSS: probe then payload, unencoded reflection check
        DOM XSS: source-to-sink flow analysis (document.URL to innerHTML)
        POST XSS: form submission reflection testing
        Context detection: HTML body, HTML attribute, JS string

    lfi_rfi
        Path traversal with depth 1 to 7 (../etc/passwd)
        PHP filter wrapper: php://filter/convert.base64-encode
        /proc/self/environ and /proc/self/cmdline
        Windows path traversal and null byte injection

    cmdi_ssti
        OS command injection: Linux (id, whoami) and Windows (whoami)
        Time-based blind confirmation: sleep 3 and timeout 3
        SSTI: Jinja2 (7*7=49), Twig, ERB, Freemarker, SpEL, Razor

    xxe
        Classic file read: /etc/passwd and windows/win.ini
        XXE via SSRF to AWS metadata endpoint
        WSDL and SOAP endpoint exposure
        Entity expansion detection

    ssrf
        AWS metadata: 169.254.169.254 IAM credentials
        GCP metadata, DigitalOcean metadata, Alibaba metadata
        Internal service discovery: localhost, 127.0.0.1
        file:// and gopher:// protocol testing

    cors
        Origin reflection with Access-Control-Allow-Credentials: true
        Wildcard with credentials (critical misconfiguration)
        Null origin acceptance via sandbox iframe bypass

    idor
        Sequential numeric ID enumeration (ID+1, ID-1, ID=1)
        GET parameter tampering with common param names
        Unauthenticated REST endpoint data access check

    redirect
        15 redirect parameter names tested across 8 endpoints
        Payloads: direct URL, double slash, backslash, encoded

    ratelimit
        Login, forgot-password, and search endpoint testing
        10 parallel requests sent to detect missing rate limits
        Checks for HTTP 429 response absence

    methods
        PUT: file upload attempt with success code detection
        DELETE: deletion attempt on common endpoints
        TRACE: Cross-Site Tracing (XST) vulnerability
        Allow header enumeration via OPTIONS

    race_condition
        15-thread barrier-synchronized parallel request sender
        Targets: coupon redemption, transfer, vote, checkout, register
        Detects multiple successful responses from simultaneous requests

    cache_poison
        X-Forwarded-Host injection with reflection detection
        Cache deception via /profile/x.css static-looking paths
        CDN behavior analysis

    file_upload
        PHP webshell upload with image/jpeg content-type bypass
        SVG file with embedded XSS script tag
        Double extension bypass: shell.php.jpg

### Advanced Modules

    graphql_scanner
        Introspection query with structural JSON confirmation
        Alias-based query duplication (rate limit bypass)
        Unlimited query depth testing (15-level nested query)
        Field suggestion schema inference
        GraphQL IDE/playground public access
        Batch query acceptance (DoS amplification)

    oob_server
        Log4Shell (CVE-2021-44228) via 6 injectable HTTP headers
        Blind SSRF confirmation via interact.sh OOB callback
        Blind XSS planting in contact/feedback forms with UUID tracking

    proto_pollute
        __proto__[key]=value via URL query string
        constructor[prototype][key]=value via URL query string
        JSON body injection: {"__proto__": {"key": "value"}}
        Admin privilege escalation via {"__proto__": {"admin": true}}

    dom_sink_scan
        Real DOM XSS detection using Playwright headless Chromium
        Marker injection and DOM content verification
        Static fallback: source-to-sink proximity analysis
        Sources: location.hash, location.search, document.URL
        Sinks: innerHTML, eval, document.write, setTimeout

    dep_confuse
        Extracts package names from package.json, requirements.txt,
        setup.py, Pipfile, Gemfile, composer.json
        Cross-checks against npm, PyPI, and RubyGems public registries
        Flags internal-looking packages not found publicly

    oauth_audit
        OIDC discovery via /.well-known/openid-configuration
        redirect_uri bypass with evil.com and scheme variations
        Missing state parameter (CSRF on OAuth flow)
        Implicit flow token leakage in redirect URL

    cloud_takeover
        S3: public listing, public write access, unclaimed bucket
        GCP: public bucket listing, unclaimed bucket fingerprint
        Azure: container listing, unclaimed storage account
        Guesses 14 common bucket names based on domain

    api_scanner
        JWT algorithm none vulnerability (signature bypass)
        JWT sensitive data in payload (password, role, admin fields)
        OpenAPI/Swagger specification publicly accessible
        Mass assignment risk detection in JSON responses

    tech_scan
        PHP: LFI, phpMyAdmin exposure, phpinfo disclosure
        Django: DEBUG=True, SECRET_KEY exposure, admin panel
        Flask: Werkzeug interactive debugger console (RCE)
        Spring: Actuator endpoints, WEB-INF directory, stack traces
        ASP.NET: web.config exposure, ELMAH log viewer
        WordPress: user enumeration, xmlrpc.php enabled
        Node.js: error stack traces, prototype pollution paths
        Go: pprof profiling endpoint exposure

    takeover
        CNAME fingerprinting for 15+ cloud services
        GitHub Pages, Heroku, Netlify, Vercel, AWS S3
        Azure Web Apps, Fastly, Shopify, Zendesk, HubSpot

---

## Anti-FP Engine Architecture

Eight dedicated Anti-False-Positive engines run before any finding is reported.

    core/
      baseline_engine.py
          Sends 3 to 5 clean benign requests before attack payloads
          Records length, response time, status codes, and baseline errors
          Any anomaly present in baseline is excluded from findings

      confirm_engine.py
          Triple Gate validation for every potential finding:
            Gate 1 — Indication:  response changes or anomaly detected
            Gate 2 — Logic Check: different payload produces same anomaly
            Gate 3 — Clean Control: benign payload does NOT trigger anomaly
          All 3 gates must pass for a bug to be confirmed and reported

      antifp_engines.py
          DiffEngine
              Structural response comparison after noise removal
              Strips timestamps, UUIDs, CSRF tokens, request IDs before diff

          TimeSyncEngine
              Calibrates network jitter with 5 clean requests
              Time-based SQLi only flagged if delay > baseline_max + stdev + 2s
              Binary delay confirmation: 2s, 4s, 6s must be roughly linear

          ErrorSignatureDB
              DBMS-specific error patterns only — no generic "error" matching
              Covers MySQL, PostgreSQL, MSSQL, Oracle, SQLite signatures
              Baseline error comparison to eliminate pre-existing errors

          ContextInjector
              Correct encoding per injection context
              URL parameter, JSON body, XML body, HTTP header, multipart

          WAFInterceptor
              Detects WAF blocks (403, 406, 429, 503) before flagging bug
              Checks response body and headers for WAF fingerprints
              Skips result if WAF block detected to avoid false positives

          SessionRotator
              Multi-session IDOR testing with owner and attacker accounts
              IDOR only confirmed if: owner=200, attacker=200, unauth=401/403
              Public resources automatically excluded from IDOR findings

          OOBCorrelator
              UUID-based callback matching for blind vulnerability detection
              Strict 60-second time window for callback acceptance
              Double-confirm option requires two separate callbacks

          ParameterDiscovery
              Hidden parameter fuzzing with 30+ common parameter names
              Response difference threshold of 20% to flag hidden params
              Injected header testing for admin bypass detection

      system_components.py
          AdaptiveRateLimiter
              Tracks 429/503 responses and applies exponential backoff
              Smart jitter: random 0.5x to 2.0x delay multiplier
              Auto-recovery: gradually reduces delay on successful responses

          HTTP2Fetcher
              Uses httpx with HTTP/2 support when available
              Falls back to urllib for HTTP/1.1 automatically
              Integrated with AdaptiveRateLimiter

          HeaderRotator
              Pool of 10 realistic User-Agent strings
              Randomizes Accept, Accept-Language, Cache-Control headers

          WAFFingerprinter
              Advanced WAF detection with confidence scoring
              Returns WAF name, confidence level, and evasion hints

          StatePersistence
              SQLite database stores completed module results
              Enables pause and resume with --resume flag
              Persists all confirmed bugs across sessions

---

## Output and Reports

Reports are saved automatically to the reports/ directory after each scan.

    reports/
      target.com_20260428_120000.json     Raw findings in JSON format
      target.com_20260428_120000.html     Styled HTML report with dark theme
      target.com_state.db                 SQLite state database for --resume

The HTML report contains:
- Target overview: IP address, WAF, SSL grade, technology stack
- All confirmed bugs sorted by severity (Critical to Info)
- Evidence and proof-of-concept for each finding
- Severity distribution with visual bar chart
- Remediation guidance per finding type

---

## Legal Disclaimer

This tool is intended exclusively for authorized security testing, vulnerability research, and bug bounty programs where explicit written permission has been granted by the target organization.

Using this tool against any system without proper authorization is illegal under applicable law, including but not limited to the Computer Fraud and Abuse Act (United States), the Computer Misuse Act (United Kingdom), Undang-Undang ITE Pasal 30 (Indonesia), and equivalent legislation in other jurisdictions.

The developers of Trace Foundry assume no responsibility or liability for any illegal, unauthorized, or unethical use of this tool. By downloading, installing, or using Trace Foundry, you acknowledge that you have read this disclaimer and confirm that you hold proper authorization for every target you scan.

Authorized use includes:
- Programs listed on Bugcrowd, HackerOne, Intigriti, or equivalent platforms
- Systems you own or have received explicit written permission to test
- Designated Capture The Flag environments

When in doubt about whether a target is in scope, do not scan it.