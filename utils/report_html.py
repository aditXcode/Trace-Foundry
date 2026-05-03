"""
Trace Foundry v2 - HTML Report Generator
Dark-theme report with all modules and bug summary
"""

def _sev_badge(sev):
    colors = {"CRITICAL":"#f85149","HIGH":"#f85149","MEDIUM":"#d29922","LOW":"#58a6ff","INFO":"#8b949e"}
    bg     = {"CRITICAL":"#3d0000","HIGH":"#3d1a00","MEDIUM":"#3d2d00","LOW":"#1c3a5e","INFO":"#21262d"}
    c = colors.get(sev,"#8b949e"); b = bg.get(sev,"#21262d")
    return f'<span style="background:{b};color:{c};padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600">{sev}</span>'

def generate_html_report(data, output_path):
    r      = data.get("results", {})
    domain = data.get("target","unknown")
    ts     = data.get("timestamp","")[:19].replace("T"," ")
    bugs   = data.get("all_bugs", [])

    dns        = r.get("dns", {})
    subdomains = r.get("subdomains", [])
    ports      = r.get("ports", [])
    paths      = r.get("paths", [])
    emails     = r.get("emails", [])
    waf        = r.get("waf", {})
    ssl        = r.get("ssl", {})
    ha         = r.get("header_audit", {})
    js         = r.get("js", {})
    whois      = r.get("whois", {})

    sensitive_paths = [p for p in paths if p.get("sensitive")]

    sev_counts = {}
    for b in bugs:
        s = b.get("severity","INFO")
        sev_counts[s] = sev_counts.get(s,0) + 1

    def rows(items, cols):
        if not items: return '<tr><td colspan="99" style="color:#8b949e;text-align:center">None found</td></tr>'
        return "".join("<tr>" + "".join(f"<td>{r.get(c,'')}</td>" for c in cols) + "</tr>" for r in items)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Trace Foundry Report — {domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;font-size:14px}}
.hdr{{background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid #30363d;padding:28px 40px}}
.hdr h1{{font-size:26px;color:#58a6ff;font-weight:700}}.hdr h1 span{{color:#f0883e}}
.hdr .meta{{color:#8b949e;margin-top:6px;font-size:13px}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px;margin-bottom:28px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px 14px;text-align:center}}
.card .n{{font-size:28px;font-weight:700;color:#58a6ff}}.card .l{{font-size:11px;color:#8b949e;margin-top:3px;text-transform:uppercase}}
.sec{{background:#161b22;border:1px solid #30363d;border-radius:10px;margin-bottom:20px;overflow:hidden}}
.sec-hdr{{padding:14px 22px;border-bottom:1px solid #30363d;display:flex;align-items:center;gap:8px}}
.sec-hdr h2{{font-size:15px;font-weight:600}}
.sec-body{{padding:18px 22px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{color:#8b949e;text-transform:uppercase;font-size:11px;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid #30363d;text-align:left}}
td{{padding:9px 10px;border-bottom:1px solid #21262d;color:#c9d1d9}}
tr:last-child td{{border-bottom:none}}tr:hover td{{background:#1c2128}}
.kv{{display:flex;gap:12px;flex-wrap:wrap}}
.kvi{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px 14px;min-width:180px;flex:1}}
.kvi .k{{font-size:11px;color:#8b949e;text-transform:uppercase;margin-bottom:3px}}
.kvi .v{{color:#e6edf3;font-size:13px;word-break:break-all}}
.bug-row td:first-child{{font-family:monospace;font-size:12px}}
a{{color:#58a6ff;text-decoration:none}}a:hover{{text-decoration:underline}}
.footer{{text-align:center;color:#8b949e;font-size:12px;padding:20px}}
.grade{{font-size:32px;font-weight:700}}
.grade-A{{color:#3fb950}}.grade-B{{color:#d29922}}.grade-C{{color:#d29922}}.grade-D{{color:#f85149}}.grade-F{{color:#f85149}}
</style></head><body>

<div class="hdr">
  <h1>🔍 Trace <span>Foundry</span> v2.0 — Recon Report</h1>
  <div class="meta">Target: <strong>{domain}</strong> &nbsp;|&nbsp; Scanned: {ts}</div>
</div>

<div class="wrap">

<!-- Summary Cards -->
<div class="grid">
  <div class="card"><div class="n">{dns.get('ip','N/A')}</div><div class="l">IP</div></div>
  <div class="card"><div class="n grade grade-{ssl.get('grade','?')}">{ssl.get('grade','?')}</div><div class="l">SSL Grade</div></div>
  <div class="card"><div class="n grade grade-{ha.get('grade','?')}">{ha.get('score','?')}</div><div class="l">Sec Headers /100</div></div>
  <div class="card"><div class="n" style="font-size:14px">{waf.get('waf_name','None') or 'None'}</div><div class="l">WAF</div></div>
  <div class="card"><div class="n">{len(subdomains)}</div><div class="l">Subdomains</div></div>
  <div class="card"><div class="n">{len(ports)}</div><div class="l">Open Ports</div></div>
  <div class="card"><div class="n" style="color:#f85149">{len(bugs)}</div><div class="l">Bugs Found</div></div>
  <div class="card"><div class="n" style="color:#f85149">{sev_counts.get('CRITICAL',0)+sev_counts.get('HIGH',0)}</div><div class="l">Crit/High</div></div>
</div>

<!-- Bugs Summary -->
<div class="sec">
  <div class="sec-hdr"><span>🚨</span><h2>All Bugs Found ({len(bugs)})</h2></div>
  <div class="sec-body">
  {'<p style="color:#3fb950">No bugs found — target looks well hardened!</p>' if not bugs else f"""
  <table><thead><tr><th>Severity</th><th>Module</th><th>Type</th><th>Detail</th></tr></thead><tbody>
  {"".join(f'<tr class=bug-row><td>{_sev_badge(b.get("severity","INFO"))}</td><td style="color:#8b949e">{b.get("module","?")}</td><td>{b.get("type","?")}</td><td style="font-size:12px;color:#8b949e">{str(b.get("detail",b.get("url","")))[:80]}</td></tr>' for b in sorted(bugs, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x.get("severity","INFO"),4)))}
  </tbody></table>"""}
  </div>
</div>

<!-- DNS -->
<div class="sec">
  <div class="sec-hdr"><span>🌐</span><h2>DNS Information</h2></div>
  <div class="sec-body"><div class="kv">
    <div class="kvi"><div class="k">IP</div><div class="v">{dns.get('ip','N/A')}</div></div>
    <div class="kvi"><div class="k">Reverse DNS</div><div class="v">{dns.get('reverse_dns','N/A')}</div></div>
    <div class="kvi"><div class="k">MX Records</div><div class="v">{', '.join(dns.get('mx',[])) or 'N/A'}</div></div>
    <div class="kvi"><div class="k">Registrar</div><div class="v">{whois.get('registrar','N/A')}</div></div>
    <div class="kvi"><div class="k">Expires</div><div class="v">{str(whois.get('expires','N/A'))[:10]}</div></div>
    <div class="kvi"><div class="k">DNSSEC</div><div class="v">{whois.get('dnssec','N/A')}</div></div>
  </div></div>
</div>

<!-- SSL -->
<div class="sec">
  <div class="sec-hdr"><span>🔐</span><h2>SSL/TLS Certificate</h2></div>
  <div class="sec-body"><div class="kv">
    <div class="kvi"><div class="k">Grade</div><div class="v grade grade-{ssl.get('grade','?')}" style="font-size:24px;font-weight:700">{ssl.get('grade','N/A')}</div></div>
    <div class="kvi"><div class="k">Common Name</div><div class="v">{ssl.get('common_name','N/A')}</div></div>
    <div class="kvi"><div class="k">Issuer</div><div class="v">{ssl.get('issuer','N/A')}</div></div>
    <div class="kvi"><div class="k">Protocol</div><div class="v">{ssl.get('protocol','N/A')}</div></div>
    <div class="kvi"><div class="k">Expiry</div><div class="v">{ssl.get('expiry','N/A')} ({ssl.get('days_left','?')} days)</div></div>
    <div class="kvi"><div class="k">Cipher</div><div class="v">{ssl.get('cipher','N/A')}</div></div>
  </div></div>
</div>

<!-- Subdomains -->
<div class="sec">
  <div class="sec-hdr"><span>🔗</span><h2>Subdomains ({len(subdomains)})</h2></div>
  <div class="sec-body">
  <table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead><tbody>
  {"".join(f'<tr><td><a href="https://{s["subdomain"]}" target="_blank">{s["subdomain"]}</a></td><td>{s["ip"]}</td></tr>' for s in subdomains) or '<tr><td colspan=2 style="color:#8b949e;text-align:center">None found</td></tr>'}
  </tbody></table></div>
</div>

<!-- Ports -->
<div class="sec">
  <div class="sec-hdr"><span>🔌</span><h2>Open Ports ({len(ports)})</h2></div>
  <div class="sec-body">
  <table><thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead><tbody>
  {"".join(f'<tr><td><strong>{p["port"]}</strong></td><td>{p["service"]}</td><td style="font-family:monospace;font-size:11px;color:#8b949e">{(p.get("banner") or "")[:80]}</td></tr>' for p in ports) or '<tr><td colspan=3 style="color:#8b949e;text-align:center">None found</td></tr>'}
  </tbody></table></div>
</div>

<!-- Paths -->
<div class="sec">
  <div class="sec-hdr"><span>📁</span><h2>Sensitive Paths ({len(paths)} total, {len(sensitive_paths)} sensitive)</h2></div>
  <div class="sec-body">
  <table><thead><tr><th>Path</th><th>Label</th><th>Status</th><th>Risk</th></tr></thead><tbody>
  {"".join(f'<tr><td><a href="{p["url"]}" target="_blank">{p["path"]}</a></td><td>{p["label"]}</td><td>{p["status"]}</td><td>{"<span style=color:#f85149;font-weight:600>⚠️ Sensitive</span>" if p.get("sensitive") else "<span style=color:#3fb950>Normal</span>"}</td></tr>' for p in paths) or '<tr><td colspan=4 style="color:#8b949e;text-align:center">None found</td></tr>'}
  </tbody></table></div>
</div>

<!-- JS Endpoints -->
<div class="sec">
  <div class="sec-hdr"><span>📜</span><h2>JS Discovered Endpoints ({len(js.get("endpoints_found",[]))})</h2></div>
  <div class="sec-body">
  <table><thead><tr><th>Endpoint</th></tr></thead><tbody>
  {"".join(f'<tr><td style="font-family:monospace">{e}</td></tr>' for e in js.get("endpoints_found",[])[:40]) or '<tr><td style="color:#8b949e;text-align:center">None found</td></tr>'}
  </tbody></table></div>
</div>

<!-- Emails -->
<div class="sec">
  <div class="sec-hdr"><span>📧</span><h2>Emails ({len(emails)})</h2></div>
  <div class="sec-body">
  <table><thead><tr><th>Email</th><th>Source</th></tr></thead><tbody>
  {"".join(f'<tr><td>{e["email"]}</td><td style="color:#8b949e;font-size:12px">{e["source"]}</td></tr>' for e in emails) or '<tr><td colspan=2 style="color:#8b949e;text-align:center">None found</td></tr>'}
  </tbody></table></div>
</div>

</div>
<div class="footer">Generated by <strong>Trace Foundry v2.0</strong> — For authorized security testing only</div>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
