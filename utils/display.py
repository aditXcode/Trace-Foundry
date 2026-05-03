"""Trace Foundry V8.5 - Rich Display System"""
import sys, time, threading

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.text    import Text
    from rich.panel   import Panel
    from rich         import box as rich_box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

R="\033[0m"; B="\033[1m"; DM="\033[2m"
CY="\033[96m"; GR="\033[92m"; YL="\033[93m"
RD="\033[91m"; BL="\033[94m"; WH="\033[97m"; MG="\033[95m"
SEV_COL={"CRITICAL":"\033[91m","HIGH":"\033[91m","MEDIUM":"\033[93m","LOW":"\033[94m","INFO":"\033[96m"}
SEV_ICON={"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}

class Spinner:
    FRAMES=["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    def __init__(self,label):
        self.label=label; self._stop=threading.Event()
        self._thread=threading.Thread(target=self._spin,daemon=True)
    def _spin(self):
        i=0
        while not self._stop.is_set():
            f=self.FRAMES[i%len(self.FRAMES)]
            sys.stdout.write(f"\r  {CY}{f}{R}  {self.label:<44}{DM}scanning...{R}  ")
            sys.stdout.flush(); time.sleep(0.1); i+=1
    def start(self): self._thread.start(); return self
    def stop(self,bugs=0,skipped=False):
        self._stop.set(); self._thread.join()
        if skipped:
            sys.stdout.write(f"\r  {DM}-{R}  {self.label:<44}{DM}skipped{R}\n")
        elif bugs>0:
            sys.stdout.write(f"\r  {RD}!{R}  {self.label:<44}{RD}{B}{bugs} bug(s) found{R}\n")
        else:
            sys.stdout.write(f"\r  {GR}v{R}  {self.label:<44}{DM}clean{R}\n")
        sys.stdout.flush()

def module_start(label): return Spinner(label).start()

def banner():
    if RICH_AVAILABLE:
        console.print(Panel(
            "[bold cyan]TRACE FOUNDRY V8.5[/bold cyan]\n"
            "[dim]34 Modules | 8 Anti-FP Engines | HTTP/2 | DOM-XSS | Rich Output[/dim]\n"
            "[dim]proto_pollute | js_entropy | dep_confuse | dom_sink | oauth_audit | cloud_takeover[/dim]\n"
            "[yellow]Authorized Use Only[/yellow]",
            border_style="cyan", expand=False))
    else:
        print(f"\n{CY}{B}  TRACE FOUNDRY V8.5{R}")
        print(f"{DM}  34 Modules | Anti-FP | HTTP/2 | DOM-XSS | Authorized Use Only{R}\n")

def ok(m):
    if RICH_AVAILABLE: console.print(f"  [green]v[/green]  {m}")
    else: sys.stdout.write(f"  {GR}[+]{R}  {m}\n"); sys.stdout.flush()

def info(m):
    if RICH_AVAILABLE: console.print(f"  [blue].[/blue]  [dim]{m}[/dim]")
    else: sys.stdout.write(f"  {BL}[*]{R}  {DM}{m}{R}\n"); sys.stdout.flush()

def warn(m):
    if RICH_AVAILABLE: console.print(f"  [yellow]![/yellow]  {m}")
    else: sys.stdout.write(f"  {YL}[!]{R}  {m}\n"); sys.stdout.flush()

def detail(m):
    if RICH_AVAILABLE: console.print(f"  [dim]-> {m}[/dim]")
    else: sys.stdout.write(f"  {DM}  -> {m}{R}\n"); sys.stdout.flush()

def print_info(m):
    if RICH_AVAILABLE: console.print(f"  [cyan]>[/cyan]  {m}")
    else: sys.stdout.write(f"  {CY}[i]{R}  {m}\n"); sys.stdout.flush()

def section(t): pass
def print_section(t): pass

def show_triple_gate(bug_type, severity, gate_results, details=None):
    if RICH_AVAILABLE:
        sc={"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"blue","INFO":"cyan"}.get(severity,"white")
        t=Table(title=f"TRIPLE GATE: {bug_type}",border_style=sc,box=rich_box.HEAVY_EDGE,expand=False)
        t.add_column("Gate",style="bold",width=8); t.add_column("Status",width=10); t.add_column("Detail",width=50)
        g=gate_results
        for i in range(1,4):
            key=f"gate{i}"
            passed=g.get(key,{}).get("passed",False) if isinstance(g.get(key),dict) else g.get(key,False)
            st="[green]PASS[/green]" if passed else "[red]FAIL[/red]"
            det=""
            if isinstance(g.get(key),dict):
                det=f"len={g[key].get('len','')} t={g[key].get('time','')}s"
            t.add_row(f"Gate {i}",st,det)
        all_pass=all((g.get(f"gate{i}",{}).get("passed",False) if isinstance(g.get(f"gate{i}"),dict) else g.get(f"gate{i}",False)) for i in range(1,4))
        verdict=f"[bold red]VULNERABLE - {severity}[/bold red]" if all_pass else "[dim]Not confirmed[/dim]"
        t.add_row("Verdict",verdict,"")
        if details:
            for k,v in details.items(): t.add_row(k,"",str(v)[:60])
        console.print(t)
    else:
        bug_found(bug_type,severity,details)

def bug_found(bug_type, severity="INFO", details=None):
    col=SEV_COL.get(severity,CY)
    if RICH_AVAILABLE:
        sc={"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"blue","INFO":"cyan"}.get(severity,"white")
        content=f"[bold {sc}]{bug_type}[/bold {sc}]\n"
        if details:
            for k,v in details.items(): content+=f"[dim]{k}:[/dim] {str(v)[:70]}\n"
        console.print(Panel(content.strip(),title=f"[bold {sc}]BUG CONFIRMED - {severity}[/bold {sc}]",border_style=sc,expand=False))
    else:
        w=64
        print(f"\n{col}{B}{'='*w}{R}")
        print(f"{col}{B}  BUG CONFIRMED - {severity}{R}")
        print(f"{col}{B}{'='*w}{R}")
        print(f"{YL}{B}  {bug_type}{R}")
        print(f"{col}{B}{'-'*w}{R}")
        if details:
            for k,v in details.items():
                print(f"{WH}  {k:<20}: {str(v)[:60]}{R}")
        print(f"{col}{B}{'='*w}{R}\n")

def print_final_summary(domain, meta, all_bugs, elapsed):
    from urllib.parse import urlparse
    sev_order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]")
        console.print(f"[bold cyan]  SCAN COMPLETE - {domain.upper()}[/bold cyan]")
        console.print(f"[bold cyan]{'='*62}[/bold cyan]\n")
        mt=Table(title="Target Info",border_style="cyan",box=rich_box.SIMPLE,expand=False)
        mt.add_column("Field",style="dim",width=22); mt.add_column("Value",width=40)
        for k,v in meta.items():
            if v and str(v) not in ("N/A","None","?","0"): mt.add_row(k,str(v)[:60])
        console.print(mt)
        total=len(all_bugs)
        console.print(f"\n[bold red]Bugs Found: {total}[/bold red]")
        if not all_bugs:
            console.print("[green]  No confirmed bugs - target looks clean[/green]\n"); return
        sbs=sorted(all_bugs,key=lambda x:sev_order.get(x.get("severity","INFO"),4))
        counts={}
        for b in sbs: s=b.get("severity","INFO"); counts[s]=counts.get(s,0)+1
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if sev in counts:
                sc={"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"blue","INFO":"cyan"}.get(sev,"white")
                bar="X"*min(counts[sev],25)
                console.print(f"  {SEV_ICON.get(sev,'.')} [{sc}]{sev:<9}[/{sc}] [{sc}]{bar}  {counts[sev]}[/{sc}]")
        bt=Table(border_style="red",box=rich_box.SIMPLE_HEAVY,expand=False)
        bt.add_column("SEV",width=10); bt.add_column("WHERE",width=28); bt.add_column("WHAT",width=38)
        for b in sbs:
            sev=b.get("severity","INFO"); btype=b.get("type","?")
            url=str(b.get("url",b.get("detail","")))
            sc={"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"blue","INFO":"cyan"}.get(sev,"white")
            try:
                p=urlparse(url); loc=(p.path+("?"+p.query[:12] if p.query else ""))[:28]
            except: loc=url[:28]
            pm=b.get("param","")
            if pm: loc+=f"[{pm}]"
            short=btype.replace("Cross-Site Scripting","XSS").replace("SQL Injection","SQLi").replace(" -- "," ")[:38]
            bt.add_row(f"{SEV_ICON.get(sev,'.')} [{sc}]{sev}[/{sc}]",f"[dim]{loc}[/dim]",short)
        console.print(bt)
        ch=counts.get("CRITICAL",0)+counts.get("HIGH",0)
        console.print(f"\n  [bold]Total: {total}[/bold]")
        if ch: console.print(f"  [bold red]-> {ch} CRITICAL/HIGH - report now![/bold red]")
        console.print(f"\n[bold cyan]{'='*62}[/bold cyan]\n")
    else:
        print(f"\n{YL}{'='*62}{R}")
        print(f"{YL}{B}  SCAN COMPLETE - {domain.upper()}{R}")
        print(f"{YL}{'='*62}{R}\n")
        for k,v in meta.items():
            if v and str(v) not in ("N/A","None","?","0"):
                print(f"  {DM}{k:<22}{R}{WH}{v}{R}")
        total=len(all_bugs)
        print(f"\n  {RD}{B}Bugs Found: {total}{R}\n")
        if not all_bugs:
            print(f"  {GR}No confirmed bugs{R}\n"); return
        sbs=sorted(all_bugs,key=lambda x:sev_order.get(x.get("severity","INFO"),4))
        counts={}
        for b in sbs: s=b.get("severity","INFO"); counts[s]=counts.get(s,0)+1
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if sev in counts:
                col=SEV_COL.get(sev,R)
                print(f"  {col}{SEV_ICON.get(sev,'.')} {sev:<9}{'|'*min(counts[sev],25)}  {counts[sev]}{R}")
        print(f"\n  {DM}SEV       WHERE                        WHAT{R}")
        for b in sbs:
            sev=b.get("severity","INFO"); col=SEV_COL.get(sev,R)
            url=str(b.get("url",b.get("detail","")))
            try:
                p=urlparse(url); loc=(p.path+("?"+p.query[:10] if p.query else ""))[:28]
            except: loc=url[:28]
            pm=b.get("param","")
            if pm: loc+=f"[{pm}]"
            print(f"  {col}{SEV_ICON.get(sev,'.')} {sev:<9}{R}{DM}{loc:<30}{R}  {b.get('type','?')[:35]}")
        ch=counts.get("CRITICAL",0)+counts.get("HIGH",0)
        print(f"\n  {B}Total: {total}{R}")
        if ch: print(f"  {RD}{B}-> {ch} CRITICAL/HIGH - prioritize for report!{R}")
        print(f"\n{YL}{'='*62}{R}\n")
