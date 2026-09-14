#!/usr/bin/env python3
# TBH-AllScan v3.0 Pro - Full Dashboard
import socket, requests, argparse, json
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v3.0 Pro \033[91m- Dashboard     \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

def check_headers(url):
    r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/3.0'})
    missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
    bug={"severity":"Low","title":"Missing Security Headers","fix":"Tambah CSP/HSTS","autofix":"add_header CSP"} if missing else None
    return {"missing":missing,"bug":bug}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    bug={"severity":"Info","title":"Open Ports","fix":"Tutup tidak perlu","autofix":"ufw deny"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def allscan(url):
    import urllib.parse
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    for name,func in [("Headers",lambda: check_headers(url)),("Ports",lambda: check_ports(ip))]:
        print(f"[~] {name}...",end=" ")
        res=func(); report[name]=res
        if res.get("bug"): report["bugs"].append({"tool":name,**res["bug"]}); print(f"[!] {res['bug']['title']} [{res['bug']['severity']}]")
        else: print("[✓] OK")
    score=sum({"High":10,"Medium":5,"Low":2,"Info":1}.get(b["severity"],0) for b in report["bugs"])
    level="Critical" if score>=15 else "High" if score>=10 else "Medium" if score>=5 else "Low" if score>=2 else "Info"
    report["risk_score"]=score; report["risk_level"]=level
    # AI-like summary
    summary=f"Target {domain} memiliki {len(report['bugs'])} bug dengan risk {level} ({score}). Rekomendasi: perbaiki {', '.join([b['title'] for b in report['bugs']])} segera."
    report["summary"]=summary
    print(f"\n[AI Summary] {summary}")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v3.0")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    parser.add_argument("--fix",help="Save fix sh")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"[✓] Found {len(report['bugs'])} bugs | Risk: {report['risk_level']} ({report['risk_score']})")
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        rows="".join([f"<tr><td>{b['tool']}</td><td style='background:{ {'High':'#ff0000','Medium':'#ff8c00','Low':'#ffcc00','Info':'#58a6ff'}.get(b['severity'],'#c9d1d9')};color:#000'>{b['severity']}</td><td>{b['title']}</td><td>{b.get('fix','')}</td></tr>" for b in report["bugs"]])
        html=f"""<html><head><style>body{{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #30363d;padding:8px}} th{{background:#ff0000;color:#fff}} .summary{{background:#161b22;padding:15px;border-left:4px solid #ff0000;margin:15px 0}}</style></head><body>
<h1>TBH-AllScan v3.0 Pro Dashboard - {report['target']}</h1>
<p>Risk: <b style='color:{"#ff0000" if report['risk_level']=="High" else "#ffcc00"}'>{report['risk_level']} ({report['risk_score']})</b> | {report['time']}</p>
<div class='summary'><b>AI Summary:</b> {report['summary']}</div>
<table><tr><th>Tool</th><th>Severity</th><th>Bug</th><th>Fix</th></tr>{rows}</table>
<pre>{json.dumps(report,indent=2)}</pre>
</body></html>"""
        open(args.html,'w').write(html); print(f"[✓] HTML Dashboard: {args.html}")
    if args.fix:
        script="\n".join([b.get('autofix','') for b in report["bugs"] if b.get('autofix')])
        open(args.fix,'w').write("#!/bin/bash\n# Auto-fix v3.0 Pro\n"+script); print(f"[✓] Fix: {args.fix}")

if __name__=="__main__": main()
