#!/usr/bin/env python3
# TBH-AllScan v2.7 Pro - Pretty + Progress
import socket, requests, argparse, json, re, ssl, urllib.parse, time
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.7 Pro \033[91m- Pretty        \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

def check_headers(url):
    r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.7'})
    missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
    bug={"severity":"Low","title":"Missing Security Headers","missing":missing,"fix":"Tambah CSP/HSTS"} if missing else None
    return {"status":r.status_code,"missing":missing,"bug":bug}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    bug={"severity":"Info","title":"Open Ports","fix":"Tutup tidak perlu"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    checks=[("Headers",lambda: check_headers(url)),("Ports",lambda: check_ports(ip))]
    for i,(name,func) in enumerate(checks,1):
        print(f"[{i}/{len(checks)}] {name}...",end=" ",flush=True)
        time.sleep(0.2)
        res=func(); report[name]=res
        if res.get("bug"): report["bugs"].append({"tool":name,**res["bug"]}); print(f"\033[91m[!] {res['bug']['title']} [{res['bug']['severity']}]\033[0m")
        else: print(f"\033[92m[✓] OK\033[0m")
    score=sum({"High":10,"Medium":5,"Low":2,"Info":1}.get(b["severity"],0) for b in report["bugs"])
    level="Critical" if score>=15 else "High" if score>=10 else "Medium" if score>=5 else "Low" if score>=2 else "Info"
    report["risk_score"]=score; report["risk_level"]=level
    # Pretty print
    print(f"\n\033[96m{'='*50}\033[0m")
    print(f"\033[97mTarget: {report['target']} | Risk: \033[91m{level} ({score})\033[0m | Bugs: {len(report['bugs'])}")
    for b in report["bugs"]:
        color={"High":"\033[91m","Medium":"\033[93m","Low":"\033[93m","Info":"\033[96m"}.get(b["severity"],"\033[0m")
        print(f" {color}• [{b['severity']}] {b['tool']}: {b['title']}\033[0m")
    print(f"\033[96m{'='*50}\033[0m")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v2.7")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        rows="".join([f"<tr><td>{b['tool']}</td><td style='background:{ {'High':'#ff0000','Medium':'#ff8c00','Low':'#ffcc00','Info':'#58a6ff'}.get(b['severity'],'#c9d1d9')};color:#000'>{b['severity']}</td><td>{b['title']}</td><td>{b.get('fix','')}</td></tr>" for b in report["bugs"]])
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>TBH-AllScan v2.7 Pro {report['target']} | Risk {report['risk_level']} ({report['risk_score']})</h1><table border=1 style='border-collapse:collapse;width:100%'><tr><th>Tool</th><th>Severity</th><th>Bug</th><th>Fix</th></tr>{rows}</table><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
