#!/usr/bin/env python3
# TBH-AllScan v2.4 Pro - Risk Score
import socket, requests, argparse, json, ssl, urllib.parse
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.4 Pro \033[91m- Risk Score     \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

WEIGHT = {"High":10,"Medium":5,"Low":2,"Info":1}

def check_headers(url):
    try:
        r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.4'})
        missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
        if missing: bug={"severity":"Low","title":"Missing Security Headers","missing":missing,"fix":"Tambah CSP/HSTS"}
        else: bug=None
        return {"status":r.status_code,"missing":missing,"bug":bug}
    except: return {"error":True}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080,8443]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    bug={"severity":"Info","title":"Open Ports","ports":open_ports,"fix":"Tutup tidak perlu"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    for name,func in [("Headers",lambda: check_headers(url)),("Ports",lambda: check_ports(ip))]:
        print(f"\n[~] {name}...")
        res=func(); report[name]=res
        if res.get("bug"): report["bugs"].append({"tool":name,**res["bug"]}); print(f"[!] {res['bug']['title']} [{res['bug']['severity']}]")
        else: print(f"[✓] {name} OK")
    # Risk score
    score=sum(WEIGHT.get(b["severity"],0) for b in report["bugs"])
    level="Critical" if score>=15 else "High" if score>=10 else "Medium" if score>=5 else "Low" if score>=2 else "Info"
    report["risk_score"]=score; report["risk_level"]=level
    print(f"\n[Risk] Score: {score} -> Level: {level}")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v2.4")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"[✓] Found {len(report['bugs'])} bugs | Risk: {report['risk_level']} ({report['risk_score']})")
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>TBH-AllScan v2.4 Pro {report['target']} | Risk: {report['risk_level']} ({report['risk_score']})</h1><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
