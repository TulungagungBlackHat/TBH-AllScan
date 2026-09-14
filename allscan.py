#!/usr/bin/env python3
# TBH-AllScan v3.2 Pro - Full 10 + Time
import socket, requests, argparse, json
from datetime import datetime
import time

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v3.2 Pro \033[91m- Full + Time    \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

def allscan(url):
    import urllib.parse
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    start=time.time()
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    # Headers
    r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/3.2'})
    missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security'] if h not in r.headers]
    if missing: report["bugs"].append({"tool":"Headers","severity":"Low","title":"Missing Headers"})
    # Ports
    open_ports=[]
    for p in [80,443]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    if open_ports: report["bugs"].append({"tool":"Ports","severity":"Info","title":"Open Ports"})
    elapsed=round(time.time()-start,2)
    report["elapsed"]=elapsed
    score=sum({"High":10,"Medium":5,"Low":2,"Info":1}.get(b["severity"],0) for b in report["bugs"])
    report["risk_score"]=score; report["risk_level"]="Low"
    print(f"[Time] {elapsed}s | Risk {report['risk_level']} ({score}) | 10 Tools")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v3.2")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>v3.2 Pro {report['target']} | {report['elapsed']}s</h1><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
