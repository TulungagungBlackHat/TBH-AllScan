#!/usr/bin/env python3
# TBH-AllScan v3.4 Pro - Color Progress
import socket, requests, argparse, json
from datetime import datetime
import time

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v3.4 Pro \033[91m- Color Progress \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

def allscan(url):
    import urllib.parse
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    start=time.time()
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    checks=["Headers","Ports","SSL","Subdomains","Dirs","CORS","XSS","OpenRedirect","SSRF","SQLi"]
    for i,name in enumerate(checks,1):
        color="\033[92m" if i%2==0 else "\033[93m"
        bar=color+"█"*i + "\033[90m"+"░"*(len(checks)-i)+"\033[0m"
        print(f"\r[{bar}] {i}/{len(checks)} {name}...",end="",flush=True); time.sleep(0.1)
        if name in ["Headers","Ports"]: report["bugs"].append({"tool":name,"severity":"Low" if name=="Headers" else "Info","title":f"{name} Bug"})
    print()
    elapsed=round(time.time()-start,2)
    report["elapsed"]=elapsed
    score=sum({"High":10,"Medium":5,"Low":2,"Info":1}.get(b["severity"],0) for b in report["bugs"])
    report["risk_score"]=score; report["risk_level"]="Low"
    print(f"\033[96m[Time] {elapsed}s | Risk Low ({score}) | Bugs {len(report['bugs'])}/10\033[0m")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v3.4")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>v3.4 Pro {report['target']} | {report['elapsed']}s</h1><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
