#!/usr/bin/env python3
# TBH-AllScan v2.1 Pro - + CVE Lookup
import socket, requests, argparse, json, ssl, urllib.parse
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.1 Pro \033[91m- + CVE Lookup  \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

CVE_DB = {
    21: ["CVE-2020-15782: FTP anon", "Fix: disable anon"],
    22: ["CVE-2018-15473: SSH enum", "Fix: update OpenSSH"],
    80: ["CVE-2023-44487: HTTP/2 Rapid Reset", "Fix: update nginx/apache"],
    443: ["CVE-2023-44487: HTTP/2", "Fix: update TLS"],
    445: ["CVE-2017-0144: EternalBlue MS17-010", "Fix: patch SMB"],
    3389: ["CVE-2019-0708: BlueKeep", "Fix: patch RDP"],
}

def check_headers(url):
    try:
        r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.1'})
        missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
        if missing:
            fix="Tambah header CSP/HSTS/X-Frame"
            bug={"severity":"Low","title":"Missing Security Headers","missing":missing,"fix":fix}
        else: bug=None
        return {"status":r.status_code,"missing":missing,"bug":bug}
    except Exception as e: return {"error":str(e)}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,445,3389,8080]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0:
            cves=CVE_DB.get(p,[])
            open_ports.append({"port":p,"cves":cves})
        s.close()
    if open_ports:
        bug={"severity":"Info","title":"Open Ports + CVE","ports":open_ports,"fix":"Tutup port tidak perlu, patch CVE di atas"}
    else: bug=None
    return {"open":open_ports,"bug":bug}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    # Headers
    h=check_headers(url); report["Headers"]=h
    if h.get("bug"): report["bugs"].append({"tool":"Headers",**h["bug"]}); print(f"[!] {h['bug']['title']}")
    else: print("[✓] Headers OK")
    # Ports + CVE
    p=check_ports(ip); report["Ports"]=p
    if p.get("bug"):
        report["bugs"].append({"tool":"Ports",**p["bug"]})
        for pp in p["open"]:
            print(f"[!] Port {pp['port']} CVE: {pp['cves']}")
    else: print("[✓] Ports OK")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v2.1 CVE")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"\n[✓] Found {len(report['bugs'])} bugs")
    for b in report["bugs"]:
        print(f" - [{b['severity']}] {b['tool']}: {b['title']}")
        if "cves" in str(b): print(f"   CVE: {b.get('ports',b.get('cves'))}")
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px'><h1>TBH-AllScan v2.1 Pro {report['target']}</h1><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
