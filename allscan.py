#!/usr/bin/env python3
# TBH-AllScan v2.2 Pro - All-in-One + CVE Table + Fix
import socket, requests, argparse, json, re, ssl, urllib.parse
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.2 Pro \033[91m- CVE Table     \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

CVE_DB = {80: "CVE-2023-44487 Rapid Reset - update nginx", 443: "CVE-2023-44487 - update TLS", 445: "CVE-2017-0144 EternalBlue - patch SMB", 3389: "CVE-2019-0708 BlueKeep - patch RDP"}

def check_headers(url):
    try:
        r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.2'})
        missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
        if missing: bug={"severity":"Low","title":"Missing Security Headers","missing":missing,"fix":"Tambah CSP: default-src 'self'; HSTS: max-age=31536000"}
        else: bug=None
        return {"status":r.status_code,"missing":missing,"bug":bug}
    except: return {"error":True}

def check_ssl(domain):
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain,443)); cert=s.getpeercert()
            expire=cert.get('notAfter'); days=(datetime.strptime(expire,"%b %d %H:%M:%S %Y %Z")-datetime.utcnow()).days
            bug={"severity":"Medium","title":"SSL Expire Soon","days":days,"fix":"Perbarui SSL via Let's Encrypt"} if days<30 else None
            return {"expire":expire,"days":days,"bug":bug}
    except: return {"note":"no https"}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080,8443,445]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append({"port":p,"cve":CVE_DB.get(p,"-"),"fix":CVE_DB.get(p,"Tutup port").split(" - ")[-1] if p in CVE_DB else "Tutup jika tidak perlu"})
        s.close()
    bug={"severity":"Info","title":"Open Ports + CVE","ports":open_ports,"fix":"Patch CVE & tutup port"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    for name,func in [("Headers",lambda: check_headers(url)),("SSL",lambda: check_ssl(domain)),("Ports",lambda: check_ports(ip))]:
        print(f"\n[~] {name}...")
        res=func(); report[name]=res
        if res.get("bug"): report["bugs"].append({"tool":name,**res["bug"]}); print(f"[!] {res['bug']['title']} [{res['bug']['severity']}]")
        else: print(f"[✓] {name} OK")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v2.2")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"\n[✓] Found {len(report['bugs'])} bugs")
    for b in report["bugs"]: print(f" - [{b['severity']}] {b['tool']}: {b['title']}")
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        rows="".join([f"<tr><td>{b['tool']}</td><td>{b['severity']}</td><td>{b['title']}</td><td>{b.get('fix','')}</td></tr>" for b in report["bugs"]])
        html=f"<html><head><style>table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30363d;padding:8px}}th{{background:#ff0000;color:#fff}}</style></head><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>TBH-AllScan v2.2 Pro {report['target']}</h1><p>{report['time']}</p><table><tr><th>Tool</th><th>Severity</th><th>Bug</th><th>Fix</th></tr>{rows}</table><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html} (CVE table)")

if __name__=="__main__": main()
