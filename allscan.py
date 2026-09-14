#!/usr/bin/env python3
# TBH-AllScan v2.5 Pro - All 10 Tools + Risk Score
import socket, requests, argparse, json, re, ssl, urllib.parse
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.5 Pro \033[91m- All 10 + Risk   \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

WEIGHT={"High":10,"Medium":5,"Low":2,"Info":1}
CVE_DB={80:"CVE-2023-44487",443:"CVE-2023-44487",445:"CVE-2017-0144",3389:"CVE-2019-0708"}

def check_headers(url):
    r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.5'})
    missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
    bug={"severity":"Low","title":"Missing Security Headers","missing":missing,"fix":"Tambah CSP/HSTS"} if missing else None
    return {"status":r.status_code,"missing":missing,"bug":bug}

def check_ssl(domain):
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain,443)); cert=s.getpeercert()
            expire=cert.get('notAfter'); days=(datetime.strptime(expire,"%b %d %H:%M:%S %Y %Z")-datetime.utcnow()).days
            bug={"severity":"Medium","title":"SSL Expire Soon","days":days,"fix":"Renew SSL"} if days<30 else None
            return {"expire":expire,"days":days,"bug":bug}
    except: return {"note":"no https"}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080,8443]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append({"port":p,"cve":CVE_DB.get(p,"-")})
        s.close()
    bug={"severity":"Info","title":"Open Ports","ports":open_ports,"fix":"Tutup tidak perlu"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def check_dirs(url):
    found=[]
    for path in [".env",".git","admin"]:
        full=f"{url.rstrip('/')}/{path}"
        try:
            r=requests.get(full,timeout=3,allow_redirects=False)
            if r.status_code in [200,403]: found.append({"path":path,"status":r.status_code})
        except: pass
    bug={"severity":"High","title":"Sensitive Dir","found":found,"fix":"Hapus .env/.git"} if any(f["path"] in [".env",".git"] for f in found) else None
    return {"found":found,"bug":bug}

def check_cors(url):
    try:
        r=requests.get(url,timeout=5,headers={'Origin':'https://evil.com'})
        acao=r.headers.get('Access-Control-Allow-Origin','')
        if acao=="https://evil.com" or acao=="*":
            bug={"severity":"High","title":"CORS Misconfig","acao":acao,"fix":"Set ACAO spesifik"}
            return {"vulnerable":True,"bug":bug}
        return {"vulnerable":False}
    except: return {"vulnerable":False}

def check_xss(url):
    payload="<svg/onload=alert(1)>"
    test_url=f"{url}?q={urllib.parse.quote(payload)}"
    try:
        r=requests.get(test_url,timeout=5)
        if payload in r.text: bug={"severity":"High","title":"Reflected XSS","payload":payload,"fix":"Encode output, CSP"}
        else: bug=None
        return {"vulnerable":bool(bug),"bug":bug}
    except: return {"vulnerable":False}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    checks=[("Headers",lambda: check_headers(url)),("SSL",lambda: check_ssl(domain)),("Ports",lambda: check_ports(ip)),("Dirs",lambda: check_dirs(url)),("CORS",lambda: check_cors(url)),("XSS",lambda: check_xss(url))]
    for name,func in checks:
        print(f"\n[~] {name}...")
        res=func(); report[name]=res
        if res.get("bug"): report["bugs"].append({"tool":name,**res["bug"]}); print(f"[!] {res['bug']['title']} [{res['bug']['severity']}]")
        else: print(f"[✓] {name} OK")
    score=sum({"High":10,"Medium":5,"Low":2,"Info":1}.get(b["severity"],0) for b in report["bugs"])
    level="Critical" if score>=15 else "High" if score>=10 else "Medium" if score>=5 else "Low" if score>=2 else "Info"
    report["risk_score"]=score; report["risk_level"]=level
    print(f"\n[Risk] {score} -> {level}")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v2.5")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"[✓] Found {len(report['bugs'])} bugs | Risk: {report['risk_level']} ({report['risk_score']})")
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        rows="".join([f"<tr><td>{b['tool']}</td><td style='background:{ {'High':'#ff0000','Medium':'#ff8c00','Low':'#ffcc00','Info':'#58a6ff'}.get(b['severity'],'#c9d1d9')};color:#000'>{b['severity']}</td><td>{b['title']}</td><td>{b.get('fix','')}</td></tr>" for b in report["bugs"]])
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>TBH-AllScan v2.5 Pro {report['target']} | Risk {report['risk_level']} ({report['risk_score']})</h1><table border=1 style='border-collapse:collapse;width:100%'><tr><th>Tool</th><th>Severity</th><th>Bug</th><th>Fix</th></tr>{rows}</table><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
