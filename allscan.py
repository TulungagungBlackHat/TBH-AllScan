#!/usr/bin/env python3
# TBH-AllScan v2.6 Pro - Full 10 Tools
import socket, requests, argparse, json, re, ssl, urllib.parse
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.6 Pro \033[91m- Full 10 Tools  \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

def check_headers(url):
    r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.6'})
    missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
    bug={"severity":"Low","title":"Missing Security Headers","fix":"Tambah CSP/HSTS"} if missing else None
    return {"missing":missing,"bug":bug}

def check_ssl(domain):
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain,443)); cert=s.getpeercert()
            days=(datetime.strptime(cert.get('notAfter'),"%b %d %H:%M:%S %Y %Z")-datetime.utcnow()).days
            bug={"severity":"Medium","title":"SSL Expire Soon","fix":"Renew SSL"} if days<30 else None
            return {"days":days,"bug":bug}
    except: return {"bug":None}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    bug={"severity":"Info","title":"Open Ports","fix":"Tutup tidak perlu"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def check_subdomains(domain):
    found=[]
    for sub in ["www","api","admin"]:
        try: socket.gethostbyname(f"{sub}.{domain}"); found.append(f"{sub}.{domain}")
        except: pass
    bug={"severity":"Info","title":"Subdomains","fix":"Audit"} if found else None
    return {"found":found,"bug":bug}

def check_dirs(url):
    found=[]
    for path in [".env",".git"]:
        try:
            r=requests.get(f"{url.rstrip('/')}/{path}",timeout=3,allow_redirects=False)
            if r.status_code in [200,403]: found.append(path)
        except: pass
    bug={"severity":"High","title":"Sensitive Dir","fix":"Hapus .env/.git"} if found else None
    return {"found":found,"bug":bug}

def check_params(url):
    try:
        r=requests.get(url,timeout=5)
        found=[p for p in ["id","debug"] if p in r.text.lower()]
        bug={"severity":"Info","title":"Hidden Params","fix":"Cek IDOR"} if found else None
        return {"found":found,"bug":bug}
    except: return {"bug":None}

def check_js(url):
    try:
        r=requests.get(url,timeout=5)
        if "api_key" in r.text.lower(): bug={"severity":"High","title":"JS Secrets","fix":"Hapus key dari JS"}
        else: bug=None
        return {"bug":bug}
    except: return {"bug":None}

def check_xss(url):
    payload="<svg/onload=alert(1)>"
    test_url=f"{url}?q={urllib.parse.quote(payload)}"
    try:
        r=requests.get(test_url,timeout=5)
        bug={"severity":"High","title":"XSS","fix":"Encode output"} if payload in r.text else None
        return {"vulnerable":bool(bug),"bug":bug}
    except: return {"vulnerable":False}

def check_redirect(url):
    payload="https://evil.com"
    test_url=f"{url}?redirect={payload}"
    try:
        r=requests.get(test_url,timeout=5,allow_redirects=False)
        bug={"severity":"Medium","title":"Open Redirect","fix":"Whitelist redirect"} if payload in r.headers.get('Location','') else None
        return {"vulnerable":bool(bug),"bug":bug}
    except: return {"vulnerable":False}

def check_cors(url):
    try:
        r=requests.get(url,timeout=5,headers={'Origin':'https://evil.com'})
        if r.headers.get('Access-Control-Allow-Origin')=="https://evil.com":
            bug={"severity":"High","title":"CORS Misconfig","fix":"Set ACAO spesifik"}
            return {"vulnerable":True,"bug":bug}
        return {"vulnerable":False}
    except: return {"vulnerable":False}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    checks=[("Headers",lambda: check_headers(url)),("SSL",lambda: check_ssl(domain)),("Ports",lambda: check_ports(ip)),("Subdomains",lambda: check_subdomains(domain)),("Dirs",lambda: check_dirs(url)),("Params",lambda: check_params(url)),("JS",lambda: check_js(url)),("XSS",lambda: check_xss(url)),("OpenRedirect",lambda: check_redirect(url)),("CORS",lambda: check_cors(url))]
    for name,func in checks:
        print(f"[~] {name}...",end=" ")
        res=func(); report[name]=res
        if res.get("bug"): report["bugs"].append({"tool":name,**res["bug"]}); print(f"[!] {res['bug']['title']} [{res['bug']['severity']}]")
        else: print("[✓] OK")
    score=sum({"High":10,"Medium":5,"Low":2,"Info":1}.get(b["severity"],0) for b in report["bugs"])
    level="Critical" if score>=15 else "High" if score>=10 else "Medium" if score>=5 else "Low" if score>=2 else "Info"
    report["risk_score"]=score; report["risk_level"]=level
    print(f"\n[Risk] {score} -> {level} | Found {len(report['bugs'])} bugs")
    return report

def main():
    print(BANNER)
    parser=argparse.ArgumentParser(description="v2.6")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        rows="".join([f"<tr><td>{b['tool']}</td><td style='background:{ {'High':'#ff0000','Medium':'#ff8c00','Low':'#ffcc00','Info':'#58a6ff'}.get(b['severity'],'#c9d1d9')};color:#000'>{b['severity']}</td><td>{b['title']}</td><td>{b.get('fix','')}</td></tr>" for b in report["bugs"]])
        html=f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'><h1>TBH-AllScan v2.6 Pro {report['target']} | Risk {report['risk_level']} ({report['risk_score']}) | 10 Tools</h1><table border=1 style='border-collapse:collapse;width:100%'><tr><th>Tool</th><th>Severity</th><th>Bug</th><th>Fix</th></tr>{rows}</table><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
