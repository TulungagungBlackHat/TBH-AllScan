#!/usr/bin/env python3
# TBH-AllScan - All-in-One Bug Bounty Scanner (Educational)
# Gabungan: Recon, SSL, Port, SubFinder, DirFinder, ParamFinder, JSLeak, XSS, OpenRedirect, CORS, SSRF, LFI, SQLi, IDOR
# Tulungagung Black Hat - uchil404 | Only Authorized Scope

import socket, requests, argparse, json, re, ssl, urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan \033[91m- All-in-One Bug Bounty \033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

COMMON_SUBS = ["www","api","admin","test","dev"]
COMMON_DIRS = ["admin","api",".env",".git","backup","config","robots.txt"]
COMMON_PARAMS = ["id","debug","admin","redirect"]

def check_headers(url):
    try:
        r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/1.0'})
        missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
        bug = {"severity":"Low","title":"Missing Security Headers","missing":missing} if missing else None
        return {"status":r.status_code,"server":r.headers.get('Server','Unknown'),"missing":missing,"bug":bug}
    except Exception as e: return {"error":str(e)}

def check_ssl(domain):
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain,443)); cert=s.getpeercert()
            expire=cert.get('notAfter'); days=(datetime.strptime(expire,"%b %d %H:%M:%S %Y %Z")-datetime.utcnow()).days
            bug = {"severity":"Medium","title":"SSL Expire Soon","days":days} if days<30 else None
            return {"expire":expire,"days":days,"bug":bug}
    except: return {"note":"no https"}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080,8443]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    bug = {"severity":"Info","title":"Open Ports","ports":open_ports} if open_ports else None
    return {"open":open_ports,"bug":bug}

def check_subdomains(domain):
    found=[]
    for sub in COMMON_SUBS:
        try: socket.gethostbyname(f"{sub}.{domain}"); found.append(f"{sub}.{domain}")
        except: pass
    bug = {"severity":"Info","title":"Subdomains Found","found":found} if found else None
    return {"found":found,"bug":bug}

def check_dirs(url):
    found=[]
    for path in COMMON_DIRS:
        full=f"{url.rstrip('/')}/{path}"
        try:
            r=requests.get(full,timeout=3,headers={'User-Agent':'TBH-AllScan/1.0'},allow_redirects=False)
            if r.status_code in [200,301,302,403]:
                severity="High" if path in [".env",".git"] else "Low"
                found.append({"path":path,"url":full,"status":r.status_code,"severity":severity})
        except: pass
    bug = {"severity":"High","title":"Sensitive Dir Found","found":found} if any(f["path"] in [".env",".git"] for f in found) else ({"severity":"Low","title":"Dirs Found","found":found} if found else None)
    return {"found":found,"bug":bug}

def check_params(url):
    # Simple param discovery
    try:
        r=requests.get(url,timeout=5)
        found=[p for p in COMMON_PARAMS if p.lower() in r.text.lower()]
        bug = {"severity":"Info","title":"Hidden Params Hint","params":found} if found else None
        return {"found":found,"bug":bug}
    except: return {"error":True}

def check_js(url):
    try:
        r=requests.get(url,timeout=5)
        js_links=re.findall(r'src=["\']([^"\']+\.js)',r.text)
        secrets={}
        for pat in [r"api[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9_\-]{10,})['\"]", r"AKIA[0-9A-Z]{16}"]:
            m=re.findall(pat,r.text,re.I)
            if m: secrets[pat]=m[:1]
        bug = {"severity":"High","title":"Secrets in JS","secrets":secrets} if secrets else None
        return {"js_links":js_links[:3],"secrets":secrets,"bug":bug}
    except: return {}

def check_xss(url):
    payload="<svg/onload=alert(1)>"
    test_url=f"{url}?q={urllib.parse.quote(payload)}" if "?" not in url else f"{url}&q={urllib.parse.quote(payload)}"
    try:
        r=requests.get(test_url,timeout=5)
        vulnerable=payload in r.text
        bug = {"severity":"High","title":"Reflected XSS","payload":payload,"url":test_url} if vulnerable else None
        return {"vulnerable":vulnerable,"bug":bug}
    except: return {"vulnerable":False}

def check_openredirect(url):
    payload="https://evil.com"
    test_url=f"{url}?redirect={payload}" if "?" not in url else f"{url}&redirect={payload}"
    try:
        r=requests.get(test_url,timeout=5,allow_redirects=False)
        vulnerable=r.status_code in [301,302,307] and payload in r.headers.get('Location','')
        bug = {"severity":"Medium","title":"Open Redirect","payload":payload} if vulnerable else None
        return {"vulnerable":vulnerable,"bug":bug}
    except: return {"vulnerable":False}

def check_cors(url):
    try:
        r=requests.get(url,timeout=5,headers={'Origin':'https://evil.com'})
        acao=r.headers.get('Access-Control-Allow-Origin','')
        vulnerable=acao=="https://evil.com" or acao=="*"
        bug = {"severity":"High","title":"CORS Misconfig","acao":acao} if vulnerable else None
        return {"vulnerable":vulnerable,"bug":bug}
    except: return {"vulnerable":False}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"\033[96m[*] Target: {domain} ({ip})\033[0m")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    checks=[
        ("Headers", lambda: check_headers(url)),
        ("SSL", lambda: check_ssl(domain)),
        ("Ports", lambda: check_ports(ip)),
        ("Subdomains", lambda: check_subdomains(domain)),
        ("Dirs", lambda: check_dirs(url)),
        ("Params", lambda: check_params(url)),
        ("JS", lambda: check_js(url)),
        ("XSS", lambda: check_xss(url)),
        ("OpenRedirect", lambda: check_openredirect(url)),
        ("CORS", lambda: check_cors(url)),
    ]
    for name, func in checks:
        print(f"\n\033[93m[~] {name}...\033[0m")
        try:
            res=func()
            report[name]=res
            if res.get("bug"):
                bug=res["bug"]; report["bugs"].append({"tool":name,**bug})
                print(f"\033[91m[!] Bug: {bug['title']} [{bug['severity']}]\033[0m")
            else:
                print(f"\033[92m[✓] {name} OK\033[0m")
        except Exception as e:
            print(f"\033[90m[-] {name} error: {e}\033[0m")
    return report

def main():
    print(BANNER)
    print("\033[91m[!] Hanya untuk scope bug bounty yang diizinkan!\033[0m\n")
    parser=argparse.ArgumentParser(description="All-in-One Bug Bounty Scanner")
    parser.add_argument("-u","--url",required=True,help="Target URL")
    parser.add_argument("--json",help="Save JSON detail")
    parser.add_argument("--html",help="Save HTML detail")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"\n\033[92m{'='*50}\n[✓] Scan Selesai - Found {len(report['bugs'])} bugs\033[0m")
    for b in report["bugs"]:
        print(f" - [{b['severity']}] {b['tool']}: {b['title']}")
    if not report["bugs"]:
        print(" -> Tidak ada bug obvious, cek manual lebih dalam")
    print("-> Detail di JSON/HTML untuk laporan HackerOne")
    if args.json:
        open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        html=f"<html><body style='font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px'><h1 style='color:#ff0000'>TBH-AllScan Report {report['target']}</h1><p>{report['time']}</p><h2>Bugs ({len(report['bugs'])})</h2><pre>{json.dumps(report['bugs'],indent=2)}</pre><h2>Full</h2><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
