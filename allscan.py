#!/usr/bin/env python3
# TBH-AllScan v2.0 Pro - + Fix Suggestions
import socket, requests, argparse, json, re, ssl, urllib.parse
from datetime import datetime

BANNER = """\033[91m╔════════════════════════════════════════╗
\033[91m║ \033[97mTBH-AllScan v2.0 Pro \033[91m- Fix Suggestions\033[91m║
\033[91m║ \033[90mTulungagung Black Hat | uchil404     \033[91m║
\033[91m╚════════════════════════════════════════╝\033[0m"""

def check_headers(url):
    try:
        r=requests.get(url,timeout=5,headers={'User-Agent':'TBH-AllScan/2.0'})
        missing=[h for h in ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options'] if h not in r.headers]
        if missing:
            fix="Tambah header: Content-Security-Policy: default-src 'self'; Strict-Transport-Security: max-age=31536000; X-Frame-Options: DENY"
            bug={"severity":"Low","title":"Missing Security Headers","missing":missing,"fix":fix}
        else: bug=None
        return {"status":r.status_code,"server":r.headers.get('Server','Unknown'),"missing":missing,"bug":bug}
    except Exception as e: return {"error":str(e)}

def check_ssl(domain):
    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=domain) as s:
            s.settimeout(3); s.connect((domain,443)); cert=s.getpeercert()
            expire=cert.get('notAfter'); days=(datetime.strptime(expire,"%b %d %H:%M:%S %Y %Z")-datetime.utcnow()).days
            if days<30:
                bug={"severity":"Medium","title":"SSL Expire Soon","days":days,"fix":"Perbarui SSL cert segera, auto-renew via Let's Encrypt"}
            else: bug=None
            return {"expire":expire,"days":days,"bug":bug}
    except: return {"note":"no https"}

def check_ports(ip):
    open_ports=[]
    for p in [80,443,8080,8443]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.settimeout(1)
        if s.connect_ex((ip,p))==0: open_ports.append(p)
        s.close()
    bug={"severity":"Info","title":"Open Ports","ports":open_ports,"fix":"Tutup port yang tidak perlu, firewall hanya 80/443"} if open_ports else None
    return {"open":open_ports,"bug":bug}

def check_subdomains(domain):
    found=[]
    for sub in ["www","api","admin","test","dev"]:
        try: socket.gethostbyname(f"{sub}.{domain}"); found.append(f"{sub}.{domain}")
        except: pass
    bug={"severity":"Info","title":"Subdomains Found","found":found,"fix":"Audit subdomain, hapus yang tidak dipakai, cek takeover"} if found else None
    return {"found":found,"bug":bug}

def check_dirs(url):
    found=[]
    for path in ["admin","api",".env",".git","robots.txt"]:
        full=f"{url.rstrip('/')}/{path}"
        try:
            r=requests.get(full,timeout=3,allow_redirects=False)
            if r.status_code in [200,301,302,403]:
                severity="High" if path in [".env",".git"] else "Low"
                fix="Hapus/.env/.git dari public, block di nginx" if path in [".env",".git"] else "Auth untuk /admin, rate limit"
                found.append({"path":path,"status":r.status_code,"severity":severity,"fix":fix})
        except: pass
    bug={"severity":"High","title":"Sensitive Dir","found":found,"fix":"Hapus file sensitif dari web root"} if any(f["path"] in [".env",".git"] for f in found) else None
    return {"found":found,"bug":bug}

def check_cors(url):
    try:
        r=requests.get(url,timeout=5,headers={'Origin':'https://evil.com'})
        acao=r.headers.get('Access-Control-Allow-Origin','')
        if acao=="https://evil.com" or acao=="*":
            bug={"severity":"High","title":"CORS Misconfig","acao":acao,"fix":"Set ACAO ke domain spesifik, jangan * + true"}
            return {"vulnerable":True,"bug":bug}
        return {"vulnerable":False}
    except: return {"vulnerable":False}

def allscan(url):
    domain=urllib.parse.urlparse(url if url.startswith("http") else "https://"+url).netloc
    ip=socket.gethostbyname(domain)
    print(f"[*] Target: {domain} ({ip})")
    report={"target":domain,"ip":ip,"url":url,"time":str(datetime.now()),"bugs":[]}
    checks=[("Headers",lambda: check_headers(url)),("SSL",lambda: check_ssl(domain)),("Ports",lambda: check_ports(ip)),("Subdomains",lambda: check_subdomains(domain)),("Dirs",lambda: check_dirs(url)),("CORS",lambda: check_cors(url))]
    for name, func in checks:
        print(f"\n[~] {name}...")
        res=func(); report[name]=res
        if res.get("bug"):
            bug=res["bug"]; report["bugs"].append({"tool":name,**bug})
            print(f"[!] {bug['title']} [{bug['severity']}] -> Fix: {bug.get('fix','')[:50]}")
        else: print(f"[✓] {name} OK")
    return report

def main():
    print(BANNER)
    print("[!] Hanya untuk scope yang diizinkan!\n")
    parser=argparse.ArgumentParser(description="AllScan v2.0 Pro")
    parser.add_argument("-u","--url",required=True)
    parser.add_argument("--json",help="Save JSON")
    parser.add_argument("--html",help="Save HTML")
    args=parser.parse_args()
    report=allscan(args.url)
    print(f"\n[✓] Found {len(report['bugs'])} bugs")
    for b in report["bugs"]:
        print(f" - [{b['severity']}] {b['tool']}: {b['title']} | Fix: {b.get('fix','')[:60]}")
    if args.json: open(args.json,'w').write(json.dumps(report,indent=2)); print(f"[✓] JSON: {args.json}")
    if args.html:
        bugs_html="".join([f"<li><b>[{b['severity']}] {b['tool']}: {b['title']}</b><br>Fix: {b.get('fix','')}</li>" for b in report["bugs"]])
        html=f"<html><body style='font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px'><h1>TBH-AllScan v2.0 Pro {report['target']}</h1><p>{report['time']}</p><h2>Bugs + Fix ({len(report['bugs'])})</h2><ul>{bugs_html}</ul><h2>Full JSON</h2><pre>{json.dumps(report,indent=2)}</pre></body></html>"
        open(args.html,'w').write(html); print(f"[✓] HTML: {args.html}")

if __name__=="__main__": main()
