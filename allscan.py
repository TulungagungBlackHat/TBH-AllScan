#!/usr/bin/env python3
"""TBH-AllScan v5 - All-in-one bug bounty scanner with REAL checks (authorized testing only).

Every module performs actual network requests. No fake sleeps, no hardcoded bugs.
"""
import argparse, json, os, socket, ssl, sys, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[!] requests required: pip install requests", file=sys.stderr)
    sys.exit(2)

VERSION = "5.1"
REPO = "https://github.com/TulungagungBlackHat/TBH-AllScan"

def banner():
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-AllScan v5\033[91m - Real 10 Modules   \033[91m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

SEV_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}

def build_session(args):
    s = requests.Session()
    s.headers["User-Agent"] = f"TBH-AllScan/{VERSION} (+{REPO})"
    if args.cookie:
        s.headers["Cookie"] = args.cookie
    for h in args.header or []:
        name, _, val = h.partition(":")
        if val:
            s.headers[name.strip()] = val.strip()
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    return s

def finding(module, severity, title, detail="", fix=""):
    return {"module": module, "severity": severity, "title": title, "detail": detail, "fix": fix}

def mod_headers(session, url, args):
    r = session.get(url, timeout=args.timeout)
    missing = [h for h in ["Content-Security-Policy", "Strict-Transport-Security",
                           "X-Frame-Options", "X-Content-Type-Options"] if h not in r.headers]
    bugs = [finding("Headers", "Low", f"Missing security header: {h}",
                    f"response {r.status_code}", f"Add appropriate {h} header") for h in missing]
    return bugs, {"status": r.status_code, "server": r.headers.get("Server", ""), "missing": missing}

def mod_ports(ip, args):
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    open_ports = []

    def probe(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(args.timeout if args.timeout <= 2 else 1.0)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p
        except OSError:
            pass
        finally:
            s.close()
        return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        for p in ex.map(probe, ports):
            if p:
                open_ports.append(p)
    interesting = {6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker"}
    bugs = [finding("Ports", "Info", f"Open port {p}/{interesting.get(p, 'tcp')}", "", "Verify exposure & auth") for p in open_ports]
    for p, name in interesting.items():
        if p in open_ports:
            bugs.append(finding("Ports", "High", f"{name} port {p} exposed", "often unauthenticated", "Restrict at firewall / require auth"))
    return bugs, {"open": sorted(open_ports)}

def mod_ssl(domain, args):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(args.timeout)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expire = cert.get("notAfter")
        days = (datetime.strptime(expire, "%b %d %H:%M:%S %Y %Z")
                .replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
        bugs = []
        if days < 30:
            bugs.append(finding("SSL", "Medium", f"Certificate expires in {days} days", expire, "Renew certificate"))
        return bugs, {"expire": expire, "days": days, "issuer": dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "")}
    except Exception as e:
        return [], {"note": f"no usable https: {e}"}

def mod_subdomains(domain, args):
    found = []
    for sub in ["www", "api", "admin", "mail", "dev", "staging"]:
        try:
            found.append((f"{sub}.{domain}", socket.gethostbyname(f"{sub}.{domain}")))
        except socket.gaierror:
            pass
    bugs = [finding("Subdomains", "Info", f"Live subdomain: {h} -> {ip}", "", "Add to scope & scan") for h, ip in found]
    return bugs, {"found": [h for h, _ in found]}

def mod_dirs(session, url, args):
    base = url.rstrip("/")
    paths = [".git/config", ".env", "admin", "api/docs", "backup.zip", "robots.txt", ".well-known/security.txt"]
    found = []

    def probe(path):
        try:
            r = session_probe(url, f"{base}/{path}", args)
            if r and r.status_code in (200, 401, 403):
                return {"path": path, "status": r.status_code, "length": len(r.content)}
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=7) as ex:
        for res in ex.map(probe, paths):
            if res:
                found.append(res)
    bugs = []
    for f in found:
        sev = "High" if f["path"] in (".git/config", ".env", "backup.zip") else "Low"
        bugs.append(finding("Dirs", sev, f"{f['status']} {f['path']}", f"{f['length']}b", "Remove or restrict"))
    return bugs, {"found": found}

_session_holder = {}

def session_probe(_url, target, args):
    return _session_holder["s"].get(target, timeout=args.timeout, allow_redirects=False)

def mod_cors(session, url, args):
    origin = "https://tbh-cors-test.invalid"
    r = session.get(url, timeout=args.timeout, headers={"Origin": origin})
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    acac = r.headers.get("Access-Control-Allow-Credentials", "")
    bugs = []
    if acao == origin and acac.lower() == "true":
        bugs.append(finding("CORS", "High", "Arbitrary origin + credentials", f"ACAO={acao} ACAC={acac}", "Allowlist origins"))
    elif acao == origin:
        bugs.append(finding("CORS", "Medium", "Arbitrary origin reflected", f"ACAO={acao}", "Allowlist origins"))
    elif acao == "*" and acac.lower() == "true":
        bugs.append(finding("CORS", "High", "Wildcard ACAO with credentials", f"ACAO={acao} ACAC={acac}", "Fix per spec"))
    elif acao == "*":
        bugs.append(finding("CORS", "Low", "Wildcard ACAO", "public API may be intended", "Confirm intent"))
    return bugs, {"acao": acao, "acac": acac}

def _inject(url, param, value):
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    param = param or next(iter(qs), "q")
    qs[param] = [value]
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(qs, doseq=True)))

def mod_xss(session, url, args):
    canary = "tbhxssCANARY1337"
    test = _inject(url, None, canary)
    r = session.get(test, timeout=args.timeout)
    bugs = []
    if canary in r.text:
        bugs.append(finding("XSS", "Medium", "Parameter reflects input unencoded", test, "Context-aware output encoding"))
    return bugs, {"reflected": canary in r.text, "status": r.status_code}

def mod_redirect(session, url, args):
    marker = "tbh-redirect-test.invalid"
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    param = next((k for k in ["next", "redirect", "url", "return", "dest"] if k in qs), None)
    bugs = []
    if param:
        test = _inject(url, param, f"https://{marker}/")
        r = session.get(test, timeout=args.timeout, allow_redirects=False)
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 303, 307, 308) and marker in loc:
            bugs.append(finding("OpenRedirect", "Medium", f"Open redirect via {param}", loc, "Strict allowlist"))
        return bugs, {"param": param, "status": r.status_code, "location": loc}
    return bugs, {"param": None, "note": "no redirect-ish param in URL"}

def mod_ssrf(session, url, args):
    payload = "http://169.254.169.254/latest/meta-data/"
    p = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
    param = next((k for k in ["url", "uri", "link", "dest", "next", "callback"] if k in qs), None)
    bugs = []
    if param:
        test = _inject(url, param, payload)
        r = session.get(test, timeout=args.timeout, allow_redirects=False)
        if "meta-data" in r.text.lower() or "ami-id" in r.text.lower():
            bugs.append(finding("SSRF", "High", f"Metadata endpoint reachable via {param}", test, "Allowlist outbound URLs"))
        return bugs, {"param": param, "status": r.status_code}
    return bugs, {"param": None, "note": "no url-ish param in URL"}

def mod_sqli(session, url, args):
    baseline = session.get(url, timeout=args.timeout)
    base_err = any(s in baseline.text.lower() for s in ["sql syntax", "mysql", "ora-"])
    bugs = []
    for payload in ["'", "1'"]:
        test = _inject(url, None, payload)
        r = session.get(test, timeout=args.timeout)
        leaked = any(s in r.text.lower() for s in ["sql syntax", "you have an error", "mysql_fetch", "ora-01756", "pg_query"])
        if leaked and not base_err:
            bugs.append(finding("SQLi", "High", "Database error leaked on quote injection", f"payload={payload!r}", "Parameterized queries"))
            break
    return bugs, {"tested": ["'", "1'"]}

MODULES = [
    ("Headers", mod_headers), ("Ports", None), ("SSL", None), ("Subdomains", None),
    ("Dirs", mod_dirs), ("CORS", mod_cors), ("XSS", mod_xss),
    ("OpenRedirect", mod_redirect), ("SSRF", mod_ssrf), ("SQLi", mod_sqli),
]

def allscan(url, args, use_color):
    session = build_session(args)
    _session_holder["s"] = session
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    domain = parsed.hostname or parsed.netloc
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(color("91", f"[!] cannot resolve {domain}", use_color), file=sys.stderr)
        return None

    print(color("96", f"[*] {domain} ({ip}) - real checks, ~30 requests", use_color))
    start = time.time()
    all_bugs = []
    results = {}

    for name, fn in MODULES:
        print(f"[~] {name}...", end=" ", flush=True)
        try:
            if name == "Ports":
                bugs, info = mod_ports(ip, args)
            elif name == "SSL":
                bugs, info = mod_ssl(domain, args)
            elif name == "Subdomains":
                bugs, info = mod_subdomains(domain, args)
            elif name == "Headers":
                bugs, info = fn(session, url, args)
            else:
                bugs, info = fn(session, url, args)
        except requests.RequestException as e:
            bugs, info = [], {"error": str(e)}
        results[name] = info
        all_bugs.extend(bugs)
        if bugs:
            worst = max(bugs, key=lambda b: SEV_ORDER[b["severity"]])
            print(color("91", f"[!] {len(bugs)} finding(s) worst={worst['severity']}", use_color))
        else:
            print(color("92", "[✓] ok", use_color))

    elapsed = round(time.time() - start, 2)
    weights = {"High": 25, "Medium": 10, "Low": 3, "Info": 1}
    risk = min(100, sum(weights[b["severity"]] for b in all_bugs))
    level = "Critical" if risk >= 50 else "High" if risk >= 30 else "Medium" if risk >= 15 else "Low" if risk else "None"
    report = {"tool": "TBH-AllScan", "version": VERSION, "target": domain, "ip": ip,
              "time": str(datetime.now(timezone.utc)), "elapsed": elapsed,
              "risk_score": risk, "risk_level": level,
              "summary": {"findings": len(all_bugs)}, "results": results, "findings": all_bugs}
    print(color("96" if all_bugs else "92",
                f"[✓] Done {elapsed}s | Risk {level} ({risk}) | {len(all_bugs)} findings", use_color))
    return report

def write_html(report, path):
    html = f"""<html><head><title>TBH-AllScan {report['target']}</title></head>
<body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px">
<h1 style="color:#ff0000">TBH-AllScan v{VERSION} - {report['target']} ({report['ip']})</h1>
<p>Risk: <b>{report['risk_level']} ({report['risk_score']})</b> | {report['elapsed']}s | {report['time']}</p>
<h2>Findings</h2><pre>{json.dumps(report['findings'], indent=2)}</pre>
<h2>Module details</h2><pre>{json.dumps(report['results'], indent=2)}</pre>
<p>Generated by TBH-AllScan v{VERSION} - Tulungagung Black Hat</p></body></html>"""
    with open(path, "w") as fh:
        fh.write(html)

def menu():
    print(banner())
    print("1. Scan All-in-One (10 real modules)\n2. Help\n0. Exit")
    while True:
        choice = input("\nPilih [1/2/0]: ").strip()
        if choice == "1":
            url = input("URL (ex: https://example.com): ").strip()
            if not url:
                continue
            class A: pass
            a = A(); a.cookie = None; a.header = None; a.proxy = None; a.timeout = 8.0
            report = allscan(url, a, True)
            if report and input("Simpan JSON+HTML? (y/n): ").strip().lower() == "y":
                json.dump(report, open("report.json", "w"), indent=2)
                write_html(report, "report.html")
                print("[✓] report.json + report.html")
        elif choice == "2":
            print("Command: python3 allscan.py -u https://example.com --json r.json --html r.html")
        elif choice == "0":
            print("Bye - Always Smile :)")
            break

def read_targets(path):
    targets = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except OSError as e:
        print(f"[!] cannot read targets file: {e}", file=sys.stderr)
    return targets

def main():
    parser = argparse.ArgumentParser(description=f"TBH-AllScan v{VERSION} - real 10-module scanner")
    parser.add_argument("-u", "--url", help="target URL")
    parser.add_argument("--targets", help="file with one URL per line (multi-target)")
    parser.add_argument("--json", help="save JSON")
    parser.add_argument("--html", help="save HTML (single target only)")
    parser.add_argument("--proxy", help="e.g. http://127.0.0.1:8080")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("-H", "--header", action="append", help="extra header, repeatable")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-AllScan {VERSION}")
    args = parser.parse_args()

    if not args.url and not args.targets:
        if len(sys.argv) == 1:
            menu()
            return
        parser.error("-u or --targets is required")

    print(banner())
    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    print(color("91", "[!] Authorized targets only.", use_color))
    targets = ([args.url] if args.url else []) + (read_targets(args.targets) if args.targets else [])

    reports = []
    for i, t in enumerate(targets):
        if i > 0 and args.targets:
            print(color("96", "-" * 40, use_color))
        r = allscan(t, args, use_color)
        if r:
            reports.append(r)

    if not reports:
        sys.exit(2)

    if args.json:
        data = (reports[0] if len(reports) == 1 else
                {"tool": "TBH-AllScan", "version": VERSION,
                 "summary": {"targets": len(reports),
                             "findings": sum(len(r["findings"]) for r in reports)},
                 "targets": reports})
        try:
            with open(args.json, "w") as fh:
                json.dump(data, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)
    if args.html:
        if len(reports) > 1:
            print(color("93", "[!] --html is single-target; skipped for multi-target scan", use_color))
        else:
            try:
                write_html(reports[0], args.html)
                print(f"[✓] HTML: {args.html}")
            except OSError as e:
                print(color("91", f"[!] cannot write HTML: {e}", use_color), file=sys.stderr)
                sys.exit(2)

    sys.exit(1 if any(r["findings"] for r in reports) else 0)

if __name__ == "__main__":
    main()
