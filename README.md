# TBH-AllScan

<p align="center">
  <a href="https://github.com/TulungagungBlackHat/TBH-AllScan/actions/workflows/ci.yml"><img src="https://github.com/TulungagungBlackHat/TBH-AllScan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/tools-10-orange.svg" alt="Modules">
</p>

All-in-one bug bounty scanner: 10 security checks, one command, one report. Interactive menu for beginners, flags for automation.

Part of the [Tulungagung Black Hat](https://github.com/TulungagungBlackHat) toolset.

## Modules

| # | Module | Severity | Typical fix |
|---|--------|----------|-------------|
| 1 | Security headers | Low | Add CSP / HSTS |
| 2 | SSL certificate | Medium | Renew before expiry |
| 3 | Open ports | Info | Close unused ports |
| 4 | Subdomains | Info | Audit forgotten assets |
| 5 | Sensitive directories | High | Remove `.env` / `.git` exposure |
| 6 | CORS misconfig | High | Restrict `Access-Control-Allow-Origin` |
| 7 | Reflected XSS | High | Context-aware output encoding |
| 8 | Open redirect | Medium | Strict allowlist |
| 9 | SSRF | High | Allowlist outbound destinations |
| 10 | SQL injection | High | Parameterized queries |

Plus a **risk score** and JSON + HTML reports with remediation notes.

## Install

```bash
git clone https://github.com/TulungagungBlackHat/TBH-AllScan
cd TBH-AllScan
pip install -r requirements.txt
```

## Usage

**Interactive menu** (no flags to remember):

```bash
python3 allscan.py
```

**Direct command** (for scripts and CI):

```bash
python3 allscan.py -u https://example.com --json report.json --html report.html
```

## Sample Output

```
[*] example.com (93.184.216.34)
[~] Headers...   [!] Bug [Low]
[~] Ports...     [!] Bug [Info]
[~] CORS...      [✓] OK
[~] XSS...       [✓] OK
[✓] Done 4.2s | Risk: Low (3/100) | 10 modules
[✓] JSON: report.json
[✓] HTML: report.html
```

## vs TBH-CLI

| | **TBH-AllScan** | [**TBH-CLI**](https://github.com/TulungagungBlackHat/TBH-CLI) |
|---|---|---|
| Modules | 10 | 35 (terminal-only) |
| Output | JSON + HTML + fixes | Terminal only |
| Best for | Reports & submissions | Interactive hunting |

## Authorized Use Only

Only run against scopes you're authorized to test. Every module sends only safe, non-destructive probes — but safe probes against unauthorized systems are still unauthorized. See [SECURITY.md](SECURITY.md).

## Related Tools

- [TBH-Toolkit](https://github.com/TulungagungBlackHat/TBH-Toolkit) — one-line installer for the whole toolset
- [TBH-BugBounty](https://github.com/TulungagungBlackHat/TBH-BugBounty) — hunter workflow with HackerOne-ready JSON

## License

[MIT](LICENSE) — Tulungagung Black Hat, East Java, Indonesia. Always Smile :)
