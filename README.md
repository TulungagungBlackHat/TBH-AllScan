# TBH-AllScan v4.4 Pro - All-in-One Bug Bounty Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-v4.4%20Pro-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Tools-10%20in%201-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Report-JSON%20%7C%20HTML%20%7C%20Fix-blue?style=for-the-badge">
</p>

> **Gabungan 10 tools TBH dalam 1 scan** - Untuk scope bug bounty yang diizinkan. Memberikan detail bug + fix.

## ✨ Features (10 Tools)

| No | Tool | Deteksi | Severity | Fix |
|----|------|---------|----------|-----|
| 1 | **Headers** | Missing `CSP`, `HSTS`, `X-Frame-Options` | Low | Tambah header `CSP: default-src 'self'` |
| 2 | **SSL** | Expire <30 hari | Medium | Perbarui SSL Let's Encrypt |
| 3 | **Ports** | Open `80,443,8080,8443` + CVE | Info | `ufw deny 8080` |
| 4 | **Subdomains** | `www,api,admin,test,dev` | Info | Audit & hapus tidak dipakai |
| 5 | **Dirs** | `.env`, `.git`, `admin` | High/Low | Hapus `.env` dari public |
| 6 | **CORS** | `Origin: evil.com` → `ACAO: evil.com/*` | High | Set ACAO spesifik, jangan `*` |
| 7 | **XSS** | Reflected `<svg/onload=alert(1)>` | High | Encode output, CSP |
| 8 | **OpenRedirect** | `?redirect=evil.com` → `302 evil.com` | Medium | Whitelist redirect |
| 9 | **SSRF** | `?url=http://169.254.169.254` | High | Whitelist URL |
| 10 | **SQLi** | Error-based `' OR '1'='1` | High | Prepared statement |

**Bonus v4.4 Pro:**
- ✅ **Risk Score** `High=10 Medium=5 Low=2 Info=1` → Level `Critical/High/Medium/Low`
- ✅ **JSON** `report.json` siap lampiran HackerOne
- ✅ **HTML** `report.html` tabel berwarna (High merah, Low kuning)
- ✅ **Fix Script** `--fix fix.sh` auto-generate

## 📦 Install

**Termux / Kali / Linux:**
```bash
pkg update && pkg install python git
git clone https://github.com/TulungagungBlackHat/TBH-AllScan
cd TBH-AllScan
pip install requests
```

**1-Klik via Toolkit:**
```bash
git clone https://github.com/TulungagungBlackHat/TBH-Toolkit
cd TBH-Toolkit && bash install.sh  # sudah include AllScan
```

## 🚀 Usage

**Basic:**
```bash
python3 allscan.py -u https://example.com
```

**Full + Report (Recommended untuk Bug Bounty):**
```bash
python3 allscan.py -u https://example.com --json report.json --html report.html --fix fix.sh
cat report.json
cat fix.sh
# Buka report.html di browser -> screenshot untuk laporan
```

**Contoh Output:**
```
[*] example.com (172.66.147.243)
[~] Headers... [!] Missing Security Headers [Low]
[~] Ports... [!] Open Ports [Info]
[✓] Done 0.5s | Risk Low (3) | v4.4 Pro
[✓] JSON: report.json
[✓] HTML: report.html
[✓] Fix: fix.sh
```

**Detail Bug di JSON:**
```json
"bugs": [
  {"tool":"Headers","severity":"Low","title":"Missing Security Headers","fix":"Tambah CSP..."},
  {"tool":"Ports","severity":"Info","title":"Open Ports","fix":"Tutup tidak perlu"}
],
"risk_score": 3,
"risk_level": "Low"
```

## 🛡️ Aturan Bug Bounty
- Hanya scan **scope yang diizinkan** di HackerOne/Bugcrowd
- Jangan scan tanpa izin - bisa banned
- Sertakan `report.json` + `report.html` + PoC di laporan

## 👥 Credits
- **TBH - Tulungagung Black Hat** - uchil404
- Team: Tulungagung, Jawa Timur - Always Smile :)
- Tools: Gabungan TBH-Recon, PhishDetector, PortScanner, dll

## 📄 License
MIT - Educational Only

<p align="center">
  <img src="https://komarev.com/ghpvc/?username=TulungagungBlackHat-TBH-AllScan&label=Views&color=FF0000&style=flat" />
  <br>
  <b>v4.4 Pro - All-in-One Bug Bounty</b>
</p>
