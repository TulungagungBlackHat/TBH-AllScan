# TBH-AllScan - All-in-One Bug Bounty Scanner

<p align="center">
  <img src="https://img.shields.io/badge/All--in--One-Bug%20Bounty-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Tools-10%20in%201-green?style=for-the-badge">
  <img src="https://img.shields.io/badge/Report-JSON%20%7C%20HTML-blue?style=for-the-badge">
</p>

> **Gabungan semua tools TBH** dalam 1 scan. Untuk scope yang diizinkan.

## ✨ Isi Scan (10 Tools)
1. Headers - Missing Security Headers (Low)
2. SSL - Expire Soon (Medium)
3. Ports - Open 80,443,8080,8443 (Info)
4. Subdomains - www,api,admin,test,dev
5. Dirs - .env/.git (High), admin/api (Low)
6. Params - Hidden params hint (Info)
7. JS - Secrets in JS (High)
8. XSS - Reflected `<svg/onload=alert(1)>` (High)
9. OpenRedirect - `?redirect=evil.com` (Medium)
10. CORS - `Origin: evil.com` (High)

## 🚀 Usage
```bash
git clone https://github.com/TulungagungBlackHat/TBH-AllScan
cd TBH-AllScan
pip install requests
python3 allscan.py -u https://example.com --json report.json --html report.html
cat report.json
# Buka report.html di browser untuk detail bug
```

## 📊 Detail Bug
Setelah scan, dapat detail:
```json
"bugs": [
  {"tool":"Headers","severity":"Low","title":"Missing Security Headers","missing":[...]},
  {"tool":"CORS","severity":"High","title":"CORS Misconfig"}
]
```

## 👥 TBH
uchil404 - Tulungagung Black Hat - Always Smile :)

## 📄 License
MIT - Edukasi
