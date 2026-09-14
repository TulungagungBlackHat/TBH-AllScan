# TBH-AllScan v4.5 Pro - Menu + Command | All-in-One Bug Bounty Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-v4.5%20Pro-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Menu%20%2B%20Command-v4.5-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Termux-Ready-orange?style=for-the-badge">
</p>

> **Gabungan 10 tools TBH dalam 1 scan** - Sekarang bisa **menu interaktif** atau **command langsung**.

## ✨ Features (10 Tools)

| No | Tool | Severity | Fix |
|----|------|----------|-----|
| 1 | Headers | Low | Tambah CSP/HSTS |
| 2 | SSL | Medium | Renew SSL |
| 3 | Ports | Info | Tutup tidak perlu |
| 4 | Subdomains | Info | Audit |
| 5 | Dirs | High | Hapus .env/.git |
| 6 | CORS | High | Set ACAO spesifik |
| 7 | XSS | High | Encode output |
| 8 | OpenRedirect | Medium | Whitelist |
| 9 | SSRF | High | Whitelist URL |
| 10 | SQLi | High | Prepared statement |

**Bonus:** Risk Score + JSON + HTML + Fix

## 📦 Install (Termux / Kali / Linux)

**Langkah 1 - Install Python & Git:**
```bash
pkg update && pkg install python git
```

**Langkah 2 - Clone:**
```bash
git clone https://github.com/TulungagungBlackHat/TBH-AllScan
cd TBH-AllScan
pip install requests
```

## 🚀 Cara Jalanin (2 Cara)

### Cara 1 - Menu Interaktif (Gampang, Tanpa Hafal Command)
```bash
python3 allscan.py
```
Muncul:
```
Pilih mode:
 1. Scan All-in-One (10 tools)
 2. Bantuan
 0. Keluar
Pilih [1/2/0]: 1
Masukkan URL (ex: https://example.com): https://example.com
```
Scan langsung, tanya `Simpan JSON+HTML? (y/n)` → `y` → `report.json` & `report.html` jadi.

### Cara 2 - Command Langsung (Untuk Hafal Command)
```bash
python3 allscan.py -u https://example.com --json report.json --html report.html
cat report.json
# Buka report.html di browser
```

### Bantuan
```bash
python3 allscan.py -h
```

## 📸 Contoh Output
```
[*] example.com (172.66.147.243)
[~] Headers... [!] Bug [Low]
[~] Ports... [!] Bug [Info]
[✓] Done 0.5s | Risk Low (3) | 10 Tools
[✓] JSON: report.json
```

## vs CLI
| | **AllScan** | **TBH-CLI** |
|---|---|---|
| **Tools** | 10 lengkap | 2 ringan |
| **Output** | JSON+HTML+Fix | Terminal saja |
| **Cara** | Menu + Command | Menu + Command |

## 🛡️ Aturan
Hanya untuk scope yang diizinkan!

## 👥 TBH
uchil404 - Tulungagung Black Hat - Always Smile :)

## 📄 License
MIT - Educational Only
