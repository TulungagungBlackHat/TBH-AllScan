# Changelog

## Unreleased

- Ecosystem standardization: SECURITY.md, CONTRIBUTING.md, requirements, CI smoke checks.

## 1.0.0 (2026-09-18)

- Initial stable single-tool release (educational, authorized-use only).

## [5.0.0] - 2026-10-10
### Fixed
- ALL 10 modules now perform REAL network checks (v4.5 simulated results with sleeps)
### Added
- Real header audit, port scan (17 ports), SSL expiry, subdomain DNS, dir probe, CORS/XSS/Redirect/SSRF/SQLi checks
- Risk scoring (High=25/Med=10/Low=3/Info=1 capped 100), findings list with fixes
- Unified TBH v3 CLI: --proxy, --cookie, -H, --timeout, --json, --html, --version
- Exit codes: 0 clean, 1 findings, 2 error
