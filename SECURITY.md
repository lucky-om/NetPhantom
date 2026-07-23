# NetPhantom Security Policy & Compliance Baseline

## Security Scope & Architecture

NetPhantom is a local network sniffer, deep packet inspection utility, and threat analysis console. Security, local data privacy, and zero telemetry are enforced across both the Python desktop runtime engine and the web frontend.

---

## 1. Secrets & Environment Configuration
- [x] **No Hardcoded Secrets**: Secrets, credentials, API tokens, and private keys are never hardcoded or committed into repository history.
- [x] **Environment Exclusion**: `.env` and `.env.*` files are explicitly excluded via `.gitignore`.
- [x] **Template Provided**: `.env.example` is maintained to standardise environment configuration across development and deployment.
- [x] **Dump File Protection**: Raw packet dumps (`*.pcap`, `*.cap`, `*.pcapng`), key logs (`*.pem`, `*.key`), and runtime backups are guarded against accidental git commits.

---

## 2. Input Validation & XSS Prevention
- [x] **Client-side Sanitization**: All user-controlled text inputs in the web interface (CLI shell fields, BPF filter sandbox inputs, search query fields) are sanitized via HTML entity escaping (`escapeHtml()`) before DOM insertion to prevent XSS (Cross-Site Scripting).
- [x] **BPF Filter Validation**: The Scapy capture engine validates Berkeley Packet Filter expressions server/runtime side and falls back safely to default capture filters if an invalid expression is entered, preventing execution crashes.

---

## 3. Transport & HTTP Security Headers
- [x] **Security Headers**: Standard security meta tags are enforced across all HTML pages:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- [x] **Local RAM Storage**: Packet payloads and threat analysis logs reside exclusively in volatile local RAM and are purged upon application termination.
- [x] **Zero Telemetry**: No tracking scripts, analytics beacons, or remote logging services exist in the codebase.

---

## 4. Authorization & OS Privilege Model
- [x] **Privilege Escalation Gate**: Raw socket capture operations strictly require Administrator (Windows UAC) or `root` (`sudo` on Linux) privileges.
- [x] **Graceful Fallback**: Unprivileged invocation attempts trigger clean UI warnings rather than uncaught stack trace exceptions.

---

## 5. Dependency Audit & Maintenance
- [x] **Minimal Dependency Tree**: Dependencies are restricted to audited core libraries (`scapy`).
- [x] **Clean Vulnerability Baseline**: `pip-audit` and `npm audit` checks are routinely run prior to release.

---

## Ethical & Legal Usage Notice
This software is intended for educational, auditing, and ethical cybersecurity analysis only. Users are responsible for complying with all applicable local, national, and international privacy and wiretapping laws. Unauthorized network monitoring without explicit authorization from the network owner is strictly prohibited.
