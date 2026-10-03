## FluxWAN v1.3.4 - SASMAN & SAS4 Billing Migration Engine

### What's New
- **SASMAN Migration Engine**:
  - Full support for Microsoft Excel (`.xlsx`, `.xls`) and CSV subscriber import & export.
  - Interactive visual preview table with auto-detection of usernames, cleartext passwords, speed profiles, static IPs, comments, and phone numbers.
  - Automatic expiration date converter supporting Excel serial numbers (e.g. `46056.74`), Unix timestamps, and ISO datetime strings (`YYYY-MM-DD HH:MM:SS`).
- **Direct SAS4 Billing System API Sync**:
  - Integrated OpenSSL-compatible AES-256-CBC decryptor with the official SAS4 passphrase (`abcdefghijuklmno0123456789012345`).
  - Automated multi-page subscriber extraction and deep sync with live progress percentage.
- **Enterprise Capacity & Performance**:
  - Increased PPPoE subscriber capacity from 256 to 4,096 concurrent subscriber accounts.
  - Increased bandwidth speed profile definitions from 32 to 64 profiles.
  - Increased active connected sessions ceiling from 256 to 1,024 sessions.
- **Export & Backup**:
  - 1-click export to native Microsoft Excel (`.xlsx`) with formatted column tables.
  - 1-click export to standard CSV template 100% compatible with SASMAN and MikroTik.
- **API & Security**:
  - HTTP OPTIONS CORS preflight support for external integrations.
  - Musl-gcc native compilation for 100% Alpine Linux and x86_64 hardware compatibility.

### OTA Binary SHA256
34a7fe8a25bc560d0f7084286c63477b82f4b8861cb4366d2f704ada5f36eed9
