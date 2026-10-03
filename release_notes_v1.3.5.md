# FluxWAN v1.3.5 Release Notes

**Release Date:** October 3, 2026  
**Author:** Ahmed Al-Dulaimi (أحمد الدليمي)  
**Binary SHA-256:** `d78e0a397777ad0aa17065d91562833186d30b7b60d9d95121c6aad3963b4963`  
**Binary Size:** 421,248 bytes (native musl-gcc static binary for Alpine Linux)

---

## 🎯 Critical Fixes & Enhancements in v1.3.5

### 1. Fix JSON Buffer Truncation at 16,383 Bytes (`GET /api/v1/broadband/status`)
- **Root Cause:** The endpoint buffer allocated for broadband subscriber and server status was statically capped at 16KB (`16384` bytes). When subscriber count exceeded ~60–70 accounts (e.g. 74 users in `usersankk_20261003110640_1.xlsx`), the JSON response was cut off mid-string at position 16383 (`Unterminated string in JSON`). This threw a silent `SyntaxError` in the browser console, causing the "Broadband User Accounts" table to render completely empty (0 users).
- **Resolution:** Upgraded the status JSON buffer to a 4 MB streaming buffer (`4194304` bytes) and the active sessions buffer to 2 MB (`2097152` bytes). Implemented socket chunk streaming with strict `Content-Length` headers, allowing seamless handling of thousands of subscribers.

### 2. Subscriber Database Protection Against Accidental Apply Wipes
- **Root Cause:** When general settings were applied (`POST /api/v1/apply`), if the payload sent an empty `users: []` array (triggered when status failed to load), the server overwrote `test_cfg->pppoe_server.users` with 0 users.
- **Resolution:** 
  1. Backend unconditionally preserves `ctx->config->pppoe_server.users` and `profiles` during `/api/v1/apply` if the payload provides 0 users/profiles while active ones exist.
  2. Frontend `saveAndApply()` strips `users` and `profiles` from general apply payloads, isolating subscriber management exclusively to dedicated broadband endpoints.

### 3. Clean Profile Replacement on Bulk Import
- **Root Cause:** In bulk import with `replace_mode = true`, `pppoe_server_bulk_import()` reset `cfg->user_count = 0` but left `cfg->profile_count` intact with the default factory profiles (`Economy_10M`, `Standard_25M`, `Turbo_100M`, `Gaming_Pro`). This resulted in unrelated profiles remaining in the database alongside imported ones.
- **Resolution:** In `replace_mode`, when new profiles are supplied from Excel or SAS4, `cfg->profile_count` is reset to 0, ensuring only actual user profiles (such as `BASIC`) exist.

### 4. Deep SAS4 API Password & Profile Enrichment
- **Enhancement:** When syncing directly with SAS4 Billing API, user rows missing cleartext passwords or specific profile names from `/index/user` are automatically enriched via concurrent batched queries to `/user/overview/{id}` with Bearer token authentication.

### 5. Alpine JS Expression Safeguard
- **Fix:** Fixed `wan.scannedNetworks.length` evaluating against `undefined` during initial page load, eliminating console exceptions.
