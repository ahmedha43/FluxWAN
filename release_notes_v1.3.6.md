# FluxWAN v1.3.6 Release Notes

**Release Date:** October 3, 2026  
**Author:** Ahmed Al-Dulaimi (أحمد الدليمي)  
**Binary SHA-256:** `85e3e937c9cef69b67e52ee5f96f7e15c2a37b066a389d3a32c3c14a0a522eb4`  
**Binary Size:** 425,344 bytes (native musl-gcc static binary for Alpine Linux)

---

## 🎯 New Features & Enhancements in v1.3.6

### 1. Interactive Subscriber Edit (`✏️ تعديل المشترك`)
- Added dedicated **Edit Subscriber** action button (`✏️`) for every account in the Broadband User Accounts table.
- Added comprehensive Edit modal pre-filled with subscriber details:
  - Username (with backend renaming support).
  - Cleartext Password.
  - Assigned Speed Profile.
  - Static IP assignment.
  - Comments / Notes (Customer Name, Tower, Phone).
  - Expiry preservation toggle (`الإبقاء على التاريخ الحالي`) or re-calculation by validity days.
  - Instant Account Enable/Disable toggle.
- Hot-Reload on credential/profile change: If the edited subscriber has an active PPPoE session, the backend automatically disconnects and re-authenticates the session with the new credentials and TC rate limits.

### 2. Interactive Speed Profile Edit (`✏️ تعديل باقة السرعة`)
- Added dedicated **Edit Profile** button (`✏️`) next to the delete button on each profile card in the dashboard.
- Added Edit modal to adjust:
  - Profile Name (with automatic cascading to all assigned users).
  - Download Speed (Down Kbps / Mbps).
  - Upload Speed (Up Kbps / Mbps).
  - Profile Default Validity Days (e.g. 30 days, or 0 for unlimited).
  - Profile Description.
- Dynamic Profile Cascading: When a speed profile is renamed, the backend automatically updates all subscribers configured with the old profile name to use the new name.
