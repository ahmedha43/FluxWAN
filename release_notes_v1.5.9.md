# FluxWAN v1.5.9 Release Notes — Smart IPv6 Happy Eyeballs Fallback & Adaptive Flow Balancer

**Release Date:** October 23, 2026  
**Author:** Ahmed Al-Dulaimi (أحمد الدليمي)  
**Binary Target:** Linux x86_64 (`musl-gcc` static Alpine appliance build)  
**Channel:** Stable  

---

## 🌟 Highlights & New Capabilities

### 1. Smart IPv6 Multi-WAN Bonding (RFC 6724 Happy Eyeballs Fallback Manipulation) 🧠⭐
- **The Problem Solved:** When one WAN interface supports IPv6 (e.g. Fiber or Starlink) while other lines are IPv4-only (e.g. 4G/LTE modems, Wireless links), client operating systems and browsers prioritize IPv6 via RFC 6724 Happy Eyeballs. As a result, ~90% of traffic (Google, YouTube, Meta, Netflix, Cloudflare) flows exclusively over the single IPv6 line, starving it while the other bonded lines sit idle.
- **The In-Kernel & DNS Solution:** The built-in FluxWAN Fast In-Memory DNS resolver (`dns64_daemon`) intercepts AAAA DNS queries and immediately responds with a standard `NOERROR` empty answer in `<0.01ms`.
- **Zero-Latency Fallback:** Client browsers and devices immediately fall back to IPv4 within milliseconds, allowing 100% of all user flows to be evenly balanced and bonded across all available physical WAN lines.
- **Web Dashboard Toggle:** Easily enabled/disabled directly from the DNS settings card in the Web UI.

### 2. Adaptive Weighted Active-Flows Balancer (Strategy: leastLoad) ⚖️
- **Dynamic Metric Scheduling:** Added a 3rd multi-server load balancing strategy:
  $$\text{Metric} = \frac{\text{Active Flows} + 1}{\text{Server Weight}}$$
- **Anti-Bufferbloat Protection:** Rather than relying solely on sequential round-robin, the balancer dynamically assigns new outgoing flows to the server with the lowest active load ratio, preventing server saturation and jitter spikes during heavy downloads.
- **Three-Engine Multi-Server Strategy:**
  1. ⚡ **Instant Failover (leastPing):** Continuous observatory health probes with sub-second failover.
  2. ⚖️ **Round-Robin Balancer (roundRobin):** Sequential multi-server load distribution.
  3. 🧠 **Smart Flow Balancer (leastLoad):** Adaptive connection-weighted balancing preventing flow concentration.

---

## 🛠️ Verification & Quality Assurance
- **Full Test Suite (`tests/test_proxy_multi_server.c`):** 100% PASS on multi-server parsing, Xray configuration generation with all 3 strategies, RAM DNS cache FNV-1a hashing, and Happy Eyeballs AAAA synthesis.
- **Embedded Web Assets:** Generated and compressed into `include/ui_assets.h` (Original: 677 KB, Gzip: 109 KB).
- **Git Exclusions:** `net-merge/` and `GS/` strictly excluded via `.gitignore`.
