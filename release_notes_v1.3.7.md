# FluxWAN v1.3.7 Release Notes — WireGuard & ZeroTier VPN Remote Access Hub

**Release Date:** October 3, 2026  
**Author:** Ahmed Al-Dulaimi (أحمد الدليمي)  
**Binary Target:** Linux x86_64 (`musl-gcc` static Alpine appliance build)  
**SHA-256 Checksum:** `5d4dd317745b036af5c186c49a9c6f76746fc18cfb2c99f92640c05511b675d4`  
**Binary Size:** `466,304` bytes  

---

## 🌟 Highlights & New Capabilities

### 1. WireGuard VPN Server & Peer Manager (🔐)
- **High-Speed Kernel WireGuard Engine:** Native Linux `wg` tunnel driver interface (`wg0`) with UDP listening port (default `51820`), configurable server subnet (default `10.250.0.1/24`), and master on/off switch.
- **Auto-Keypair & 1-Click QR Code Generator (📱):** Instant Curve25519 cryptographic keypair generation directly in browser and backend. Displays an instant scannable high-contrast QR Code compatible with official WireGuard apps on iPhone, Android, Windows, Mac, and Linux.
- **Client Profile (.conf) One-Click Download:** Generates and downloads ready-to-use client `.conf` configuration files with auto-assigned client virtual IPs (`10.250.0.2/32`, `10.250.0.3/32`, etc.).
- **Live Peer Telemetry:** Real-time monitoring of peer connection status, handshake timestamps (active / idle / never connected), real-time bandwidth consumption (bytes RX / TX), and observed remote endpoint IPs.

### 2. ZeroTier SDN Cloud Mesh (🌐)
- **ZeroTier Service Integration:** Native integration with `zerotier-one` and `zerotier-cli`.
- **Node ID 1-Click Access:** Displays the router's 10-hex ZeroTier Node ID with a 1-click copy button and a direct link to `my.zerotier.com` to easily authorize the router.
- **Multi-Network Joiner:** Join and manage multiple ZeroTier virtual networks simultaneously by entering 16-hex Network IDs.
- **Dynamic Network Status & IP Tracking:** Monitors real-time network states (`OK`, `ACCESS_DENIED`, `REQUESTING`), device interfaces (`zt0`), and assigned virtual IP addresses.

### 3. Full Remote Router Management & Firewall Bypass (🚀)
- **Worldwide Web Dashboard & SSH Access:** Automatically manages `iptables` input rules on `wg0` and `zt+` interfaces.
- Allows administrators to securely open the FluxWAN web dashboard (`http://10.250.0.1:8080` or `http://[ZeroTier-IP]:8080`) and SSH from anywhere in the world without requiring a public static IP or configuring port forwarding on ISP modems.
- NAT Masquerade and L3 forwarding for seamless remote access to local LAN subnets.

---

## 🛠️ Verification & Quality Assurance
- **Static Compilation:** Built exclusively with `musl-gcc` in Ubuntu 24.04 (WSL `SILAB`) targeting Alpine Linux.
- **Lab Benchmark Suite:** 100% pass on Maglev consistent hashing, zero-drop sticky persistence, sub-millisecond failover, and RFC 2131 DHCP allocation.
- **Embedded Web UI:** Pre-compressed gzip assets embedded directly into the C binary for standalone zero-dependency execution.
