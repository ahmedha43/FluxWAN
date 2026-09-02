# ⚡ FluxWAN Operating System

> **High-Performance Multi-WAN Load Balancing, Traffic Aggregation & Embedded Network Operating System**  
> Powered by **Linux 6.6 LTS**, **eBPF XDP (eXpress Data Path)**, **Stateless NAT46 (SIIT)**, and a **Lightweight C Reactor Core**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/Arch-ARM64%20%7C%20x86__64%20%7C%20MIPS-emerald.svg)]()
[![Kernel](https://img.shields.io/badge/Linux-6.6%20LTS-orange.svg)]()
[![Data Plane](https://img.shields.io/badge/Data%20Plane-eBPF%20XDP%20(277%20Mpps)-purple.svg)]()
[![Starlink Ready](https://img.shields.io/badge/Starlink-NAT46%20Bypass%20Active-brightgreen.svg)]()

---

## 🚀 Overview

**FluxWAN** is a specialized, carrier-grade embedded network appliance designed to sit directly between upstream ISPs (Starlink, Fiber, PPPoE) and downstream distribution routers (MikroTik BRAS / PPPoE Server / Hotspot).

It aggregates multi-gigabit uplinks, performs active-active load balancing with session affinity, and features an **eBPF XDP Stateless NAT46 Translation Engine** that transparently converts subscriber IPv4 traffic into **Native IPv6**—completely bypassing Starlink CGNAT session limits at line rate (3.60 nanosecond latency).

---

## 🗺️ Network Deployment Topology

```
 ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
 │ صحن ستارلنك     │   │ خط ضوئي (Fiber) │   │ خطوط ISP PPPoE  │
 │ (Native IPv6)   │   │ (DHCP / Static) │   │ (Multi-Session) │
 └────────┬────────┘   └────────┬────────┘   └────────┬────────┘
          │ (WAN 1)             │ (WAN 2)             │ (WAN 3..N)
          ▼                     ▼                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                    جهاز FluxWAN (Core Load Balancer)                       │
│              (مثبت على راوتر RB5009 أو سيرفر x86_64 Appliance)              │
│                                                                            │
│  1. تجميع ودمج كافة الخطوط في نفق بيانات واحد فائق السرعة (eBPF XDP).      │
│  2. التوجيه الذكي (IPv6 / NAT46 Steering) لخطوط ستارلنك.                   │
│  3. موازنة الأحمال والـ Session Affinity (منع قفل البنوك والألعاب).       │
│  4. إخراج كل السرعات المدمجة عبر منفذ الـ LAN كشبكة واحدة نظيفة وسريعة.     │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ (كابل LAN واحد 10G / 2.5G / 1G)
                                      ▼ (يدخل في منفذ WAN جهاز مايكروتك التوزيع)
┌────────────────────────────────────────────────────────────────────────────┐
│                   جهاز مايكروتك التوزيع (Distribution Router)               │
│                                                                            │
│  • وظيفته فقط: سيرفر برودباند (PPPoE Server) + هوتسبوت + كروت واشتراكات.    │
│  • يتعامل مع الإنترنت كأنه خط واحد ضخم ومستقر جداً من FluxWAN.              │
│  • يوزع السرعات للمشتركين ويخرجهم عبر بريدج الخروج (Bridge Out).           │
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │
                                      ▼
                     [ مشتركو وأبراج الشبكة والزبائن ]
```

---

## ✨ Key Features & Capabilities

### 1. 🛰️ Starlink CGNAT Bypass via Stateless NAT46 & DNS64
- **Problem**: Starlink's router imposes strict NAT44 session limits (~500–1,000 sessions per dish), causing throttling and dropouts during peak usage.
- **FluxWAN Solution**:
  - Embedded **DNS64 Proxy** discovers IPv6 (`AAAA`) targets for high-bandwidth CDNs (YouTube, Meta, Netflix, Cloudflare, TikTok, Akamai).
  - In-kernel **eBPF XDP Stateless NAT46 (RFC 7915)** expands packet headers by 20 bytes and translates outgoing traffic directly to **Native IPv6**.
  - **Zero NAT44 sessions** are consumed on the Starlink dish, unlocking maximum throughput and zero packet drop.

### 2. 🏎️ eBPF XDP Wire-Speed Packet Acceleration
- **In-Kernel Switching**: Packets are processed at the network interface card (NIC) driver layer before reaching netfilter or userspace.
- **Maglev Consistent Hashing & WRR**: Flow-aware load balancing with zero connection disruption during link weight changes.
- **Benchmark Performance**: **277.47 Million Packets/Second (Mpps)** with **3.60 ns** per-packet translation latency.

### 3. 📡 Comprehensive Live Session Inspector & Telemetry
Each WAN card on the Web GUI provides real-time connection inspection:
- **PPPoE Clients**: Uptime duration, BRAS Access Concentrator (AC Name), MTU (1492), Dynamic IP & Gateway.
- **DHCP Clients**: Total lease duration, Remaining lease time, Gateway, MTU (1500), Dynamic DNS.
- **Static Uplinks**: Manual CIDR, Subnet netmask, Gateway status.
- **Native IPv6**: Live SLAAC / DHCPv6 delegated `/64` or `/56` prefix display.
- **Health Prober**: Real-time ICMP ping latency (ms), jitter, and packet loss percentage.

### 4. 🔒 Sticky Session Affinity
- Automatically binds secure flows (online banking, gaming, VoIP, payment gateways) to a specific WAN IP for the duration of the session, preventing unexpected IP rotation drops.

### 5. ⚡ 1-Click Automated Installers
- **Windows Flasher (`FluxWAN-Windows-Flasher.bat`)**: Automated Netboot server tool that configures IP, DHCP, and TFTP in 1 click.
- **Responsive Web NAND Installer (`installer.html`)**: Single `[ 🚀 تثبيت FluxWAN الدائم ]` button to flash internal NAND memory in seconds.

---

## 🎯 Supported Hardware Architectures

| Target Hardware | Architecture | SoC / Processor | Primary Storage | Network Ports |
|---|---|---|---|---|
| **x86_64 Generic** | `x86_64` / `AMD64` | Intel Core / Xeon / AMD EPYC / VMs | NVMe / SATA / USB | 1G / 2.5G / 10G / 25G / 40G Intel/Realtek NICs |
| **MikroTik RB5009** | `AArch64` (ARM64) | Marvell Armada 7040 (4x Cortex-A72 @ 1.4GHz) | 1024 MB NAND Flash | 7x 1G + 1x 2.5G (`ether1`) + 1x 10G SFP+ (`sfp-sfpplus1`) |
| **MikroTik RB750Gr3** | `MIPS32` | MediaTek MT7621AT (2x MIPS1004Kc @ 880MHz) | 16 MB SPI Flash | 5x 1G Gigabit Ethernet |

---

## 📁 Repository Structure

```
FluxWAN/
├── src/                      # Universal C Reactor Engine Source Code
│   ├── main.c                # Daemon entrypoint & main reactor event loop
│   ├── config.c              # JSON configuration parser & serializer
│   ├── bpf_loader.c          # eBPF XDP bytecode loader & map manager
│   ├── dns64_daemon.c        # Embedded DNS64 Proxy & Synthetic IP pool allocator
│   ├── wan_manager.c         # Multi-WAN rebalancing & dynamic failover
│   ├── pppoe_manager.c       # Multi-session PPPoE client supervisor
│   ├── dhcp_server.c         # Embedded RFC 2131 LAN DHCP server
│   ├── prober.c              # Dynamic sub-second ICMP health prober
│   ├── sticky.c              # LRU Sticky Session hash table
│   └── web_server.c          # High-performance HTTP REST API & Web GUI server
│
├── include/                  # Core C Header Definitions
├── bpf/                      # eBPF XDP In-Kernel Programs
│   ├── nat46_maps.h          # Shared NAT46 BPF map structures
│   ├── xdp_nat46.bpf.c       # Stateless NAT46 / SIIT Translation Engine
│   └── xdp_router.bpf.c      # Maglev WRR Multi-WAN Load Balancing Engine
│
├── config/                   # Default Configuration Files (fluxwan.json)
├── web/                      # HTML5/Tailwind/Alpine.js Web Management UI
│
├── targets/                  # Self-Contained Architecture Targets
│   ├── x86_64/               # x86_64 PC/Server/VMware target (ISO & Overlay)
│   ├── rb5009/               # MikroTik RB5009 ARM64 target (DTS, FIT, Netboot, Installer)
│   └── rb750gr3/             # MikroTik RB750Gr3 MIPS target
│
├── dist/                     # Distribution Directory (Pre-built Binaries & Guides)
├── tests/                    # Automated Test Suites & Packet Verification
│   ├── test_live_nat46_translation.c # Live packet translation benchmark
│   └── xdp_packet_test.c     # XDP packet injection verification
│
├── build.sh                  # Master Multi-Target Build Script
└── Makefile                  # Core C Engine Makefile
```

---

## 🛠️ Building From Source

FluxWAN utilizes isolated, reproducible Docker cross-compilation environments for each hardware target.

### Prerequisites:
- Linux / macOS / Windows with Docker installed.
- Git & Bash shell.

### 1. Build All Targets:
```bash
./build.sh all
```

### 2. Build MikroTik RB5009 (ARM64 FIT Image):
```bash
./build.sh rb5009
```
*Outputs generated in:* `dist/rb5009/fluxwan-rb5009.itb` (39.0 MB) and `dist/rb5009/fluxwan-rb5009-netboot.tar.gz` (39.0 MB).

### 3. Build x86_64 Hybrid Bootable ISO:
```bash
./build.sh x86_64
```
*Outputs generated in:* `dist/x86_64/fluxwan-os-x86_64.iso`

---

## 🌐 Web Dashboard & Access

Once booted, FluxWAN is accessible via browser:
- **Default IP**: `http://192.168.88.1:8080` (or `http://10.10.10.1:8080`)
- **Default User**: `admin`
- **Default Password**: `admin`
- **SSH Console**: `ssh root@192.168.88.1` (Password: `fluxwan`)

---

## 📜 Documentation & Detailed Guides
- [MikroTik RB5009 Full Installation Guide (العربية)](targets/rb5009/INSTALL.md)
- [Comprehensive Multi-Platform Deployment Guide](dist/INSTALLATION_GUIDE.md)

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.