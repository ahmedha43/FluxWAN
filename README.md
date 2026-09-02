# ⚡ FluxWAN Operating System

> **High-Performance Multi-WAN Load Balancing & Embedded Network Appliance Engine**  
> Powered by **Linux 6.6 LTS**, **eBPF XDP (eXpress Data Path)**, and a **Lightweight C Reactor Core**.

---

## 🚀 Overview

**FluxWAN** is an open-source, carrier-grade embedded network operating system designed for multi-gigabit Multi-WAN aggregation, active-active load balancing, intelligent traffic failover, and line-rate packet processing.

Unlike traditional software routers that process packets in userspace or rely on heavy netfilter overhead, **FluxWAN** implements **Kernel-Bypass & eBPF XDP Packet Steering** directly inside the network driver layer, achieving microsecond latency and maximum wire-speed throughput on modest hardware.

---

## 🎯 Supported Hardware Architectures

| Target Hardware | Architecture | SoC / Processor | Primary Storage | Network Ports |
|---|---|---|---|---|
| **x86_64 Generic** | `x86_64` / `AMD64` | Intel Core / Xeon / AMD EPYC / VMs | NVMe / SATA / USB | 1G / 2.5G / 10G / 25G / 40G Intel/Realtek NICs |
| **MikroTik RB5009** | `AArch64` (ARM64) | Marvell Armada 7040 (4x Cortex-A72 @ 1.4GHz) | 1024 MB NAND Flash | 7x 1G + 1x 2.5G (`ether1`) + 1x 10G SFP+ (`sfp-sfpplus1`) |
| **MikroTik RB750Gr3** | `MIPS32` | MediaTek MT7621AT (2x MIPS1004Kc @ 880MHz) | 16 MB SPI Flash | 5x 1G Gigabit Ethernet |

---

## ✨ Key Features

- 🏎️ **eBPF XDP Packet Acceleration**: In-kernel line-rate load balancing with Weighted Round-Robin (WRR) and flow hashing.
- 📡 **Active Multi-WAN Health Probing**: Sub-second ICMP/TCP ping probing with auto-failover and latency-aware routing.
- 🔒 **Sticky Flow Hashing**: Session affinity prevents banking and VoIP session drops across multiple dynamic WAN IPs.
- 🔐 **Hardware Crypto Offload**: Native driver integration for Marvell SafeXcel (EIP-197) crypto engine (IPsec / WireGuard).
- 🌐 **Modern Embedded Web Dashboard**: Real-time traffic graphs (Chart.js), WAN status monitor, DHCP client tables, and 1-Click live configuration.
- ⚡ **1-Click Web & Netboot Installers**: Effortless automated installation for both x86 appliances and MikroTik RouterBOOT Netboot.

---

## 📁 Repository Structure

```
FluxWAN/
├── src/                      # Universal C Reactor Engine Source Code
├── include/                  # Core C Header Definitions & API Structures
├── bpf/                      # eBPF XDP Routing & Packet Classification Programs
├── config/                   # Default Multi-WAN & Router Configuration
├── web/                      # Responsive HTML5/Tailwind/Alpine.js Web Dashboard
│
├── targets/                  # Modular Multi-Architecture Hardware Modules
│   ├── x86_64/               # x86_64 PC/Server/VMware target (ISO & Overlay)
│   ├── rb5009/               # MikroTik RB5009 ARM64 target (DTS, FIT, Installer, Netboot)
│   └── rb750gr3/             # MikroTik RB750Gr3 MIPS target
│
├── dist/                     # Build Distribution Output Directory
│   ├── x86_64/               # x86 Bootable Hybrid ISO
│   ├── rb5009/               # RB5009 FIT Image (.itb) & Netboot Tools
│   └── INSTALLATION_GUIDE.md # Comprehensive Installation Guide (Arabic & English)
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
*Outputs generated in:* `dist/rb5009/fluxwan-rb5009.itb`

### 3. Build x86_64 Hybrid Bootable ISO:
```bash
./build.sh x86_64
```
*Outputs generated in:* `dist/x86_64/fluxwan-os-x86_64.iso`

---

## 🌐 Web Dashboard & Management

Once booted, FluxWAN is accessible via browser:
- **Default IP**: `http://192.168.88.1:8080` (or `http://10.10.10.1:8080`)
- **Default User**: `admin`
- **Default Password**: `admin`
- **SSH Console**: `ssh root@192.168.88.1` (Password: `fluxwan`)

---

## 📜 Documentation & Guides
- [MikroTik RB5009 Installation Guide](targets/rb5009/INSTALL.md)
- [Comprehensive Multi-Platform Guide](dist/INSTALLATION_GUIDE.md)

---

## 📄 License
This project is licensed under the MIT License.