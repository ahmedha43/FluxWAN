# FluxWAN Multi-WAN Router Appliance for EVE-NG

This directory contains the necessary templates and instructions to run **FluxWAN** as an appliance node inside **EVE-NG (Community and Professional editions)**.

---

## 🚀 Key Features in EVE-NG
- **Full Telnet Serial Console**: Connects immediately to `/dev/ttyS0` (115200 baud). Clicking on the node in EVE-NG opens the interactive ASCII TUI menu (`fluxwan-menu`) with zero delays.
- **High-Performance VirtIO Networking**: Supports 4 to 8+ VirtIO NICs (`eth0` LAN/Management, `eth1..ethN` WANs).
- **Embedded Web UI**: Accessible on `http://192.168.90.1:8080` (or port 80 via redirection) by connecting any virtual PC or management cloud to `eth0`.
- **Ultra-Lightweight Footprint**: Requires only 512MB - 1024MB RAM and 1-2 vCPUs.

---

## 📦 File Paths & Directory Conventions in EVE-NG

In EVE-NG, QEMU nodes reside in `/opt/unetlab/addons/qemu/`.

| Template Name | Folder on EVE-NG | Disk File Name | Notes |
|---|---|---|---|
| **Standard Linux (Built-in)** | `/opt/unetlab/addons/qemu/linux-fluxwan-1.2.5/` | `virtioa.qcow2` | Works on all EVE-NG servers without modifying templates. |
| **Dedicated FluxWAN Template** | `/opt/unetlab/addons/qemu/fluxwan-1.2.5/` | `virtioa.qcow2` | Requires `fluxwan.yml` placed in `/opt/unetlab/html/templates/intel/` |

---

## 🛠️ Method 1: Build Directly on the EVE-NG Host (Recommended - 2 Minutes)

Because EVE-NG has KVM and QEMU pre-installed, building on EVE-NG is the fastest method:

1. Copy `fluxwan-os-x86_64.iso` to `/tmp/` on your EVE-NG server (using SCP / WinSCP).
2. SSH into your EVE-NG server as `root`.
3. Create the directory and the empty virtual disk:
   ```bash
   mkdir -p /opt/unetlab/addons/qemu/linux-fluxwan-1.2.5
   cd /opt/unetlab/addons/qemu/linux-fluxwan-1.2.5
   qemu-img create -f qcow2 virtioa.qcow2 2G
   ```
4. Boot the ISO installer in headless mode:
   ```bash
   qemu-system-x86_64 -enable-kvm -m 1024 -smp 2 \
       -cdrom /tmp/fluxwan-os-x86_64.iso \
       -drive file=virtioa.qcow2,format=qcow2,if=virtio \
       -boot d -nographic -serial mon:stdio
   ```
5. When the installer boots to prompt, execute:
   ```bash
   fluxwan-install --disk /dev/vda --yes
   ```
   After installation finishes, type:
   ```bash
   poweroff
   ```
6. Fix EVE-NG permissions:
   ```bash
   /opt/unetlab/wrappers/unl_wrapper -a fixpermissions
   ```

---

## 🎨 Optional: Install Custom EVE-NG Template (Router Icon)

To give FluxWAN its own custom router entry and icon instead of generic Linux:

1. Copy `fluxwan.yml` to the EVE-NG template directories:
   ```bash
   cp fluxwan.yml /opt/unetlab/html/templates/intel/fluxwan.yml
   cp fluxwan.yml /opt/unetlab/html/templates/amd/fluxwan.yml 2>/dev/null || true
   ```
2. Create folder and symlink the image:
   ```bash
   mkdir -p /opt/unetlab/addons/qemu/fluxwan-1.2.5
   ln -sf /opt/unetlab/addons/qemu/linux-fluxwan-1.2.5/virtioa.qcow2 /opt/unetlab/addons/qemu/fluxwan-1.2.5/virtioa.qcow2
   /opt/unetlab/wrappers/unl_wrapper -a fixpermissions
   ```

---

## 🔌 Recommended Node Settings in EVE-NG Lab

When adding a node in the EVE-NG topology editor:
- **Template**: `Linux` (Image: `linux-fluxwan-1.2.5`) OR `FluxWAN`
- **CPUs**: `2`
- **RAM**: `1024 MB` (or `512 MB`)
- **Ethernet Interfaces**: `4` (or `6` / `8`)
- **Console**: `telnet` (Clicking the node opens the serial console directly)
