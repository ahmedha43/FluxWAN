#!/usr/bin/env bash
# ==============================================================================
# FluxWAN MikroTik RB5009 (ARM64) Production Image Build Script
# Targets:
#   - dist/rb5009/fluxwan-rb5009.itb (RouterBOOT / U-Boot Flattened Image Tree)
#   - dist/rb5009/fluxwan-rb5009-netboot.tar.gz (Netboot bundle)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="$SCRIPT_DIR"
DIST_DIR="$PROJECT_ROOT/dist/rb5009"
BUILD_DIR="/tmp/fluxwan_rb5009_build"
ROOTFS_DIR="$BUILD_DIR/rootfs"
CACHE_DIR="$PROJECT_ROOT/.cache/arm64"

echo "======================================================================"
echo "   FluxWAN MikroTik RB5009 (ARM64) Appliance Build Engine             "
echo "======================================================================"
echo " Project Root : $PROJECT_ROOT"
echo " Output Dir   : $DIST_DIR"

rm -rf "$BUILD_DIR"
mkdir -p "$DIST_DIR" "$BUILD_DIR" "$ROOTFS_DIR" "$CACHE_DIR"

# 1. Fetch Official Linux LTS Kernel & BusyBox for ARM64 (aarch64)
echo "[1/6] Fetching Production Linux LTS 6.6 Kernel & Busybox (ARM64)..."
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine/v3.19/main/aarch64"

if [ ! -f "$CACHE_DIR/busybox-static.apk" ]; then
    echo "    * Downloading busybox-static (aarch64)..."
    curl -fL --retry 3 -sS "$ALPINE_MIRROR/busybox-static-1.36.1-r21.apk" -o "$CACHE_DIR/busybox-static.apk" || \
    curl -fL --retry 3 -sS "$ALPINE_MIRROR/busybox-static-1.36.1-r19.apk" -o "$CACHE_DIR/busybox-static.apk"
test -s "$CACHE_DIR/busybox-static.apk"
fi

if [ ! -f "$CACHE_DIR/linux-lts.apk" ]; then
    echo "    * Downloading Linux LTS Kernel (aarch64)..."
    curl -fL --retry 3 -sS "$ALPINE_MIRROR/linux-lts-6.6.142-r0.apk" -o "$CACHE_DIR/linux-lts.apk" || \
    curl -fL --retry 3 -sS "$ALPINE_MIRROR/linux-lts-6.6.14-r0.apk" -o "$CACHE_DIR/linux-lts.apk"
test -s "$CACHE_DIR/linux-lts.apk"
fi

# Extract Kernel vmlinuz-lts (Image.gz)
mkdir -p "$BUILD_DIR/kernel_extract"
tar -xzf "$CACHE_DIR/linux-lts.apk" -C "$BUILD_DIR/kernel_extract" 2>/dev/null || true
if [ ! -f "$BUILD_DIR/kernel_extract/boot/vmlinuz-lts" ]; then
    echo "ERROR: Alpine kernel package did not contain boot/vmlinuz-lts" >&2
    exit 1
fi
cp -f "$BUILD_DIR/kernel_extract/boot/vmlinuz-lts" "$BUILD_DIR/Image.gz"
echo "    * Extracted Linux ARM64 Kernel: $(ls -lh "$BUILD_DIR/Image.gz" | awk '{print $5}')"

# 2. Compile FluxWAN Core for ARM64 (aarch64)
echo "[2/6] Compiling FluxWAN Core Engine for aarch64 (ARMv8-A)..."
aarch64-linux-gnu-gcc -O2 -march=armv8-a -I"$PROJECT_ROOT/include" \
    "$PROJECT_ROOT"/src/*.c \
    -o "$BUILD_DIR/fluxwan" \
    -lpthread 2>/dev/null || \
aarch64-linux-gnu-gcc -O2 -I"$PROJECT_ROOT/include" \
    "$PROJECT_ROOT"/src/*.c \
    -o "$BUILD_DIR/fluxwan" \
    -lpthread

echo "    * FluxWAN ARM64 Binary compiled: $(ls -lh "$BUILD_DIR/fluxwan" | awk '{print $5}')"

# 3. Compile eBPF XDP Engine for ARM64
echo "[3/6] Compiling eBPF XDP Acceleration Engine for ARM64..."
mkdir -p "$BUILD_DIR/bpf"
if command -v clang >/dev/null 2>&1 && [ -f "$PROJECT_ROOT/bpf/xdp_router.bpf.c" ]; then
    clang -O2 -target bpf -D__TARGET_ARCH_arm64 \
        -I"$PROJECT_ROOT/include" \
        -I/usr/aarch64-linux-gnu/include \
        -c "$PROJECT_ROOT/bpf/xdp_router.bpf.c" \
        -o "$BUILD_DIR/bpf/xdp_router.bpf.o"
    test -s "$BUILD_DIR/bpf/xdp_router.bpf.o"
    echo "    * eBPF XDP ARM64 Object compiled: $(ls -lh "$BUILD_DIR/bpf/xdp_router.bpf.o" | awk '{print $5}')"
fi

# 4. Assemble Streamlined Embedded ARM64 RootFS
echo "[4/6] Assembling Production Embedded ARM64 RootFS..."
mkdir -p "$ROOTFS_DIR/bin" "$ROOTFS_DIR/sbin" "$ROOTFS_DIR/etc" "$ROOTFS_DIR/proc" \
         "$ROOTFS_DIR/sys" "$ROOTFS_DIR/dev" "$ROOTFS_DIR/tmp" "$ROOTFS_DIR/run" \
         "$ROOTFS_DIR/opt/fluxwan/config" "$ROOTFS_DIR/opt/fluxwan/bpf" \
         "$ROOTFS_DIR/usr/bin" "$ROOTFS_DIR/usr/sbin" "$ROOTFS_DIR/usr/local/bin" \
         "$ROOTFS_DIR/var/log" "$ROOTFS_DIR/var/run" "$ROOTFS_DIR/root"

# Install Busybox ARM64 binaries and symlinks
mkdir -p "$BUILD_DIR/bb_extract"
tar -xzf "$CACHE_DIR/busybox-static.apk" -C "$BUILD_DIR/bb_extract" 2>/dev/null || true
if [ -f "$BUILD_DIR/bb_extract/bin/busybox.static" ]; then
    cp -f "$BUILD_DIR/bb_extract/bin/busybox.static" "$ROOTFS_DIR/bin/busybox"
    chmod +x "$ROOTFS_DIR/bin/busybox"
    for cmd in sh ash ls cp mv rm mkdir rmdir cat echo grep sed awk mount umount \
               ps kill pgrep pkill top ifconfig ip route ping dmesg sync sleep \
               tar gzip find date chmod chown vi clear reboot poweroff uname; do
        ln -sf /bin/busybox "$ROOTFS_DIR/bin/$cmd" 2>/dev/null || true
        ln -sf /bin/busybox "$ROOTFS_DIR/sbin/$cmd" 2>/dev/null || true
        ln -sf /bin/busybox "$ROOTFS_DIR/usr/bin/$cmd" 2>/dev/null || true
    done
fi

# Copy FluxWAN Core, config, and installer
cp -f "$BUILD_DIR/fluxwan" "$ROOTFS_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$ROOTFS_DIR/opt/fluxwan/config/"
[ -f "$BUILD_DIR/bpf/xdp_router.bpf.o" ] && cp -f "$BUILD_DIR/bpf/xdp_router.bpf.o" "$ROOTFS_DIR/opt/fluxwan/bpf/"

if [ -f "$TARGET_DIR/installer/rb5009-install" ]; then
    cp -f "$TARGET_DIR/installer/rb5009-install" "$ROOTFS_DIR/usr/local/bin/"
    chmod +x "$ROOTFS_DIR/usr/local/bin/rb5009-install"
fi

# Copy essential networking & MTD kernel modules
if [ -d "$BUILD_DIR/kernel_extract/lib/modules" ]; then
    mkdir -p "$ROOTFS_DIR/lib/modules"
    # Selectively copy network, crypto, switch, and MTD drivers for small fast initramfs
    for kver in $(ls "$BUILD_DIR/kernel_extract/lib/modules/"); do
        mkdir -p "$ROOTFS_DIR/lib/modules/$kver/kernel/drivers/net"
        mkdir -p "$ROOTFS_DIR/lib/modules/$kver/kernel/net"
        mkdir -p "$ROOTFS_DIR/lib/modules/$kver/kernel/drivers/mtd"
        mkdir -p "$ROOTFS_DIR/lib/modules/$kver/kernel/drivers/crypto"
        cp -a "$BUILD_DIR/kernel_extract/lib/modules/$kver/kernel/drivers/net/"* "$ROOTFS_DIR/lib/modules/$kver/kernel/drivers/net/" 2>/dev/null || true
        cp -a "$BUILD_DIR/kernel_extract/lib/modules/$kver/kernel/net/"* "$ROOTFS_DIR/lib/modules/$kver/kernel/net/" 2>/dev/null || true
        cp -a "$BUILD_DIR/kernel_extract/lib/modules/$kver/kernel/drivers/mtd/"* "$ROOTFS_DIR/lib/modules/$kver/kernel/drivers/mtd/" 2>/dev/null || true
        cp -a "$BUILD_DIR/kernel_extract/lib/modules/$kver/kernel/drivers/crypto/"* "$ROOTFS_DIR/lib/modules/$kver/kernel/drivers/crypto/" 2>/dev/null || true
        [ -f "$BUILD_DIR/kernel_extract/lib/modules/$kver/modules.dep" ] && cp -f "$BUILD_DIR/kernel_extract/lib/modules/$kver"/modules.* "$ROOTFS_DIR/lib/modules/$kver/" 2>/dev/null || true
    done
fi

# Create embedded init script
cat << 'EOF' > "$ROOTFS_DIR/init"
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || /bin/busybox mdev -s
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

# Set hostname
echo "FluxWAN-RB5009" > /etc/hostname

# Configure Network (ether1 default IP for management)
ifconfig lo 127.0.0.1 up
ifconfig eth0 192.168.88.1 netmask 255.255.255.0 up 2>/dev/null || true
ifconfig ether1 192.168.88.1 netmask 255.255.255.0 up 2>/dev/null || true

# Forwarding & TCP Optimization
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

clear
echo "======================================================================"
echo "   ⚡ FluxWAN Embedded Network Appliance (MikroTik RB5009 ARM64)      "
echo "======================================================================"
echo "  Architecture : ARM64 (Marvell Armada 7040 Quad Cortex-A72 @ 1.4GHz) "
echo "  RAM Memory   : 1024 MB DDR4                                         "
echo "  Storage      : 1024 MB NAND Flash (/dev/mtd5 / ubi0)                "
echo "  Web GUI      : http://192.168.88.1:8080                             "
echo "======================================================================"

# Start FluxWAN Core Reactor Daemon
if [ -x /opt/fluxwan/fluxwan ]; then
    /opt/fluxwan/fluxwan /opt/fluxwan/config/fluxwan.json >/var/log/fluxwan.log 2>&1 &
    echo " [✓] FluxWAN Reactor Engine started."
fi

echo ""
echo " >>> To install FluxWAN permanently to internal NAND flash, type: rb5009-install"
echo " >>> Or simply open http://192.168.88.1:8080 in your browser to 1-Click Flash."
echo ""

exec /bin/sh
EOF
chmod +x "$ROOTFS_DIR/init"

# Package CPIO initramfs
(cd "$ROOTFS_DIR" && find . | cpio -H newc -o | gzip -9 > "$BUILD_DIR/initramfs-fluxwan-arm64.cpio.gz")
echo "    * Production Initramfs size: $(ls -lh "$BUILD_DIR/initramfs-fluxwan-arm64.cpio.gz" | awk '{print $5}')"

# 5. Compile Device Tree (DTB)
echo "[5/6] Compiling Device Tree (armada-7040-rb5009.dtb)..."
if [ -f "$TARGET_DIR/kernel/armada-7040-rb5009.dts" ]; then
    gcc -E -nostdinc -I"$TARGET_DIR/kernel" -undef -D__DTS__ -x assembler-with-cpp \
        "$TARGET_DIR/kernel/armada-7040-rb5009.dts" -o "$BUILD_DIR/armada-7040-rb5009.dts.tmp"
    dtc -I dts -O dtb -o "$BUILD_DIR/armada-7040-rb5009.dtb" \
        -i "$TARGET_DIR/kernel" "$BUILD_DIR/armada-7040-rb5009.dts.tmp"
    test -s "$BUILD_DIR/armada-7040-rb5009.dtb"
    file "$BUILD_DIR/armada-7040-rb5009.dtb" | grep -q 'Device Tree Blob'
fi

# 6. Build Flattened Image Tree (FIT .itb image)
echo "[6/6] Generating Production FIT Image (fluxwan-rb5009.itb)..."
test -s "$BUILD_DIR/Image.gz"
test -s "$BUILD_DIR/armada-7040-rb5009.dtb"

cp -f "$TARGET_DIR/fluxwan-rb5009.its" "$BUILD_DIR/"
# Build in local /tmp (fast ext4)
(cd "$BUILD_DIR" && mkimage -f fluxwan-rb5009.its "$BUILD_DIR/fluxwan-rb5009.itb")

# Copy finished image to dist/rb5009 and root dist/
cp -f "$BUILD_DIR/fluxwan-rb5009.itb" "$DIST_DIR/fluxwan-rb5009.itb"
cp -f "$BUILD_DIR/fluxwan-rb5009.itb" "$PROJECT_ROOT/dist/fluxwan-rb5009.itb" 2>/dev/null || true

# Copy Windows Flasher tool into dist/rb5009
cp -f "$TARGET_DIR/netboot/FluxWAN-Windows-Flasher.bat" "$DIST_DIR/" 2>/dev/null || true
cp -f "$TARGET_DIR/netboot/FluxWAN-Windows-Flasher.bat" "$PROJECT_ROOT/dist/" 2>/dev/null || true

# Create netboot tarball bundle
tar -czf "$DIST_DIR/fluxwan-rb5009-netboot.tar.gz" -C "$DIST_DIR" fluxwan-rb5009.itb FluxWAN-Windows-Flasher.bat
cp -f "$DIST_DIR/fluxwan-rb5009-netboot.tar.gz" "$PROJECT_ROOT/dist/" 2>/dev/null || true

echo ""
echo "======================================================================"
echo " [✓] PRODUCTION RB5009 ARM64 APPLIANCE BUNDLE GENERATED!"
echo "  FIT Image (Kernel + RootFS + DTB) : $(ls -lh "$DIST_DIR/fluxwan-rb5009.itb" | awk '{print $5}') ($DIST_DIR/fluxwan-rb5009.itb)"
echo "  Netboot Bundle                     : $(ls -lh "$DIST_DIR/fluxwan-rb5009-netboot.tar.gz" | awk '{print $5}')"
echo "======================================================================"