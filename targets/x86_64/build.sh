#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Embedded Linux Network Appliance - Hybrid Bootable ISO Builder
# Target: dist/fluxwan-os-x86_64.iso (Hybrid Bootable ISO - UEFI + BIOS)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
BUILD_DIR="/tmp/fluxwan_iso_build"
ROOTFS_DIR="$BUILD_DIR/rootfs"
APKOVL_DIR="$BUILD_DIR/apkovl"
ISO_DIR="$BUILD_DIR/iso"
ALPINE_STD_ISO="$DIST_DIR/alpine-standard-base.iso"

echo "======================================================================"
echo "   FluxWAN Embedded Network Appliance - ISO Build Engine              "
echo "======================================================================"

mkdir -p "$DIST_DIR"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$ROOTFS_DIR" "$APKOVL_DIR" "$ISO_DIR"

# ------------------------------------------------------------------------------
# 1. Compile FluxWAN Core Daemon & eBPF Bytecode
# ------------------------------------------------------------------------------
echo "[1/4] Compiling FluxWAN C Reactor & eBPF XDP Engine..."
cd "$PROJECT_ROOT"
python3 scripts/embed_ui.py >/dev/null 2>&1 || true
make clean >/dev/null 2>&1 || true
make all >/dev/null 2>&1 || true
strip --strip-all "$PROJECT_ROOT/fluxwan" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 2. Extract Kernel & Minimal Hardware Modules
# ------------------------------------------------------------------------------
echo "[2/4] Extracting Linux LTS Kernel & Essential Hardware Modules..."
if [ ! -f "$ALPINE_STD_ISO" ]; then
    echo "    * Fetching Alpine Linux 3.19 Base ISO..."
    mkdir -p "$DIST_DIR"
    curl -sSL "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-standard-3.19.1-x86_64.iso" -o "$ALPINE_STD_ISO"
fi

mkdir -p "$BUILD_DIR/iso_extract"
xorriso -osirrox on -indev "$ALPINE_STD_ISO" -extract / "$BUILD_DIR/iso_extract" >/dev/null 2>&1

mkdir -p "$BUILD_DIR/modloop_unpacked"
unsquashfs -d "$BUILD_DIR/modloop_unpacked" "$BUILD_DIR/iso_extract/boot/modloop-lts" >/dev/null 2>&1 || true

# Filter kernel modules: Keep Network, Storage, CDROM, Netfilter, Crypto, VirtIO, Filesystems
mkdir -p "$BUILD_DIR/filtered_modules"
for kdir in "$BUILD_DIR/modloop_unpacked/modules/"*; do
    if [ -d "$kdir" ]; then
        kver="$(basename "$kdir")"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/drivers"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/net"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/crypto"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/fs"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/lib"

        # Network Drivers (Intel, Realtek, Broadcom, Mellanox, VirtIO, VMXNET3)
        [ -d "$kdir/kernel/drivers/net" ] && cp -a "$kdir/kernel/drivers/net" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        # Storage & CDROM Drivers (NVMe, SATA, AHCI, SCSI, CD-ROM, Block, VirtIO-blk, USB-Storage)
        [ -d "$kdir/kernel/drivers/nvme" ] && cp -a "$kdir/kernel/drivers/nvme" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/ata" ] && cp -a "$kdir/kernel/drivers/ata" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/scsi" ] && cp -a "$kdir/kernel/drivers/scsi" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/cdrom" ] && cp -a "$kdir/kernel/drivers/cdrom" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/block" ] && cp -a "$kdir/kernel/drivers/block" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/virtio" ] && cp -a "$kdir/kernel/drivers/virtio" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        if [ -d "$kdir/kernel/drivers/usb" ]; then
            mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/usb"
            cp -a "$kdir/kernel/drivers/usb/storage" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/usb/" 2>/dev/null || true
            cp -a "$kdir/kernel/drivers/usb/host" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/usb/" 2>/dev/null || true
            cp -a "$kdir/kernel/drivers/usb/core" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/usb/" 2>/dev/null || true
        fi
        # Netfilter, Routing, eBPF Subsystems
        [ -d "$kdir/kernel/net" ] && cp -a "$kdir/kernel/net" "$BUILD_DIR/filtered_modules/$kver/kernel/" 2>/dev/null || true
        # Crypto & Checksum Libraries (crc32c, sha, aes, etc.)
        [ -d "$kdir/kernel/crypto" ] && cp -a "$kdir/kernel/crypto" "$BUILD_DIR/filtered_modules/$kver/kernel/" 2>/dev/null || true
        # Essential Kernel Helper Libraries (crc16, zlib, etc.)
        [ -d "$kdir/kernel/lib" ] && cp -a "$kdir/kernel/lib" "$BUILD_DIR/filtered_modules/$kver/kernel/" 2>/dev/null || true
        # Complete Filesystem Modules (ext4, jbd2, mbcache, vfat, fat, nls, isofs, squashfs)
        [ -d "$kdir/kernel/fs" ] && cp -a "$kdir/kernel/fs" "$BUILD_DIR/filtered_modules/$kver/kernel/" 2>/dev/null || true

        # Remove irrelevant desktop/SAN modules to keep image compact
        rm -rf "$BUILD_DIR/filtered_modules/$kver/kernel/net/wireless" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/net/mac80211" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/net/bluetooth" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/net/wireless" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/scsi/qla2xxx" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/scsi/lpfc" 2>/dev/null || true

        # Re-generate module dependencies with depmod
        depmod -b "$BUILD_DIR/filtered_modules" "$kver" 2>/dev/null || cp -a "$kdir"/modules.* "$BUILD_DIR/filtered_modules/$kver/" 2>/dev/null || true
    fi
done

# Create compressed modloop squashfs
mksquashfs "$BUILD_DIR/filtered_modules" "$BUILD_DIR/modloop-lts" -comp xz -Xbcj x86 -b 256K -noappend >/dev/null 2>&1

# ------------------------------------------------------------------------------
# 3. Assemble FluxWAN RootFS & Alpine Apkovl Overlay
# ------------------------------------------------------------------------------
echo "[3/4] Assembling Minimal Embedded RootFS & Apkovl..."
mkdir -p "$APKOVL_DIR/etc/init.d" "$APKOVL_DIR/etc/runlevels/default" "$APKOVL_DIR/etc/runlevels/boot" \
         "$APKOVL_DIR/etc/network" "$APKOVL_DIR/etc/apk" "$APKOVL_DIR/opt/fluxwan/config" "$APKOVL_DIR/opt/fluxwan/bpf" \
         "$APKOVL_DIR/usr/local/bin" "$APKOVL_DIR/var/log"

# Define default packages installed during boot from local ISO APK repository
cat <<'EOF' > "$APKOVL_DIR/etc/apk/world"
alpine-base
sfdisk
partx
e2fsprogs
e2fsprogs-extra
dosfstools
syslinux
grub-bios
util-linux
EOF

# Copy FluxWAN binaries, BPF objects, configs and scripts into apkovl
cp -f "$PROJECT_ROOT/fluxwan" "$APKOVL_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$APKOVL_DIR/opt/fluxwan/config/"
cp -f "$PROJECT_ROOT"/bpf/*.bpf.o "$APKOVL_DIR/opt/fluxwan/bpf/" 2>/dev/null || true
cp -f "$PROJECT_ROOT/targets/x86_64/overlay/usr/local/bin/"* "$APKOVL_DIR/usr/local/bin/" 2>/dev/null || true
cp -f "$PROJECT_ROOT/iso/overlay/usr/local/bin/"* "$APKOVL_DIR/usr/local/bin/" 2>/dev/null || true
cp -f "$PROJECT_ROOT/install_harddisk.sh" "$APKOVL_DIR/usr/local/bin/fluxwan-install" 2>/dev/null || true
cp -f "$PROJECT_ROOT/install_harddisk.sh" "$APKOVL_DIR/usr/local/bin/install_harddisk.sh" 2>/dev/null || true
chmod +x "$APKOVL_DIR/usr/local/bin/"* 2>/dev/null || true

# Copy pure Alpine syslinux modules and binaries from base ISO and builder host
mkdir -p "$APKOVL_DIR/usr/share/syslinux" "$APKOVL_DIR/boot/syslinux"
cp -a "$BUILD_DIR/iso_extract/boot/syslinux/"* "$APKOVL_DIR/boot/syslinux/" 2>/dev/null || true
cp -a "$BUILD_DIR/iso_extract/boot/syslinux/"* "$APKOVL_DIR/usr/share/syslinux/" 2>/dev/null || true
if [ -d /usr/share/syslinux ]; then
    cp -a /usr/share/syslinux/. "$APKOVL_DIR/usr/share/syslinux/" 2>/dev/null || true
fi

mkdir -p "$APKOVL_DIR/usr/sbin" "$APKOVL_DIR/sbin" "$APKOVL_DIR/usr/lib" "$APKOVL_DIR/lib"

# Embed the complete offline bootloader toolchain. The disk installer runs from
# initramfs, so apk/world alone cannot provide these commands at install time.
if [ -d /usr/lib/grub/i386-pc ]; then
    mkdir -p "$APKOVL_DIR/usr/lib/grub/i386-pc"
    cp -a /usr/lib/grub/i386-pc/. "$APKOVL_DIR/usr/lib/grub/i386-pc/"
fi

if [ -d /usr/lib/grub/x86_64-efi ]; then
    mkdir -p "$APKOVL_DIR/usr/lib/grub/x86_64-efi"
    cp -a /usr/lib/grub/x86_64-efi/. "$APKOVL_DIR/usr/lib/grub/x86_64-efi/"
fi

for bin in grub-install grub-mkimage grub-bios-setup grub-probe grub-setup; do
    SRC=$(command -v "$bin" 2>/dev/null || true)
    [ -n "$SRC" ] && cp -f "$SRC" "$APKOVL_DIR/usr/sbin/$bin"
done

# extlinux is the BIOS fallback and requires its executable in addition to the
# Syslinux modules and MBR code copied above.
EXTLINUX_BIN=$(command -v extlinux 2>/dev/null || true)
[ -n "$EXTLINUX_BIN" ] && cp -f "$EXTLINUX_BIN" "$APKOVL_DIR/sbin/extlinux"

# grub-install is dynamically linked on Alpine; include its non-base runtime
# libraries in initramfs so it cannot fail after the disk is repartitioned.
for lib in /usr/lib/liblzma.so.5 /lib/libdevmapper.so.1.02; do
    [ -f "$lib" ] && cp -a "$lib" "${APKOVL_DIR}${lib}"
done
# Copy appliance configuration files
cp -f "$PROJECT_ROOT/appliance/etc/inittab" "$APKOVL_DIR/etc/inittab" 2>/dev/null || true
cp -f "$PROJECT_ROOT/appliance/etc/sysctl.conf" "$APKOVL_DIR/etc/sysctl.conf" 2>/dev/null || true
cp -f "$PROJECT_ROOT/appliance/etc/network/interfaces" "$APKOVL_DIR/etc/network/interfaces" 2>/dev/null || true
cp -f "$PROJECT_ROOT/appliance/etc/passwd" "$APKOVL_DIR/etc/passwd" 2>/dev/null || true
cp -f "$PROJECT_ROOT/appliance/etc/shadow" "$APKOVL_DIR/etc/shadow" 2>/dev/null || true
cp -f "$PROJECT_ROOT/appliance/etc/group" "$APKOVL_DIR/etc/group" 2>/dev/null || true
chmod 600 "$APKOVL_DIR/etc/shadow" 2>/dev/null || true

# Setup OpenRC service for FluxWAN
cat <<'EOF' > "$APKOVL_DIR/etc/init.d/fluxwan"
#!/sbin/openrc-run

name="fluxwan"
description="FluxWAN Edge SD-WAN & Multi-WAN Reactor Engine"
command="/opt/fluxwan/fluxwan"
command_args="/opt/fluxwan/config/fluxwan.json"
command_background=true
pidfile="/run/fluxwan.pid"

depend() {
    need net
    after firewall
}

start_pre() {
    # Forwarding & TCP BBR / Cake QoS
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null 2>&1 || true
    sysctl -w net.ipv4.conf.default.rp_filter=2 >/dev/null 2>&1 || true
    # Web Management Port 80 -> 8080 Redirection
    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
    return 0
}
EOF
chmod +x "$APKOVL_DIR/etc/init.d/fluxwan"
ln -sf /etc/init.d/fluxwan "$APKOVL_DIR/etc/runlevels/default/fluxwan"

# Also include rcS for Busybox fallback
cp -f "$PROJECT_ROOT/appliance/etc/init.d/rcS" "$APKOVL_DIR/etc/init.d/rcS" 2>/dev/null || true
chmod +x "$APKOVL_DIR/etc/init.d/rcS" 2>/dev/null || true

# Strip Windows CRLF line endings only from text and config files (do NOT touch binaries or bpf.o!)
find "$APKOVL_DIR/etc" "$APKOVL_DIR/usr" -type f \( -name "*.cfg" -o -name "*.conf" -o -name "*.sh" -o -name "*.json" -o -name "inittab" -o -name "interfaces" -o -name "passwd" -o -name "shadow" -o -name "group" -o -name "fluxwan-*" \) -exec sed -i 's/\r$//' {} + 2>/dev/null || true

# Create localhost.apkovl.tar.gz (standard Alpine auto-loaded overlay)
tar -czf "$DIST_DIR/localhost.apkovl.tar.gz" -C "$APKOVL_DIR" .
tar -czf "$DIST_DIR/fluxwan-rootfs.tar.gz" -C "$APKOVL_DIR" .

# ------------------------------------------------------------------------------
# 4. Assemble Complete Clean ISO Tree & Generate Hybrid ISO
# ------------------------------------------------------------------------------
echo "[4/4] Generating Hybrid Bootable ISO (UEFI + BIOS)..."

# Copy entire original Alpine ISO structure (includes apks/, .boot_repository, efi/, boot/)
cp -a "$BUILD_DIR/iso_extract/." "$ISO_DIR/"
chmod -R u+w "$ISO_DIR" 2>/dev/null || true

# Replace modloop with our optimized/filtered modloop
rm -f "$ISO_DIR/boot/modloop-lts" 2>/dev/null || true
cp -f "$BUILD_DIR/modloop-lts" "$ISO_DIR/boot/modloop-lts"

# Place FluxWAN overlay into ISO root with all possible hostnames
cp -f "$DIST_DIR/localhost.apkovl.tar.gz" "$ISO_DIR/localhost.apkovl.tar.gz"
cp -f "$DIST_DIR/localhost.apkovl.tar.gz" "$ISO_DIR/alpine.apkovl.tar.gz"
cp -f "$DIST_DIR/localhost.apkovl.tar.gz" "$ISO_DIR/fluxwan.apkovl.tar.gz"
cp -f "$DIST_DIR/localhost.apkovl.tar.gz" "$ISO_DIR/apkovl.tar.gz"
mkdir -p "$ISO_DIR/opt/fluxwan"
cp -f "$PROJECT_ROOT/fluxwan" "$ISO_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$ISO_DIR/opt/fluxwan/config.json"
cp -f "$DIST_DIR/fluxwan-rootfs.tar.gz" "$ISO_DIR/opt/fluxwan/"

# Direct injection into initramfs-lts (guarantees /usr/local/bin/fluxwan-menu exists immediately on boot)
echo "[+] Embedding FluxWAN control console into initramfs-lts..."
mkdir -p "$BUILD_DIR/initramfs_unpacked"
(cd "$BUILD_DIR/initramfs_unpacked" && zcat "$ISO_DIR/boot/initramfs-lts" | cpio -idmu >/dev/null 2>&1 || true)
cp -a "$APKOVL_DIR/." "$BUILD_DIR/initramfs_unpacked/"
mkdir -p "$BUILD_DIR/initramfs_unpacked/usr/bin" "$BUILD_DIR/initramfs_unpacked/bin" "$BUILD_DIR/initramfs_unpacked/usr/local/bin"
cp -f "$APKOVL_DIR/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/usr/local/bin/" 2>/dev/null || true
cp -f "$APKOVL_DIR/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/usr/bin/" 2>/dev/null || true
cp -f "$APKOVL_DIR/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/bin/" 2>/dev/null || true
chmod +x "$BUILD_DIR/initramfs_unpacked/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/usr/bin/"* "$BUILD_DIR/initramfs_unpacked/bin/"* 2>/dev/null || true
find "$BUILD_DIR/initramfs_unpacked" -type f \( -name "*.sh" -o -name "fluxwan-*" -o -name "inittab" -o -name "*.cfg" \) -exec sed -i 's/\r$//' {} + 2>/dev/null || true
(cd "$BUILD_DIR/initramfs_unpacked" && find . | cpio -H newc -o | gzip -9 > "$ISO_DIR/boot/initramfs-lts")

# Configure Syslinux / ISOLINUX boot (Legacy BIOS)
cat <<'EOF' > "$ISO_DIR/boot/syslinux/syslinux.cfg"
TIMEOUT 30
PROMPT 0
DEFAULT fluxwan

LABEL fluxwan
  MENU LABEL FluxWAN Embedded Network Appliance
  KERNEL /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr-mod,cdrom,isofs console=tty0 console=ttyS0,115200
EOF

# Ensure isolinux.cfg also points to the same configuration
cp -f "$ISO_DIR/boot/syslinux/syslinux.cfg" "$ISO_DIR/boot/syslinux/isolinux.cfg"

# Configure GRUB boot (UEFI)
cat <<'EOF' > "$ISO_DIR/boot/grub/grub.cfg"
set timeout=2
set default=0

menuentry "FluxWAN Embedded Network Appliance" {
    linux /boot/vmlinuz-lts modules=loop,squashfs,sd-mod,usb-storage,sr-mod,cdrom,isofs console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-lts
}
EOF

# Ensure Windows CRLF endings are stripped from text config files only
find "$ISO_DIR/boot" -type f \( -name "*.cfg" -o -name "*.conf" \) -exec sed -i 's/\r$//' {} + 2>/dev/null || true

ISO_OUTPUT="$DIST_DIR/fluxwan-os-x86_64.iso"
ISOHDPFX="$ISO_DIR/boot/syslinux/isohdpfx.bin"

# Generate Hybrid ISO with EFI + BIOS El Torito boot records
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "alpine-std 3.19.1 x86_64" \
    -isohybrid-mbr "$ISOHDPFX" \
    -c boot/syslinux/boot.cat \
    -b boot/syslinux/isolinux.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot -boot-load-size 2880 -isohybrid-gpt-basdat \
    -output "$ISO_OUTPUT" \
    "$ISO_DIR" > /dev/null 2>&1

# ------------------------------------------------------------------------------
# Measurement Report
# ------------------------------------------------------------------------------
echo "======================================================================"
echo "    FluxWAN Embedded Appliance - ISO Measurement Report               "
echo "======================================================================"

ISO_SIZE=$(du -h "$ISO_OUTPUT" | awk '{print $1}')
APKOVL_SIZE=$(du -h "$DIST_DIR/localhost.apkovl.tar.gz" | awk '{print $1}')
KERNEL_SIZE=$(du -h "$ISO_DIR/boot/vmlinuz-lts" | awk '{print $1}')
INITRD_SIZE=$(du -h "$ISO_DIR/boot/initramfs-lts" | awk '{print $1}')
MODLOOP_SIZE=$(du -h "$ISO_DIR/boot/modloop-lts" | awk '{print $1}')
DAEMON_SIZE=$(du -h "$PROJECT_ROOT/fluxwan" | awk '{print $1}')

echo "  Target ISO File      : $ISO_OUTPUT"
echo "  Total ISO Size       : $ISO_SIZE"
echo "  Apkovl Overlay Size  : $APKOVL_SIZE"
echo "  Kernel (vmlinuz-lts) : $KERNEL_SIZE"
echo "  Initramfs Size       : $INITRD_SIZE"
echo "  Driver Modloop Size  : $MODLOOP_SIZE"
echo "  FluxWAN Core Daemon  : $DAEMON_SIZE"
echo "======================================================================"
echo " [✓] ISO READY FOR DEPLOYMENT!"
echo "     Path: $ISO_OUTPUT"
echo "======================================================================"
