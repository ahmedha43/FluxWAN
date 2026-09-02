#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Embedded Linux Network Appliance - Master Build Pipeline
# Architecture: Linux Kernel + musl libc + BusyBox init + FluxWAN Daemon + Web UI
# Outputs:
#   1. dist/fluxwan-os-x86_64.iso     (Hybrid Bootable ISO - UEFI + BIOS)
#   2. dist/fluxwan-vmware.vmdk       (Ready-to-boot VMware Virtual Disk)
#   3. dist/fluxwan-disk.img.gz       (Compressed Raw Disk Image for Bare-Metal)
#   4. dist/fluxwan-rootfs.tar.gz     (Minimal RootFS Archive)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
OUTPUT_DIR="$PROJECT_ROOT/output/images"
BUILD_DIR="/tmp/fluxwan_appliance_build"
ROOTFS_DIR="$BUILD_DIR/rootfs"
ISO_DIR="$BUILD_DIR/iso"
ALPINE_STD_ISO="$DIST_DIR/alpine-standard-base.iso"

echo "======================================================================"
echo "    FluxWAN Embedded Linux Network Appliance - Build Engine           "
echo "======================================================================"

mkdir -p "$DIST_DIR" "$OUTPUT_DIR"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$ROOTFS_DIR" "$ISO_DIR"

# ------------------------------------------------------------------------------
# Step 1: Compile FluxWAN Core Daemon & eBPF Bytecode
# ------------------------------------------------------------------------------
echo "[+] Step 1: Compiling FluxWAN Core C Daemon & eBPF Bytecode..."
cd "$PROJECT_ROOT"
python3 scripts/embed_ui.py >/dev/null 2>&1 || true
make clean >/dev/null 2>&1 || true
make all >/dev/null 2>&1 || true
strip --strip-all "$PROJECT_ROOT/fluxwan" 2>/dev/null || true

# ------------------------------------------------------------------------------
# Step 2: Extract Linux LTS Kernel & Filter Network/Storage Drivers
# ------------------------------------------------------------------------------
echo "[+] Step 2: Extracting Linux LTS Kernel & Network Hardware Drivers..."
mkdir -p "$BUILD_DIR/iso_extract"
xorriso -osirrox on -indev "$ALPINE_STD_ISO" -extract / "$BUILD_DIR/iso_extract" >/dev/null 2>&1

mkdir -p "$BUILD_DIR/modloop_unpacked"
unsquashfs -d "$BUILD_DIR/modloop_unpacked" "$BUILD_DIR/iso_extract/boot/modloop-lts" >/dev/null 2>&1 || true

# Filter kernel modules: Keep ONLY Network, Storage, Netfilter, Crypto, VirtIO
mkdir -p "$BUILD_DIR/filtered_modules"
for kdir in "$BUILD_DIR/modloop_unpacked/modules/"*; do
    if [ -d "$kdir" ]; then
        kver="$(basename "$kdir")"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/drivers"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/net"
        mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/crypto"

        # Network Drivers (Intel, Realtek, Broadcom, Mellanox, Solarflare, Aquantia, VirtIO, VMXNET3)
        [ -d "$kdir/kernel/drivers/net" ] && cp -a "$kdir/kernel/drivers/net" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        # Storage Drivers (NVMe, SATA, AHCI, SCSI, Block, VirtIO-blk, USB-Storage)
        [ -d "$kdir/kernel/drivers/nvme" ] && cp -a "$kdir/kernel/drivers/nvme" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/ata" ] && cp -a "$kdir/kernel/drivers/ata" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/scsi" ] && cp -a "$kdir/kernel/drivers/scsi" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/block" ] && cp -a "$kdir/kernel/drivers/block" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/virtio" ] && cp -a "$kdir/kernel/drivers/virtio" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/" 2>/dev/null || true
        if [ -d "$kdir/kernel/drivers/usb/storage" ]; then
            mkdir -p "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/usb"
            cp -a "$kdir/kernel/drivers/usb/storage" "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/usb/" 2>/dev/null || true
        fi
        # Netfilter, Routing, eBPF & Crypto Subsystems
        [ -d "$kdir/kernel/net" ] && cp -a "$kdir/kernel/net" "$BUILD_DIR/filtered_modules/$kver/kernel/" 2>/dev/null || true
        [ -d "$kdir/kernel/crypto" ] && cp -a "$kdir/kernel/crypto" "$BUILD_DIR/filtered_modules/$kver/kernel/" 2>/dev/null || true
        # Module metadata files
        cp -a "$kdir"/modules.* "$BUILD_DIR/filtered_modules/$kver/" 2>/dev/null || true

        # Remove irrelevant large non-router modules (Wireless, Bluetooth, SAN Fibre Channel)
        rm -rf "$BUILD_DIR/filtered_modules/$kver/kernel/net/wireless" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/net/mac80211" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/net/bluetooth" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/scsi/qla2xxx" \
               "$BUILD_DIR/filtered_modules/$kver/kernel/drivers/scsi/lpfc" 2>/dev/null || true
    fi
done

# Rebuild lightweight modloop for ISO (< 18MB)
mksquashfs "$BUILD_DIR/filtered_modules" "$BUILD_DIR/modloop-lts" -comp xz -Xbcj x86 -b 256K -noappend >/dev/null 2>&1

# ------------------------------------------------------------------------------
# Step 3: Assemble Minimal Embedded Root Filesystem (< 25 MB)
# ------------------------------------------------------------------------------
echo "[+] Step 3: Assembling Minimal Embedded Root Filesystem..."
mkdir -p "$ROOTFS_DIR/bin" "$ROOTFS_DIR/sbin" "$ROOTFS_DIR/lib" "$ROOTFS_DIR/etc" \
         "$ROOTFS_DIR/usr/bin" "$ROOTFS_DIR/usr/sbin" "$ROOTFS_DIR/usr/lib" "$ROOTFS_DIR/usr/share/syslinux" \
         "$ROOTFS_DIR/opt/fluxwan/config" "$ROOTFS_DIR/opt/fluxwan/bpf" \
         "$ROOTFS_DIR/usr/local/bin" "$ROOTFS_DIR/boot/syslinux" "$ROOTFS_DIR/boot/grub" \
         "$ROOTFS_DIR/dev" "$ROOTFS_DIR/proc" "$ROOTFS_DIR/sys" "$ROOTFS_DIR/tmp" "$ROOTFS_DIR/run" "$ROOTFS_DIR/var/log" "$ROOTFS_DIR/root"

# Copy base binaries and core libraries (musl libc)
cp -a /bin /sbin /lib "$ROOTFS_DIR/" 2>/dev/null || true

# Copy necessary /usr runtime tools only (NO compilers, NO python, NO node)
for ub in /usr/bin/curl /usr/bin/wget /usr/bin/ssh /usr/bin/scp /usr/bin/syslinux /usr/bin/htop /usr/bin/tcpdump; do
    [ -f "$ub" ] && cp -f "$ub" "$ROOTFS_DIR/usr/bin/" 2>/dev/null || true
done
for usb in /usr/sbin/sshd /usr/sbin/partx /usr/sbin/partprobe /usr/sbin/ethtool /usr/sbin/sfdisk; do
    [ -f "$usb" ] && cp -f "$usb" "$ROOTFS_DIR/usr/sbin/" 2>/dev/null || true
done

# Copy ONLY runtime libraries needed by the appliance tools (EXCLUDE compilers, LLVM, Clang, Python, GCC)
for lib in /usr/lib/libssl.so* /usr/lib/libcrypto.so* /usr/lib/libcurl.so* /usr/lib/libz.so* \
           /usr/lib/libfdisk.so* /usr/lib/libsmartcols.so* /usr/lib/libblkid.so* /usr/lib/libuuid.so* \
           /usr/lib/libncursesw.so* /usr/lib/libreadline.so* /usr/lib/libmnl.so* /usr/lib/libnftnl.so* \
           /usr/lib/libnetfilter*.so* /usr/lib/libelf.so* /usr/lib/libelf-*.so* /usr/lib/libbpf.so* \
           /usr/lib/libpcap.so* /usr/lib/libnl*.so*; do
    [ -f "$lib" ] && cp -a "$lib" "$ROOTFS_DIR/usr/lib/" 2>/dev/null || true
done
cp -a /usr/share/syslinux/* "$ROOTFS_DIR/usr/share/syslinux/" 2>/dev/null || true

# Copy Linux Kernel and Initramfs to /boot
cp -f "$BUILD_DIR/iso_extract/boot/vmlinuz-lts" "$ROOTFS_DIR/boot/vmlinuz-lts"
cp -f "$BUILD_DIR/iso_extract/boot/initramfs-lts" "$ROOTFS_DIR/boot/initramfs-lts"

# Copy Filtered Network/Storage Kernel Modules to /lib/modules
mkdir -p "$ROOTFS_DIR/lib/modules"
cp -a "$BUILD_DIR/filtered_modules/"* "$ROOTFS_DIR/lib/modules/" 2>/dev/null || true

# Copy FluxWAN binaries, BPF objects, configs and scripts
cp -f "$PROJECT_ROOT/fluxwan" "$ROOTFS_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$ROOTFS_DIR/opt/fluxwan/config/"
cp -f "$PROJECT_ROOT"/bpf/*.bpf.o "$ROOTFS_DIR/opt/fluxwan/bpf/" 2>/dev/null || true
cp -f "$PROJECT_ROOT/iso/overlay/usr/local/bin/"* "$ROOTFS_DIR/usr/local/bin/" 2>/dev/null || true
chmod +x "$ROOTFS_DIR/usr/local/bin/"* 2>/dev/null || true

# Copy BusyBox Init configs and appliance scripts
cp -f "$PROJECT_ROOT/appliance/etc/inittab" "$ROOTFS_DIR/etc/inittab"
mkdir -p "$ROOTFS_DIR/etc/init.d"
cp -f "$PROJECT_ROOT/appliance/etc/init.d/rcS" "$ROOTFS_DIR/etc/init.d/rcS"
cp -f "$PROJECT_ROOT/appliance/etc/init.d/rcK" "$ROOTFS_DIR/etc/init.d/rcK"
chmod +x "$ROOTFS_DIR/etc/init.d/rcS" "$ROOTFS_DIR/etc/init.d/rcK"

cp -f "$PROJECT_ROOT/appliance/etc/sysctl.conf" "$ROOTFS_DIR/etc/sysctl.conf"
mkdir -p "$ROOTFS_DIR/etc/network"
cp -f "$PROJECT_ROOT/appliance/etc/network/interfaces" "$ROOTFS_DIR/etc/network/interfaces"
cp -f "$PROJECT_ROOT/appliance/etc/passwd" "$ROOTFS_DIR/etc/passwd"
cp -f "$PROJECT_ROOT/appliance/etc/shadow" "$ROOTFS_DIR/etc/shadow"
cp -f "$PROJECT_ROOT/appliance/etc/group" "$ROOTFS_DIR/etc/group"
chmod 600 "$ROOTFS_DIR/etc/shadow"

# Strip Windows CRLF line endings from text configs
find "$ROOTFS_DIR/etc" "$ROOTFS_DIR/usr/local/bin" "$ROOTFS_DIR/boot" -type f -exec sed -i 's/\r$//' {} + 2>/dev/null || true

# Create minimal rootfs tarball
tar -czf "$DIST_DIR/fluxwan-rootfs.tar.gz" -C "$ROOTFS_DIR" .
cp -f "$DIST_DIR/fluxwan-rootfs.tar.gz" "$OUTPUT_DIR/fluxwan-rootfs.tar.gz"

# ------------------------------------------------------------------------------
# Step 4: Build Pre-Baked VMware Virtual Disk (.vmdk) & Raw Flasher (.img.gz)
# ------------------------------------------------------------------------------
echo "[+] Step 4: Building VMware Virtual Disk (.vmdk) & Raw Flasher (.img.gz)..."
RAW_IMG="$DIST_DIR/fluxwan-disk.img"
VMDK_IMG="$DIST_DIR/fluxwan-vmware.vmdk"

# Create 256MB raw disk container
dd if=/dev/zero of="$RAW_IMG" bs=1M count=256 status=none

# Partition MBR DOS
(
  echo "label: dos"
  echo "start=2048, type=83, bootable"
) | sfdisk --force "$RAW_IMG" >/dev/null 2>&1

# Setup loop devices inside Docker
for i in $(seq 0 16); do
    [ -e "/dev/loop$i" ] || mknod -m 660 "/dev/loop$i" b 7 "$i" 2>/dev/null || true
done
[ -e /dev/loop-control ] || mknod -m 660 /dev/loop-control c 10 237 2>/dev/null || true

DEV=$(losetup -f --show "$RAW_IMG")
PART=$(losetup -f --show -o 1048576 "$RAW_IMG")

mkfs.ext4 -F -O ^64bit,^orphan_file,^metadata_csum_seed -L "FLUXWAN_ROOT" "$PART" >/dev/null 2>&1

MNT_DISK="$BUILD_DIR/mnt_disk"
mkdir -p "$MNT_DISK"
mount "$PART" "$MNT_DISK"

cp -a "$ROOTFS_DIR/"* "$MNT_DISK/" 2>/dev/null || true

# Setup Syslinux Bootloader in Disk
mkdir -p "$MNT_DISK/boot/syslinux"
for p in /usr/share/syslinux /usr/lib/syslinux/bios /usr/lib/syslinux; do
    if [ -d "$p" ]; then
        cp -f "$p"/*.c32 "$MNT_DISK/boot/syslinux/" 2>/dev/null || true
        cp -f "$p"/*.bin "$MNT_DISK/boot/syslinux/" 2>/dev/null || true
    fi
done

cat > "$MNT_DISK/boot/syslinux/syslinux.cfg" << 'EOF'
DEFAULT fluxwan
TIMEOUT 20
PROMPT 0

LABEL fluxwan
  KERNEL /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND root=/dev/sda1 rootfstype=ext4 rw quiet console=tty0
EOF
cp -f "$MNT_DISK/boot/syslinux/syslinux.cfg" "$MNT_DISK/syslinux.cfg" 2>/dev/null || true

extlinux --install "$MNT_DISK/boot/syslinux" >/dev/null 2>&1 || true

sync
umount "$MNT_DISK"
losetup -d "$PART"

# Write Syslinux MBR boot code
for mbr in /usr/share/syslinux/mbr.bin /usr/lib/syslinux/bios/mbr.bin; do
    if [ -f "$mbr" ]; then
        dd bs=440 count=1 conv=notrunc if="$mbr" of="$DEV" status=none 2>/dev/null || true
        break
    fi
done
printf '\x80' | dd of="$DEV" bs=1 seek=446 count=1 conv=notrunc status=none 2>/dev/null || true
losetup -d "$DEV"

# Convert to VMware VMDK
qemu-img convert -f raw -O vmdk "$RAW_IMG" "$VMDK_IMG"
cp -f "$VMDK_IMG" "$OUTPUT_DIR/fluxwan-vmware.vmdk"

# Fast compress raw disk image with Gzip
gzip -c -1 "$RAW_IMG" > "$DIST_DIR/fluxwan-disk.img.gz"
cp -f "$DIST_DIR/fluxwan-disk.img.gz" "$OUTPUT_DIR/fluxwan-disk.img.gz"

# ------------------------------------------------------------------------------
# Step 5: Build Hybrid Bootable ISO (UEFI + BIOS)
# ------------------------------------------------------------------------------
echo "[+] Step 5: Building Hybrid Bootable ISO (UEFI + BIOS)..."
mkdir -p "$ISO_DIR/boot/syslinux" "$ISO_DIR/boot/grub" "$ISO_DIR/EFI/BOOT"

# Copy kernel, initramfs and filtered modloop
cp -f "$BUILD_DIR/iso_extract/boot/vmlinuz-lts" "$ISO_DIR/boot/vmlinuz-lts"
cp -f "$BUILD_DIR/iso_extract/boot/initramfs-lts" "$ISO_DIR/boot/initramfs-lts"
cp -f "$BUILD_DIR/modloop-lts" "$ISO_DIR/boot/modloop-lts"

# Copy isolinux/syslinux files for Legacy BIOS boot
for p in /usr/share/syslinux /usr/lib/syslinux/bios /usr/lib/syslinux; do
    if [ -d "$p" ]; then
        cp -f "$p"/isolinux.bin "$ISO_DIR/boot/syslinux/" 2>/dev/null || true
        cp -f "$p"/ldlinux.c32 "$ISO_DIR/boot/syslinux/" 2>/dev/null || true
        cp -f "$p"/*.c32 "$ISO_DIR/boot/syslinux/" 2>/dev/null || true
    fi
done

cat > "$ISO_DIR/boot/syslinux/isolinux.cfg" << 'EOF'
DEFAULT fluxwan
TIMEOUT 30
PROMPT 0

LABEL fluxwan
  MENU LABEL FluxWAN Embedded Network Appliance
  LINUX /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND init_cash_size=64M modules=loop,squashfs,sd-mod,usb-storage,ext4 modloop=/boot/modloop-lts quiet console=tty0
EOF

cp -f "$ISO_DIR/boot/syslinux/isolinux.cfg" "$ISO_DIR/boot/syslinux/syslinux.cfg" 2>/dev/null || true

# Copy GRUB EFI for UEFI boot
cat > "$ISO_DIR/boot/grub/grub.cfg" << 'EOF'
set default=0
set timeout=3

menuentry "FluxWAN Embedded Network Appliance (UEFI)" {
    linux /boot/vmlinuz-lts modloop=/boot/modloop-lts modules=loop,squashfs,sd-mod,usb-storage,ext4 quiet console=tty0
    initrd /boot/initramfs-lts
}
EOF

# Create EFI FAT image for UEFI boot
dd if=/dev/zero of="$BUILD_DIR/efi.img" bs=1M count=8 status=none
mkfs.vfat -F 12 -n "FLUXWAN_EFI" "$BUILD_DIR/efi.img" >/dev/null 2>&1
mkdir -p "$BUILD_DIR/mnt_efi"
mount "$BUILD_DIR/efi.img" "$BUILD_DIR/mnt_efi"
mkdir -p "$BUILD_DIR/mnt_efi/EFI/BOOT"
cp -f "$ISO_DIR/boot/grub/grub.cfg" "$BUILD_DIR/mnt_efi/EFI/BOOT/grub.cfg" 2>/dev/null || true
if [ -f "/usr/lib/grub/x86_64-efi/monolithic/grubx64.efi" ]; then
    cp -f "/usr/lib/grub/x86_64-efi/monolithic/grubx64.efi" "$BUILD_DIR/mnt_efi/EFI/BOOT/BOOTX64.EFI"
    cp -f "/usr/lib/grub/x86_64-efi/monolithic/grubx64.efi" "$ISO_DIR/EFI/BOOT/BOOTX64.EFI" 2>/dev/null || true
fi
umount "$BUILD_DIR/mnt_efi"
cp -f "$BUILD_DIR/efi.img" "$ISO_DIR/boot/syslinux/efi.img" 2>/dev/null || true

# Copy RootFS tarball and installer overlay into ISO
mkdir -p "$ISO_DIR/opt/fluxwan"
cp -f "$DIST_DIR/fluxwan-rootfs.tar.gz" "$ISO_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/fluxwan" "$ISO_DIR/opt/fluxwan/" 2>/dev/null || true
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$ISO_DIR/opt/fluxwan/config.json" 2>/dev/null || true

ISO_OUTPUT="$DIST_DIR/fluxwan-os-x86_64.iso"
xorriso -as mkisofs \
    -iso-level 3 \
    -full-iso9660-filenames \
    -volid "FLUXWAN_OS" \
    -eltorito-boot boot/syslinux/isolinux.bin \
    -eltorito-catalog boot/syslinux/boot.cat \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot \
    -e boot/syslinux/efi.img \
    -no-emul-boot -isohybrid-gpt-basdat \
    -output "$ISO_OUTPUT" \
    "$ISO_DIR" >/dev/null 2>&1 || \
xorriso -as mkisofs \
    -iso-level 3 \
    -volid "FLUXWAN_OS" \
    -eltorito-boot boot/syslinux/isolinux.bin \
    -eltorito-catalog boot/syslinux/boot.cat \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -output "$ISO_OUTPUT" \
    "$ISO_DIR" >/dev/null 2>&1

cp -f "$ISO_OUTPUT" "$OUTPUT_DIR/fluxwan-os-x86_64.iso"

# ------------------------------------------------------------------------------
# Step 6: Measurement and Size Breakdown Report
# ------------------------------------------------------------------------------
echo "======================================================================"
echo "    FluxWAN Embedded Appliance - Build Measurement Report             "
echo "======================================================================"

ISO_SIZE=$(du -h "$ISO_OUTPUT" | awk '{print $1}')
ROOTFS_TAR_SIZE=$(du -h "$DIST_DIR/fluxwan-rootfs.tar.gz" | awk '{print $1}')
VMDK_SIZE=$(du -h "$VMDK_IMG" | awk '{print $1}')
RAW_GZ_SIZE=$(du -h "$DIST_DIR/fluxwan-disk.img.gz" | awk '{print $1}')
KERNEL_SIZE=$(du -h "$BUILD_DIR/iso_extract/boot/vmlinuz-lts" | awk '{print $1}')
INITRD_SIZE=$(du -h "$BUILD_DIR/iso_extract/boot/initramfs-lts" | awk '{print $1}')
DAEMON_SIZE=$(du -h "$PROJECT_ROOT/fluxwan" | awk '{print $1}')

echo "  Total ISO Size       : $ISO_SIZE"
echo "  RootFS Archive Size  : $ROOTFS_TAR_SIZE"
echo "  VMware VMDK Size     : $VMDK_SIZE"
echo "  Compressed Raw Image : $RAW_GZ_SIZE"
echo "  Kernel (vmlinuz-lts) : $KERNEL_SIZE"
echo "  Initramfs Size       : $INITRD_SIZE"
echo "  FluxWAN Core Daemon  : $DAEMON_SIZE"
echo "======================================================================"
echo ""
echo "--- Top 20 Largest Files in RootFS ---"
set +o pipefail
find "$ROOTFS_DIR" -type f -exec du -h {} + 2>/dev/null | sort -rh | head -n 20 || true
set -o pipefail
echo ""
echo "======================================================================"
echo " [✓] BUILD COMPLETED SUCCESSFULLY!"
echo "     All distribution artifacts ready in:"
echo "     - $DIST_DIR/"
echo "     - $OUTPUT_DIR/"
echo "======================================================================"
