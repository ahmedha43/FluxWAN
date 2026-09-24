#!/bin/bash
set -euo pipefail

echo "=== [1/8] Preparing Environment and Kernel Modules ==="
modprobe loop || true

VERSION="1.2.5"
ISO_PATH="/tmp/fluxwan-os-x86_64.iso"
TARGET_DIR="/opt/unetlab/addons/qemu/linux-fluxwan-${VERSION}"
CUSTOM_DIR="/opt/unetlab/addons/qemu/fluxwan-${VERSION}"
FINAL_QCOW2="${TARGET_DIR}/virtioa.qcow2"
RAW_IMG="/tmp/fluxwan_disk.raw"

mkdir -p "$TARGET_DIR" "$CUSTOM_DIR" /mnt/iso /mnt/target

echo "=== [2/8] Mounting FluxWAN ISO ==="
mountpoint -q /mnt/iso || mount -o loop,ro "$ISO_PATH" /mnt/iso

echo "=== [3/8] Creating 1500MB Raw Disk Image ==="
rm -f "$RAW_IMG" "$FINAL_QCOW2"
truncate -s 1500M "$RAW_IMG"

echo "=== [4/8] Setting Up Loop Device and Partitioning ==="
LOOP_DEV=$(losetup -f -P --show "$RAW_IMG")
echo "Attached loop device: $LOOP_DEV"

# Partition with MBR
parted -s "$LOOP_DEV" mklabel msdos
parted -s "$LOOP_DEV" mkpart primary ext4 2048s 100%
parted -s "$LOOP_DEV" set 1 boot on
partprobe "$LOOP_DEV" 2>/dev/null || true
sleep 1

PART_DEV="${LOOP_DEV}p1"
[ -b "$PART_DEV" ] || PART_DEV="${LOOP_DEV}1"

echo "=== [5/8] Formatting Ext4 Filesystem ==="
mkfs.ext4 -F -L "FLUXWAN_ROOT" "$PART_DEV"
mount -t ext4 "$PART_DEV" /mnt/target

echo "=== [6/8] Extracting RootFS and Kernel Modules ==="
tar -xzf /mnt/iso/opt/fluxwan/fluxwan-rootfs.tar.gz -C /mnt/target/

mkdir -p /mnt/target/boot /mnt/target/lib/modules
rm -rf /tmp/modloop_extracted
unsquashfs -f -d /tmp/modloop_extracted /mnt/iso/boot/modloop-lts
cp -a /tmp/modloop_extracted/modules/* /mnt/target/lib/modules/
rm -rf /tmp/modloop_extracted

# Copy Kernel & Initramfs
cp -f /mnt/iso/boot/vmlinuz-lts /mnt/target/boot/vmlinuz-lts
cp -f /mnt/iso/boot/initramfs-lts /mnt/target/boot/initramfs-lts
cp -f /mnt/iso/boot/modloop-lts /mnt/target/boot/modloop-lts

# Copy updated binary if provided
if [ -f /tmp/fluxwan_binary ]; then
    cp -f /tmp/fluxwan_binary /mnt/target/opt/fluxwan/fluxwan
    chmod 755 /mnt/target/opt/fluxwan/fluxwan
fi

# Ensure /etc/fstab
cat << 'EOF' > /mnt/target/etc/fstab
/dev/vda1        /          ext4    defaults,noatime,rw    0 1
tmpfs            /tmp       tmpfs   defaults,nosuid,nodev  0 0
tmpfs            /run       tmpfs   mode=0755,nosuid,nodev 0 0
devpts           /dev/pts   devpts  gid=5,mode=620         0 0
proc             /proc      proc    defaults               0 0
sysfs            /sys       sysfs   defaults               0 0
EOF

# Ensure /etc/inittab
cat << 'EOF' > /mnt/target/etc/inittab
# /etc/inittab - FluxWAN Network Appliance
::sysinit:/etc/init.d/rcS

# Telnet / Serial Console for EVE-NG
ttyS0::respawn:/usr/local/bin/fluxwan-menu
tty1::respawn:/usr/local/bin/fluxwan-menu
tty2::respawn:/bin/ash

::ctrlaltdel:/sbin/reboot
::shutdown:/etc/init.d/rcK
EOF

echo "=== [7/8] Installing Bootloader (GRUB & Extlinux) ==="
mkdir -p /mnt/target/boot/grub /mnt/target/boot/syslinux /mnt/target/boot/extlinux

# 1. GRUB Configuration
cat << 'EOF' > /mnt/target/boot/grub/grub.cfg
set default=0
set timeout=1
set timeout_style=menu

serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console

menuentry "FluxWAN Multi-WAN Router Appliance" {
    linux /boot/vmlinuz-lts root=/dev/vda1 rootflags=rw rootfstype=ext4 init=/sbin/init rw quiet console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-lts
}
EOF

# Install GRUB
if command -v grub-install >/dev/null 2>&1; then
    echo "Installing GRUB to $LOOP_DEV..."
    grub-install --target=i386-pc --boot-directory=/mnt/target/boot "$LOOP_DEV" || true
fi

# 2. Syslinux/Extlinux Configuration as Fallback
cp -f /mnt/iso/boot/syslinux/*.c32 /mnt/target/boot/syslinux/ 2>/dev/null || true
cp -f /mnt/iso/boot/syslinux/*.c32 /mnt/target/boot/extlinux/ 2>/dev/null || true
cp -f /mnt/iso/boot/syslinux/*.c32 /mnt/target/boot/ 2>/dev/null || true
cp -f /mnt/target/boot/vmlinuz-lts /mnt/target/boot/syslinux/ 2>/dev/null || true
cp -f /mnt/target/boot/initramfs-lts /mnt/target/boot/syslinux/ 2>/dev/null || true
cp -f /mnt/target/boot/vmlinuz-lts /mnt/target/ 2>/dev/null || true
cp -f /mnt/target/boot/initramfs-lts /mnt/target/ 2>/dev/null || true

cat << 'EOF' > /tmp/fluxwan_boot.cfg
SERIAL 0 115200
DEFAULT fluxwan
TIMEOUT 10
PROMPT 0

LABEL fluxwan
  MENU LABEL FluxWAN Multi-WAN Router Appliance
  LINUX /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND root=/dev/vda1 rootflags=rw rootfstype=ext4 init=/sbin/init rw quiet console=ttyS0,115200 console=tty0
EOF

for dest in \
    /mnt/target/boot/syslinux/syslinux.cfg \
    /mnt/target/boot/syslinux/extlinux.conf \
    /mnt/target/boot/extlinux/extlinux.conf \
    /mnt/target/boot/extlinux/syslinux.cfg \
    /mnt/target/boot/syslinux.cfg \
    /mnt/target/boot/extlinux.conf \
    /mnt/target/syslinux.cfg \
    /mnt/target/extlinux.conf; do
    cp -f /tmp/fluxwan_boot.cfg "$dest"
done



sync
umount /mnt/target
losetup -d "$LOOP_DEV"
umount /mnt/iso 2>/dev/null || true

echo "=== [8/8] Converting to Compressed QCOW2 Disk ==="
qemu-img convert -c -O qcow2 "$RAW_IMG" "$FINAL_QCOW2"
rm -f "$RAW_IMG"

# Link to custom template
rm -f "${CUSTOM_DIR}/virtioa.qcow2"
ln -sf "${FINAL_QCOW2}" "${CUSTOM_DIR}/virtioa.qcow2"

if [ -f /tmp/fluxwan.yml ]; then
    cp -f /tmp/fluxwan.yml /opt/unetlab/html/templates/intel/fluxwan.yml
    cp -f /tmp/fluxwan.yml /opt/unetlab/html/templates/amd/fluxwan.yml 2>/dev/null || true
fi

/opt/unetlab/wrappers/unl_wrapper -a fixpermissions

echo "=== [✓] FLUXWAN INSTALLATION COMPLETED SUCCESSFULLY! ==="
ls -lh "$FINAL_QCOW2"
