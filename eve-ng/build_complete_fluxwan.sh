#!/bin/bash
set -euo pipefail

echo "=== [1/7] Preparing Environment ==="
modprobe loop || true

TARGET_DIR="/opt/unetlab/addons/qemu/linux-fluxwan-1.2.5"
CUSTOM_DIR="/opt/unetlab/addons/qemu/fluxwan-1.2.5"
FINAL_QCOW2="${TARGET_DIR}/virtioa.qcow2"
RAW_IMG="/tmp/fluxwan_disk.raw"
MNT="/mnt/target"

mkdir -p "$TARGET_DIR" "$CUSTOM_DIR" "$MNT"
rm -f "$RAW_IMG" "$FINAL_QCOW2"
truncate -s 1500M "$RAW_IMG"

echo "=== [2/7] Partitioning and Mounting Raw Disk ==="
LOOP_DEV=$(losetup -f -P --show "$RAW_IMG")
echo "Using loop device: $LOOP_DEV"

parted -s "$LOOP_DEV" mklabel msdos
parted -s "$LOOP_DEV" mkpart primary ext4 2048s 100%
parted -s "$LOOP_DEV" set 1 boot on
partprobe "$LOOP_DEV" 2>/dev/null || true
sleep 1

PART_DEV="${LOOP_DEV}p1"
[ -b "$PART_DEV" ] || PART_DEV="${LOOP_DEV}1"

mkfs.ext4 -F -L "FLUXWAN_ROOT" "$PART_DEV"
mount -t ext4 "$PART_DEV" "$MNT"

echo "=== [3/7] Extracting Base Alpine System (Minirootfs) ==="
# This extracts real /bin/busybox, /sbin/init, /lib/ld-musl-x86_64.so.1, etc.
tar -xzf /tmp/alpine-minirootfs.tar.gz -C "$MNT/"

echo "=== [4/7] Creating Static Device Nodes ==="
# switch_root specifically verifies /dev/console before pivoting!
mkdir -p "$MNT/dev" "$MNT/proc" "$MNT/sys" "$MNT/tmp" "$MNT/run" "$MNT/var/log" "$MNT/var/run" "$MNT/root" "$MNT/opt/fluxwan/config" "$MNT/opt/fluxwan/bpf"
mknod -m 600 "$MNT/dev/console" c 5 1
mknod -m 666 "$MNT/dev/null" c 1 3
mknod -m 666 "$MNT/dev/zero" c 1 5
mknod -m 666 "$MNT/dev/tty" c 5 0
mknod -m 620 "$MNT/dev/tty0" c 4 0
mknod -m 660 "$MNT/dev/ttyS0" c 4 64
mknod -m 666 "$MNT/dev/ptmx" c 5 2

echo "=== [5/7] Installing FluxWAN Daemon, Overlay and Kernel Modules ==="
tar -xzf /tmp/fluxwan-rootfs.tar.gz -C "$MNT/"

# Extract kernel modules from modloop
mkdir -p "$MNT/lib/modules" /tmp/modloop_extracted
rm -rf /tmp/modloop_extracted
unsquashfs -f -d /tmp/modloop_extracted /tmp/modloop-lts
cp -a /tmp/modloop_extracted/modules/* "$MNT/lib/modules/"
rm -rf /tmp/modloop_extracted

# Copy Kernel & Initramfs
mkdir -p "$MNT/boot"
cp -f /tmp/vmlinuz-lts "$MNT/boot/vmlinuz-lts"
cp -f /tmp/initramfs-lts "$MNT/boot/initramfs-lts"

# Install latest FluxWAN binary & config
if [ -f /tmp/fluxwan_binary ]; then
    cp -f /tmp/fluxwan_binary "$MNT/opt/fluxwan/fluxwan"
fi
chmod 755 "$MNT/opt/fluxwan/fluxwan"
mkdir -p "$MNT/root/config" "$MNT/config"
ln -sf /opt/fluxwan/config/fluxwan.json "$MNT/root/config/fluxwan.json" 2>/dev/null || true
ln -sf /opt/fluxwan/config/fluxwan.json "$MNT/config/fluxwan.json" 2>/dev/null || true

# Write /etc/fstab
cat << 'EOF' > "$MNT/etc/fstab"
/dev/vda1        /          ext4    defaults,noatime,rw    0 1
tmpfs            /tmp       tmpfs   defaults,nosuid,nodev  0 0
tmpfs            /run       tmpfs   mode=0755,nosuid,nodev 0 0
devpts           /dev/pts   devpts  gid=5,mode=620         0 0
proc             /proc      proc    defaults               0 0
sysfs            /sys       sysfs   defaults               0 0
EOF

# Write /etc/inittab
cat << 'EOF' > "$MNT/etc/inittab"
# /etc/inittab - FluxWAN Network Appliance
::sysinit:/etc/init.d/rcS

# Serial Console for EVE-NG Telnet & Monitor
ttyS0::respawn:/usr/local/bin/fluxwan-menu
tty1::respawn:/usr/local/bin/fluxwan-menu
tty2::respawn:/bin/ash

::ctrlaltdel:/sbin/reboot
::shutdown:/etc/init.d/rcK
EOF

# Write robust /etc/init.d/rcS
cat << 'EOF' > "$MNT/etc/init.d/rcS"
#!/bin/sh
# FluxWAN Embedded Network Appliance Startup (/etc/init.d/rcS)
mount -o remount,rw / 2>/dev/null || true
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm /tmp /run /var/log /var/run
mount -t devpts devpts /dev/pts -o gid=5,mode=620 2>/dev/null || true
mount -t tmpfs tmpfs /tmp -o mode=1777 2>/dev/null || true
mount -t tmpfs tmpfs /run 2>/dev/null || true

if [ -x /sbin/mdev ]; then
    echo /sbin/mdev > /proc/sys/kernel/hotplug 2>/dev/null || true
    mdev -s 2>/dev/null || true
fi

# Kernel Network Tuning
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null 2>&1 || true

# Load VirtIO and networking kernel modules
for mod in loop ext4 virtio_net virtio_blk virtio_pci e1000 e1000e tun tap packet af_packet ppp_generic pppoe xt_conntrack xt_nat xt_MASQUERADE xt_mark xt_statistic xt_TCPMSS sch_cake nft_masq nft_nat iptable_nat iptable_mangle iptable_filter; do
    modprobe $mod 2>/dev/null || true
done

# Ensure iptables uses legacy if available
if [ -x /sbin/iptables-legacy ]; then
    ln -sf /sbin/iptables-legacy /sbin/iptables 2>/dev/null || true
    ln -sf /sbin/iptables-legacy /sbin/iptables-save 2>/dev/null || true
    ln -sf /sbin/iptables-legacy /sbin/iptables-restore 2>/dev/null || true
fi

# Ensure ip command is available (fallback to busybox if dynamic library missing)
if ! ip addr >/dev/null 2>&1; then
    ln -sf /bin/busybox /sbin/ip 2>/dev/null || true
fi

# Bring up loopback
ip link set lo up 2>/dev/null || true

# Auto-configure primary LAN interface (eth0)
ip link set eth0 up 2>/dev/null || true
ip addr add 192.168.90.1/24 dev eth0 2>/dev/null || true

# Bring up all physical WAN interfaces
for iface in $(ls /sys/class/net 2>/dev/null); do
    if [ "$iface" != "lo" ]; then
        ip link set "$iface" up 2>/dev/null || true
    fi
done

# Web UI Redirection: Port 80 -> 8080
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true

# Start Dropbear SSH Daemon
mkdir -p /etc/dropbear /root/.ssh
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null || true
echo "root:admin" | chpasswd 2>/dev/null || true
dropbear -R -B -p 22 2>/dev/null || /usr/sbin/dropbear -R -B -p 22 2>/dev/null || true

# Start FluxWAN Core Reactor Daemon
mkdir -p /root/config /config
ln -sf /opt/fluxwan/config/fluxwan.json /root/config/fluxwan.json 2>/dev/null || true
ln -sf /opt/fluxwan/config/fluxwan.json /config/fluxwan.json 2>/dev/null || true
if [ -x /opt/fluxwan/fluxwan ] && [ -f /opt/fluxwan/config/fluxwan.json ]; then
    /opt/fluxwan/fluxwan /opt/fluxwan/config/fluxwan.json >/var/log/fluxwan.log 2>&1 &
fi
EOF
chmod +x "$MNT/etc/init.d/rcS"

echo "=== [5.5/7] Installing Networking Packages via APK inside Rootfs ==="
cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true
chroot "$MNT" apk update 2>/dev/null || true
chroot "$MNT" apk add --no-cache iptables iptables-legacy iproute2 nftables curl conntrack-tools libcap 2>/dev/null || true
if [ -f "$MNT/sbin/iptables-legacy" ]; then
    ln -sf /sbin/iptables-legacy "$MNT/sbin/iptables" 2>/dev/null || true
    ln -sf /sbin/iptables-legacy "$MNT/sbin/iptables-save" 2>/dev/null || true
    ln -sf /sbin/iptables-legacy "$MNT/sbin/iptables-restore" 2>/dev/null || true
fi

echo "=== [6/7] Installing GRUB Bootloader ==="
mkdir -p "$MNT/boot/grub"

cat << 'EOF' > "$MNT/boot/grub/grub.cfg"
set default=0
set timeout=1
set timeout_style=menu

serial --unit=0 --speed=115200
terminal_input serial console
terminal_output serial console

menuentry "FluxWAN Multi-WAN Router Appliance" {
    linux /boot/vmlinuz-lts root=/dev/vda1 modules=loop,squashfs,sd-mod,usb-storage,ext4,virtio-blk,virtio-scsi,virtio_pci,virtio_net rootflags=rw rootfstype=ext4 rw console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-lts
}
menuentry "FluxWAN (Safe / Verbose)" {
    linux /boot/vmlinuz-lts root=/dev/vda1 modules=loop,squashfs,sd-mod,usb-storage,ext4,virtio-blk,virtio-scsi,virtio_pci,virtio_net rootflags=rw rootfstype=ext4 rw debug verbose console=ttyS0,115200 console=tty0
    initrd /boot/initramfs-lts
}

EOF

grub-install --target=i386-pc --boot-directory="$MNT/boot" "$LOOP_DEV"

sync
umount "$MNT"
losetup -d "$LOOP_DEV"

echo "=== [7/7] Converting to Compressed QCOW2 Disk ==="
qemu-img convert -c -O qcow2 "$RAW_IMG" "$FINAL_QCOW2"
rm -f "$RAW_IMG"

# Link to custom template directory
rm -f "${CUSTOM_DIR}/virtioa.qcow2"
ln -sf "${FINAL_QCOW2}" "${CUSTOM_DIR}/virtioa.qcow2"

# Reset EVE-NG permissions
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions

echo "=== [✓] FLUXWAN COMPLETED SUCCESSFULLY! ==="
ls -lh "$FINAL_QCOW2"
