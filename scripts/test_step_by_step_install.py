#!/usr/bin/env python3
import subprocess
import time
import sys

def main():
    print("=== TESTING FLUXWAN DISK INSTALLATION WITH FULL VERBOSE LOGGING ===")
    disk_path = "/tmp/debug_target_disk.img"
    with open(disk_path, "wb") as f:
        f.truncate(2 * 1024 * 1024 * 1024)

    proc = subprocess.Popen([
        'qemu-system-x86_64',
        '-nographic',
        '-cdrom', 'dist/fluxwan-os-x86_64.iso',
        '-drive', f'file={disk_path},format=raw,if=ide',
        '-boot', 'd',
        '-m', '512',
        '-serial', 'mon:stdio',
        '-no-reboot',
        '-smp', '1'
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=0)

    # Wait 45s for boot
    time.sleep(45)
    print("Sending root...")
    proc.stdin.write("\nroot\n")
    proc.stdin.flush()
    time.sleep(2)

    # Run manual installation commands step-by-step with full verbosity!
    cmds = """
echo "=== STEP 1: Partitioning ==="
printf "label: dos\\nstart=2048, type=83, bootable\\n" | sfdisk --force /dev/sda
partx -u /dev/sda || partx -a /dev/sda || true
mdev -s
ls -la /dev/sda*

echo "=== STEP 2: Formatting ==="
mkfs.ext4 -F -O ^64bit,^orphan_file,^metadata_csum_seed -L "FLUXWAN_ROOT" /dev/sda1
echo "mkfs exit code: $?"

echo "=== STEP 3: Mounting ==="
mkdir -p /mnt
mount -t ext4 /dev/sda1 /mnt
echo "mount exit code: $?"

echo "=== STEP 4: Copying files ==="
mkdir -p /mnt/boot/syslinux
cp -a /boot/* /mnt/boot/ 2>/dev/null || true
cp -a /usr/lib/syslinux/* /mnt/boot/syslinux/ 2>/dev/null || true
cp -a /usr/lib/syslinux/modules/bios/* /mnt/boot/syslinux/ 2>/dev/null || true
cp -a /opt/fluxwan /mnt/opt/ 2>/dev/null || true

cat << 'EOF' > /mnt/boot/syslinux/syslinux.cfg
DEFAULT fluxwan
TIMEOUT 20
PROMPT 0
LABEL fluxwan
  MENU LABEL FluxWAN Embedded Network Appliance
  LINUX /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND root=/dev/sda1 rootfstype=ext4 rw quiet console=tty0 console=ttyS0,115200
EOF
cp /mnt/boot/syslinux/syslinux.cfg /mnt/boot/syslinux/extlinux.conf
cp /mnt/boot/syslinux/syslinux.cfg /mnt/extlinux.conf
cp /mnt/boot/syslinux/syslinux.cfg /mnt/syslinux.cfg

echo "=== STEP 5: Extlinux install ==="
extlinux --version
extlinux --install /mnt/boot/syslinux
echo "extlinux install exit code: $?"
ls -la /mnt/boot/syslinux/

echo "=== STEP 6: MBR Installation ==="
find / -name "mbr.bin"
MBR_FILE=$(find / -name "mbr.bin" | head -1)
echo "Found MBR: $MBR_FILE"
dd bs=440 count=1 conv=notrunc if="$MBR_FILE" of=/dev/sda
echo "dd MBR exit code: $?"

sfdisk --activate /dev/sda 1
echo "sfdisk activate exit code: $?"

# Dump MBR partition table to verify active flag (0x80)
hexdump -C -n 512 /dev/sda | tail -n 6

sync
umount /mnt
echo "=== ALL STEPS FINISHED ==="
poweroff
"""
    print("Sending commands...")
    proc.stdin.write(cmds)
    proc.stdin.flush()

    out, _ = proc.communicate(timeout=60)
    print("=== RAW QEMU VERBOSE LOG ===")
    print(out)

if __name__ == '__main__':
    main()
