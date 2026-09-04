#!/bin/sh
# ==============================================================================
# FluxWAN Embedded Network Appliance - Universal Hard Disk / NVMe / VM Installer
# Supports:
#   - Physical Bare-Metal SATA SSD/HDD (/dev/sdX)
#   - High-Speed NVMe PCIe Storage (/dev/nvmeXnX)
#   - Virtual Machines: VMware SCSI, VirtualBox, Proxmox/KVM VirtIO (/dev/vdX)
#   - Dual Boot Architecture: UEFI (GPT + ESP) & Legacy BIOS (MBR + GRUB)
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}      ⚡ FluxWAN Multi-WAN Appliance - Production Disk Installer     ${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo ""

# 1. Root Permission Check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] ERROR: This installer must be run as root.${NC}" >&2
    exit 1
fi

# Parse CLI arguments
AUTO_DISK=""
AUTO_CONFIRM=0

while [ $# -gt 0 ]; do
    case "$1" in
        --disk|-d)
            AUTO_DISK="$2"
            shift 2
            ;;
        --yes|-y)
            AUTO_CONFIRM=1
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# 2. Check and Install Required Tools
echo -e "${BLUE}[1/6] Checking required storage and partition tools...${NC}"
modprobe ext4 2>/dev/null || true
modprobe vfat 2>/dev/null || true
modprobe fat 2>/dev/null || true
modprobe loop 2>/dev/null || true

MISSING_TOOLS=""
for tool in sfdisk mkfs.ext4 partx blkid; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
done

if [ -n "$MISSING_TOOLS" ]; then
    echo -e "${YELLOW}[*] Installing missing utilities: $MISSING_TOOLS...${NC}"
    apk add --quiet sfdisk e2fsprogs dosfstools partx blkid util-linux grub-bios 2>/dev/null || true
fi

# 3. Detect Firmware Boot Mode (UEFI vs Legacy BIOS)
IS_UEFI=0
if [ -d "/sys/firmware/efi" ]; then
    IS_UEFI=1
    echo -e "    * Firmware Mode : ${GREEN}${BOLD}UEFI 64-bit (GPT + ESP Partition Table)${NC}"
else
    echo -e "    * Firmware Mode : ${YELLOW}${BOLD}Legacy BIOS / CSM (MBR Partition Table)${NC}"
fi

# 4. Storage Device Discovery
echo -e "${BLUE}[2/6] Scanning available storage drives...${NC}"
DISKS_LIST=""
DISK_COUNT=0

for block_dev in $(ls /sys/block/ 2>/dev/null); do
    case "$block_dev" in
        sd*|nvme*|vd*|hd*|xvd*)
            RO=$(cat "/sys/block/$block_dev/ro" 2>/dev/null || echo 1)
            if [ "$RO" = "0" ]; then
                SIZE_SECTORS=$(cat "/sys/block/$block_dev/size" 2>/dev/null || echo 0)
                SIZE_MB=$((SIZE_SECTORS * 512 / 1024 / 1024))
                MODEL=$(cat "/sys/block/$block_dev/device/model" 2>/dev/null || echo "Generic Storage")
                MODEL=$(echo "$MODEL" | sed 's/^[ \t]*//;s/[ \t]*$//')
                [ -z "$MODEL" ] && MODEL="Internal Storage Device"
                
                # Filter out tiny loopback/RAM drives < 500MB
                if [ "$SIZE_MB" -gt 500 ]; then
                    DISK_COUNT=$((DISK_COUNT + 1))
                    DISKS_LIST="$DISKS_LIST /dev/$block_dev"
                    echo -e "    [$DISK_COUNT] ${BOLD}/dev/$block_dev${NC} - $MODEL (${SIZE_MB} MB / $(awk "BEGIN {printf \"%.1f\", $SIZE_MB/1024}") GB)"
                fi
            fi
            ;;
    esac
done

if [ "$DISK_COUNT" -eq 0 ]; then
    echo -e "${RED}[!] FATAL: No writable hard disk or NVMe drive found on this system!${NC}" >&2
    exit 1
fi

TARGET_DEV=""
if [ -n "$AUTO_DISK" ]; then
    TARGET_DEV="$AUTO_DISK"
elif [ "$DISK_COUNT" -eq 1 ]; then
    TARGET_DEV=$(echo "$DISKS_LIST" | awk '{print $1}')
    echo -e "    * Automatically selected single available drive: ${GREEN}${BOLD}$TARGET_DEV${NC}"
else
    echo ""
    printf "Enter target drive path (e.g. /dev/sda, /dev/nvme0n1, /dev/vda): "
    read -r TARGET_DEV
fi

if [ ! -b "$TARGET_DEV" ]; then
    echo -e "${RED}[!] ERROR: Invalid block device $TARGET_DEV${NC}" >&2
    exit 1
fi

if [ "$AUTO_CONFIRM" -ne 1 ]; then
    echo ""
    echo -e "${RED}${BOLD}======================================================================${NC}"
    echo -e "${RED}${BOLD}  WARNING: ALL DATA ON $TARGET_DEV WILL BE PERMANENTLY ERASED!        ${NC}"
    echo -e "${RED}${BOLD}======================================================================${NC}"
    printf "Type 'YES' to format and install FluxWAN to $TARGET_DEV: "
    read -r CONFIRM
    if [ "$CONFIRM" != "YES" ] && [ "$CONFIRM" != "yes" ]; then
        echo -e "${YELLOW}[*] Installation aborted by user.${NC}"
        exit 0
    fi
fi

# 5. Partitioning and Formatting
echo -e "${BLUE}[3/6] Partitioning target drive $TARGET_DEV...${NC}"

# Unmount any existing partitions on target
for p in $(ls /dev/$(basename "$TARGET_DEV")* 2>/dev/null); do
    umount -f "$p" 2>/dev/null || true
    swapoff "$p" 2>/dev/null || true
done

# Wipe existing partition signatures
dd if=/dev/zero of="$TARGET_DEV" bs=1M count=16 conv=notrunc status=none 2>/dev/null || true

if [ "$IS_UEFI" -eq 1 ]; then
    echo "    * Creating GPT Partition Table (512MB EFI ESP + Ext4 Root)..."
    cat << 'EOF' | sfdisk --quiet "$TARGET_DEV" >/dev/null 2>&1
label: gpt
size=512MiB, type=U, name="EFI System Partition"
size=+, type=L, name="FluxWAN Root"
EOF
else
    echo "    * Creating MBR Partition Table (Bootable Ext4 Root)..."
    cat << 'EOF' | sfdisk --quiet "$TARGET_DEV" >/dev/null 2>&1
label: dos
size=+, type=83, bootable
EOF
fi

# Inform kernel of partition table changes
sync
sfdisk -R "$TARGET_DEV" 2>/dev/null || true
partx -u "$TARGET_DEV" 2>/dev/null || true
partprobe "$TARGET_DEV" 2>/dev/null || true
blockdev --rereadpt "$TARGET_DEV" 2>/dev/null || true
mdev -s 2>/dev/null || true
sleep 2

if [ "$IS_UEFI" -eq 0 ]; then
    sfdisk --activate "$TARGET_DEV" 1 2>/dev/null || true
fi

# Detect partition naming (e.g. sda1 vs nvme0n1p1)
if [ -b "${TARGET_DEV}p1" ]; then
    PART_PREFIX="${TARGET_DEV}p"
else
    PART_PREFIX="${TARGET_DEV}"
fi

EFI_PART=""
if [ "$IS_UEFI" -eq 1 ]; then
    EFI_PART="${PART_PREFIX}1"
    ROOT_PART="${PART_PREFIX}2"
    echo -e "    * Formatting EFI Partition ($EFI_PART as FAT32)..."
    mkfs.vfat -F 32 -n "FLUX_EFI" "$EFI_PART" >/dev/null 2>&1 || mkfs.fat -F 32 "$EFI_PART" >/dev/null 2>&1
else
    ROOT_PART="${PART_PREFIX}1"
fi

mdev -s 2>/dev/null || true
sleep 1

# Helper: Ensure ext4 kernel module is actively loaded in the running kernel
ensure_ext4_ready() {
    grep -qw "ext4" /proc/filesystems && return 0
    modprobe ext4 2>/dev/null || true
    grep -qw "ext4" /proc/filesystems && return 0

    echo -e "    * Loading ext4 filesystem kernel modules..."
    # Attempt to mount modloop if modules are still compressed on boot media
    for ml in /media/*/boot/modloop-lts /media/sr0/boot/modloop-lts /boot/modloop-lts; do
        if [ -f "$ml" ]; then
            mkdir -p /.modloop_tmp
            mount -t squashfs -o loop,ro "$ml" /.modloop_tmp 2>/dev/null || true
            if [ -d /.modloop_tmp/modules ]; then
                cp -a /.modloop_tmp/modules/* /lib/modules/ 2>/dev/null || true
                depmod -a 2>/dev/null || true
                modprobe ext4 2>/dev/null || true
            fi
            umount /.modloop_tmp 2>/dev/null || true
            break
        fi
    done
    grep -qw "ext4" /proc/filesystems && return 0

    # Manual insmod discovery fallback
    for mod in crc16 mbcache jbd2 ext4; do
        modfile=$(find /lib/modules /media -name "${mod}.ko*" 2>/dev/null | head -n 1)
        if [ -n "$modfile" ]; then
            insmod "$modfile" 2>/dev/null || true
        fi
    done
    grep -qw "ext4" /proc/filesystems && return 0
    echo -e "${YELLOW}[!] WARNING: ext4 filesystem module not yet registered in kernel.${NC}"
}

ensure_ext4_ready

echo -e "    * Formatting Root Partition ($ROOT_PART as Ext4)..."
mkfs.ext4 -F -L "FLUXWAN_ROOT" "$ROOT_PART" || {
    echo -e "${YELLOW}[*] Retrying ext4 format on $ROOT_PART...${NC}"
    sync
    sleep 2
    mkfs.ext4 -F -L "FLUXWAN_ROOT" "$ROOT_PART"
}

sync
mdev -s 2>/dev/null || true
sleep 1

# 6. Deploying Filesystem & Kernel
echo -e "${BLUE}[4/6] Deploying FluxWAN Embedded Operating System...${NC}"
MOUNT_DIR="/tmp/fluxwan_install_target"
umount -f "$MOUNT_DIR" 2>/dev/null || true
rm -rf "$MOUNT_DIR"
mkdir -p "$MOUNT_DIR"

ensure_ext4_ready

# Ensure root partition block device is ready
if [ ! -b "$ROOT_PART" ]; then
    echo -e "    * Waiting for $ROOT_PART block device node..."
    mdev -s 2>/dev/null || true
    partprobe "$TARGET_DEV" 2>/dev/null || true
    sleep 2
fi

# Mount root partition
MOUNTED=0
for i in 1 2 3; do
    if mount -t ext4 "$ROOT_PART" "$MOUNT_DIR" 2>/dev/null || mount "$ROOT_PART" "$MOUNT_DIR" 2>/dev/null; then
        MOUNTED=1
        break
    fi
    sleep 1
    mdev -s 2>/dev/null || true
done

if [ "$MOUNTED" -ne 1 ]; then
    echo -e "${RED}[!] ERROR: Failed to mount root partition $ROOT_PART on $MOUNT_DIR.${NC}" >&2
    exit 1
fi

# Create standard Linux root directory structure
mkdir -p "$MOUNT_DIR/bin" "$MOUNT_DIR/sbin" "$MOUNT_DIR/lib" "$MOUNT_DIR/etc" \
         "$MOUNT_DIR/usr/bin" "$MOUNT_DIR/usr/sbin" "$MOUNT_DIR/usr/lib" \
         "$MOUNT_DIR/usr/local/bin" "$MOUNT_DIR/opt/fluxwan/config" "$MOUNT_DIR/opt/fluxwan/bpf" \
         "$MOUNT_DIR/boot" "$MOUNT_DIR/root" "$MOUNT_DIR/dev" "$MOUNT_DIR/proc" \
         "$MOUNT_DIR/sys" "$MOUNT_DIR/tmp" "$MOUNT_DIR/run" "$MOUNT_DIR/var/log" "$MOUNT_DIR/var/run"

echo -e "    * Copying core system binaries and libraries..."
cp -a /bin/* "$MOUNT_DIR/bin/" 2>/dev/null || true
cp -a /sbin/* "$MOUNT_DIR/sbin/" 2>/dev/null || true
cp -a /lib/* "$MOUNT_DIR/lib/" 2>/dev/null || true
cp -a /etc/* "$MOUNT_DIR/etc/" 2>/dev/null || true
cp -a /usr/bin/* "$MOUNT_DIR/usr/bin/" 2>/dev/null || true
cp -a /usr/sbin/* "$MOUNT_DIR/usr/sbin/" 2>/dev/null || true
cp -a /usr/lib/* "$MOUNT_DIR/usr/lib/" 2>/dev/null || true
cp -a /usr/local/bin/* "$MOUNT_DIR/usr/local/bin/" 2>/dev/null || true
chmod +x "$MOUNT_DIR/usr/local/bin/"* 2>/dev/null || true

# Copy FluxWAN engine and BPF objects
echo -e "    * Copying FluxWAN Reactor Daemon & Web Control Plane..."
if [ -d /opt/fluxwan ]; then
    cp -a /opt/fluxwan/* "$MOUNT_DIR/opt/fluxwan/" 2>/dev/null || true
fi
chmod +x "$MOUNT_DIR/opt/fluxwan/fluxwan" 2>/dev/null || true

# Locate live media boot files
LIVE_BOOT_DIR=""
for candidate in /media/*/boot /media/sr0/boot /media/cdrom/boot /boot; do
    if [ -f "$candidate/vmlinuz-lts" ]; then
        LIVE_BOOT_DIR="$candidate"
        break
    fi
done

echo -e "    * Copying Linux LTS Kernel & Driver Modloop..."
if [ -n "$LIVE_BOOT_DIR" ]; then
    cp -f "$LIVE_BOOT_DIR/vmlinuz-lts" "$MOUNT_DIR/boot/"
    cp -f "$LIVE_BOOT_DIR/initramfs-lts" "$MOUNT_DIR/boot/"
    [ -f "$LIVE_BOOT_DIR/modloop-lts" ] && cp -f "$LIVE_BOOT_DIR/modloop-lts" "$MOUNT_DIR/boot/"
    if [ -d "$LIVE_BOOT_DIR/syslinux" ]; then
        mkdir -p "$MOUNT_DIR/boot/syslinux"
        cp -a "$LIVE_BOOT_DIR/syslinux/." "$MOUNT_DIR/boot/syslinux/" 2>/dev/null || true
    fi
fi

# Ensure kernel modules are unpacked in /lib/modules
if [ -d /lib/modules ]; then
    cp -a /lib/modules/* "$MOUNT_DIR/lib/modules/" 2>/dev/null || true
fi

# Generate /etc/fstab with UUIDs
ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART" 2>/dev/null || echo "")
if [ -n "$ROOT_UUID" ]; then
    ROOT_SPEC="UUID=$ROOT_UUID"
else
    ROOT_SPEC="$ROOT_PART"
fi

if [ "$IS_UEFI" -eq 1 ] && [ -n "$EFI_PART" ]; then
    EFI_UUID=$(blkid -s UUID -o value "$EFI_PART" 2>/dev/null || echo "")
    if [ -n "$EFI_UUID" ]; then
        EFI_SPEC="UUID=$EFI_UUID"
    else
        EFI_SPEC="$EFI_PART"
    fi
else
    EFI_SPEC="# no-efi"
fi

cat << EOF > "$MOUNT_DIR/etc/fstab"
# /etc/fstab: Static file system table for FluxWAN Appliance
$ROOT_SPEC               /               ext4        defaults,noatime,rw         0       1
EOF

if [ "$IS_UEFI" -eq 1 ]; then
    echo "$EFI_SPEC               /boot/efi       vfat        defaults,noatime            0       2" >> "$MOUNT_DIR/etc/fstab"
fi

cat << 'EOF' >> "$MOUNT_DIR/etc/fstab"
tmpfs                       /tmp            tmpfs       defaults,nosuid,nodev       0       0
tmpfs                       /run            tmpfs       mode=0755,nosuid,nodev      0       0
devpts                      /dev/pts        devpts      gid=5,mode=620              0       0
proc                        /proc           proc        defaults                    0       0
sysfs                       /sys            sysfs       defaults                    0       0
EOF

# 7. Installing GRUB Bootloader
echo -e "${BLUE}[5/6] Installing GRUB Bootloader to $TARGET_DEV...${NC}"

if [ "$IS_UEFI" -eq 1 ]; then
    echo "    * Installing GRUB EFI Bootloader..."
    mkdir -p "$MOUNT_DIR/boot/efi"
    mount "$EFI_PART" "$MOUNT_DIR/boot/efi" || {
        echo -e "${RED}[!] ERROR: Cannot mount EFI system partition $EFI_PART.${NC}" >&2
        exit 1
    }
    mkdir -p "$MOUNT_DIR/boot/efi/EFI/BOOT"

    cat << EOF > "$MOUNT_DIR/boot/efi/EFI/BOOT/grub.cfg"
set default=0
set timeout=3
set timeout_style=menu
menuentry "FluxWAN Multi-WAN Router Appliance" {
    linux /boot/vmlinuz-lts root=$ROOT_SPEC rw quiet loglevel=3 console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-lts
}
menuentry "FluxWAN (Safe Mode / Verbose)" {
    linux /boot/vmlinuz-lts root=$ROOT_SPEC rw debug verbose console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-lts
}
EOF
    mkdir -p "$MOUNT_DIR/boot/grub"
    cp -f "$MOUNT_DIR/boot/efi/EFI/BOOT/grub.cfg" "$MOUNT_DIR/boot/grub/grub.cfg"
    command -v grub-install >/dev/null 2>&1 || {
        echo -e "${RED}[!] ERROR: grub-install is missing from the live installer image.${NC}" >&2
        exit 1
    }
    grub-install --target=x86_64-efi --efi-directory="$MOUNT_DIR/boot/efi" \
        --boot-directory="$MOUNT_DIR/boot" --bootloader-id=FluxWAN --removable --no-nvram || {
        echo -e "${RED}[!] ERROR: GRUB EFI installation failed; the disk is not bootable.${NC}" >&2
        exit 1
    }
    [ -f "$MOUNT_DIR/boot/efi/EFI/BOOT/BOOTX64.EFI" ] || {
        echo -e "${RED}[!] ERROR: GRUB did not create EFI/BOOT/BOOTX64.EFI.${NC}" >&2
        exit 1
    }
    umount "$MOUNT_DIR/boot/efi"
else
    echo "    * Installing GRUB2 to MBR on $TARGET_DEV..."
    mkdir -p "$MOUNT_DIR/boot/grub"

    cat << EOF > "$MOUNT_DIR/boot/grub/grub.cfg"
set default=0
set timeout=3
set timeout_style=menu
menuentry "FluxWAN Multi-WAN Router Appliance" {
    linux /boot/vmlinuz-lts root=$ROOT_SPEC rootfstype=ext4 rw quiet loglevel=3 console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-lts
}
menuentry "FluxWAN (Safe Mode / Verbose)" {
    linux /boot/vmlinuz-lts root=$ROOT_SPEC rootfstype=ext4 rw debug verbose console=tty0 console=ttyS0,115200
    initrd /boot/initramfs-lts
}
EOF

    if command -v grub-install >/dev/null 2>&1 && \
        grub-install --target=i386-pc --recheck --boot-directory="$MOUNT_DIR/boot" "$TARGET_DEV"; then
        echo -e "    * ${GREEN}GRUB2 MBR installed successfully.${NC}"
    else
        echo -e "${YELLOW}[!] GRUB BIOS install unavailable or failed; trying Extlinux fallback.${NC}"
        mkdir -p "$MOUNT_DIR/boot/syslinux" "$MOUNT_DIR/boot/extlinux"

        # Copy all Syslinux C32 modules (ldlinux.c32, libcom32.c32, libutil.c32, mboot.c32, etc.)
        for src in /boot/syslinux /usr/share/syslinux /usr/lib/syslinux/bios /usr/lib/syslinux/mbr /media/*/boot/syslinux /media/sr0/boot/syslinux "$LIVE_BOOT_DIR/syslinux"; do
            if [ -d "$src" ]; then
                cp -f "$src"/*.c32 "$MOUNT_DIR/boot/syslinux/" 2>/dev/null || true
                cp -f "$src"/*.c32 "$MOUNT_DIR/boot/extlinux/" 2>/dev/null || true
            fi
        done

        # Explicit fallback check for ldlinux.c32
        if [ ! -f "$MOUNT_DIR/boot/syslinux/ldlinux.c32" ]; then
            for ld in /boot/syslinux/ldlinux.c32 /usr/share/syslinux/ldlinux.c32 /usr/lib/syslinux/bios/ldlinux.c32 /media/*/boot/syslinux/ldlinux.c32 /media/sr0/boot/syslinux/ldlinux.c32 "$LIVE_BOOT_DIR/syslinux/ldlinux.c32"; do
                if [ -f "$ld" ]; then
                    cp -f "$ld" "$MOUNT_DIR/boot/syslinux/ldlinux.c32" 2>/dev/null || true
                    break
                fi
            done
        fi
        cp -f "$MOUNT_DIR/boot/syslinux/ldlinux.c32" "$MOUNT_DIR/boot/extlinux/ldlinux.c32" 2>/dev/null || true
        cp -f "$MOUNT_DIR/boot/syslinux/ldlinux.c32" "$MOUNT_DIR/ldlinux.c32" 2>/dev/null || true

        CFG_CONTENT="DEFAULT fluxwan
PROMPT 0
TIMEOUT 20

LABEL fluxwan
  MENU LABEL FluxWAN Multi-WAN Router Appliance
  LINUX /boot/vmlinuz-lts
  INITRD /boot/initramfs-lts
  APPEND root=$ROOT_SPEC rootfstype=ext4 rw quiet console=tty0 console=ttyS0,115200

LABEL fluxwan-rel
  MENU LABEL FluxWAN (Relative Boot)
  LINUX vmlinuz-lts
  INITRD initramfs-lts
  APPEND root=$ROOT_SPEC rootfstype=ext4 rw quiet console=tty0 console=ttyS0,115200
"
        mkdir -p "$MOUNT_DIR/boot/syslinux" "$MOUNT_DIR/boot/extlinux"

        # Write configuration to all possible locations and filenames expected by Extlinux/Syslinux
        for cfg in \
            "$MOUNT_DIR/boot/syslinux/extlinux.conf" \
            "$MOUNT_DIR/boot/syslinux/syslinux.cfg" \
            "$MOUNT_DIR/boot/extlinux/extlinux.conf" \
            "$MOUNT_DIR/boot/extlinux/syslinux.cfg" \
            "$MOUNT_DIR/extlinux.conf" \
            "$MOUNT_DIR/syslinux.cfg" \
            "$MOUNT_DIR/boot/extlinux.conf" \
            "$MOUNT_DIR/boot/syslinux.cfg"; do
            printf "%s\n" "$CFG_CONTENT" > "$cfg"
            sed -i 's/\r$//' "$cfg" 2>/dev/null || true
        done

        # Also place kernel and initramfs links in /boot/syslinux for relative path safety
        ln -sf ../vmlinuz-lts "$MOUNT_DIR/boot/syslinux/vmlinuz-lts" 2>/dev/null || true
        ln -sf ../initramfs-lts "$MOUNT_DIR/boot/syslinux/initramfs-lts" 2>/dev/null || true
        ln -sf ../vmlinuz-lts "$MOUNT_DIR/boot/extlinux/vmlinuz-lts" 2>/dev/null || true
        ln -sf ../initramfs-lts "$MOUNT_DIR/boot/extlinux/initramfs-lts" 2>/dev/null || true

        command -v extlinux >/dev/null 2>&1 || {
            echo -e "${RED}[!] ERROR: Neither GRUB nor extlinux is available; the disk is not bootable.${NC}" >&2
            exit 1
        }
        echo -e "    * Installing Extlinux bootloader on $ROOT_PART..."
        extlinux --install "$MOUNT_DIR/boot/syslinux" || extlinux --install "$MOUNT_DIR/boot/extlinux" || extlinux --install "$MOUNT_DIR" || {
            echo -e "${RED}[!] ERROR: Extlinux installation failed; the disk is not bootable.${NC}" >&2
            exit 1
        }

        MBR_FOUND=0
        for mbr in /usr/share/syslinux/mbr.bin /usr/lib/syslinux/mbr/mbr.bin \
            /usr/lib/syslinux/bios/mbr.bin /boot/syslinux/mbr.bin \
            /media/*/boot/syslinux/mbr.bin /media/sr0/boot/syslinux/mbr.bin "$LIVE_BOOT_DIR/syslinux/mbr.bin"; do
            if [ -f "$mbr" ]; then
                echo -e "    * Writing Hard Disk MBR Boot Sector (${CYAN}$mbr${NC}) to $TARGET_DEV..."
                dd bs=440 count=1 conv=notrunc if="$mbr" of="$TARGET_DEV" status=none
                sync
                MBR_FOUND=1
                break
            fi
        done
        [ "$MBR_FOUND" -eq 1 ] || {
            echo -e "${RED}[!] ERROR: Syslinux MBR code is missing; the disk is not bootable.${NC}" >&2
            exit 1
        }
    fi
fi
# 8. Enable OpenRC Services
echo -e "${BLUE}[6/6] Finalizing installation and enabling system services...${NC}"
mkdir -p "$MOUNT_DIR/etc/runlevels/default" "$MOUNT_DIR/etc/runlevels/boot"
ln -sf /etc/init.d/fluxwan "$MOUNT_DIR/etc/runlevels/default/fluxwan" 2>/dev/null || true

sync
umount "$MOUNT_DIR" 2>/dev/null || true

echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}${BOLD} [✓] SUCCESS: FluxWAN Installed to $TARGET_DEV Successfully!         ${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "${CYAN}You can now remove the ISO/USB media and reboot into your new router.${NC}"
echo ""

if [ "$AUTO_CONFIRM" -ne 1 ]; then
    printf "Press Enter to reboot now, or 'q' to return to shell: "
    read -r REB
    if [ "$REB" != "q" ] && [ "$REB" != "Q" ]; then
        echo "[*] Rebooting..."
        reboot 2>/dev/null || true
    fi
fi