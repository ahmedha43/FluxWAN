#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Embedded Linux Network Appliance - Hybrid Bootable ISO Builder
# Target: dist/fluxwan-os-x86_64.iso (Hybrid Bootable ISO - UEFI + BIOS)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
BUILD_DIR="${BUILD_DIR:-/var/tmp/fluxwan_iso_build}"
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
python3 scripts/embed_ui.py || true
make fluxwan
strip --strip-all "$PROJECT_ROOT/fluxwan" 2>/dev/null || true
if [ -f "$PROJECT_ROOT/fluxwan_lab" ]; then
    strip --strip-all "$PROJECT_ROOT/fluxwan_lab" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 2. Extract Kernel & Minimal Hardware Modules
# ------------------------------------------------------------------------------
if [ ! -f "$ALPINE_STD_ISO" ]; then
    if [ -f "/root/alpine-standard-base.iso" ]; then
        echo "    * Using cached Alpine Base ISO from /root/alpine-standard-base.iso..."
        cp -f "/root/alpine-standard-base.iso" "$ALPINE_STD_ISO"
    elif [ -f "$PROJECT_ROOT/dist/alpine-standard-base.iso" ]; then
        cp -f "$PROJECT_ROOT/dist/alpine-standard-base.iso" "$ALPINE_STD_ISO"
    else
        echo "    * Fetching Alpine Linux 3.19 Base ISO..."
        mkdir -p "$DIST_DIR"
        curl -sSL "https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/alpine-standard-3.19.1-x86_64.iso" -o "$ALPINE_STD_ISO"
    fi
fi

mkdir -p "$BUILD_DIR/iso_extract"
xorriso -osirrox on -indev "$ALPINE_STD_ISO" -extract / "$BUILD_DIR/iso_extract" >/dev/null 2>&1

mkdir -p "$BUILD_DIR/modloop_unpacked"
unsquashfs -d "$BUILD_DIR/modloop_unpacked" "$BUILD_DIR/iso_extract/boot/modloop-lts" >/dev/null 2>&1 || true

# Filter kernel modules: Keep Network, Storage, CDROM, Netfilter, Crypto, VirtIO, Filesystems
# Note: Alpine Linux init mounts modloop-lts to /.modloop and creates symlink /.modloop/modules -> /lib/modules.
# Therefore, modloop-lts MUST have top-level directory "modules/$kver/..."
mkdir -p "$BUILD_DIR/filtered_modules/modules"
for kdir in "$BUILD_DIR/modloop_unpacked/modules/"*; do
    if [ -d "$kdir" ]; then
        kver="$(basename "$kdir")"
        K_DEST="$BUILD_DIR/filtered_modules/modules/$kver"
        mkdir -p "$K_DEST/kernel/drivers"
        mkdir -p "$K_DEST/kernel/net"
        mkdir -p "$K_DEST/kernel/crypto"
        mkdir -p "$K_DEST/kernel/fs"
        mkdir -p "$K_DEST/kernel/lib"

        # Network Drivers (Intel, Realtek, Broadcom, Mellanox, VirtIO, VMXNET3)
        [ -d "$kdir/kernel/drivers/net" ] && cp -a "$kdir/kernel/drivers/net" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        # Storage & CDROM Drivers (NVMe, SATA, AHCI, SCSI, CD-ROM, Block, VirtIO-blk, USB-Storage)
        [ -d "$kdir/kernel/drivers/nvme" ] && cp -a "$kdir/kernel/drivers/nvme" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/ata" ] && cp -a "$kdir/kernel/drivers/ata" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/scsi" ] && cp -a "$kdir/kernel/drivers/scsi" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/cdrom" ] && cp -a "$kdir/kernel/drivers/cdrom" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/block" ] && cp -a "$kdir/kernel/drivers/block" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        [ -d "$kdir/kernel/drivers/virtio" ] && cp -a "$kdir/kernel/drivers/virtio" "$K_DEST/kernel/drivers/" 2>/dev/null || true
        if [ -d "$kdir/kernel/drivers/usb" ]; then
            mkdir -p "$K_DEST/kernel/drivers/usb"
            cp -a "$kdir/kernel/drivers/usb/storage" "$K_DEST/kernel/drivers/usb/" 2>/dev/null || true
            cp -a "$kdir/kernel/drivers/usb/host" "$K_DEST/kernel/drivers/usb/" 2>/dev/null || true
            cp -a "$kdir/kernel/drivers/usb/core" "$K_DEST/kernel/drivers/usb/" 2>/dev/null || true
        fi
        # Netfilter, Routing, eBPF Subsystems (includes packet / AF_PACKET)
        [ -d "$kdir/kernel/net" ] && cp -a "$kdir/kernel/net" "$K_DEST/kernel/" 2>/dev/null || true
        # Crypto & Checksum Libraries (crc32c, sha, aes, etc.)
        [ -d "$kdir/kernel/crypto" ] && cp -a "$kdir/kernel/crypto" "$K_DEST/kernel/" 2>/dev/null || true
        # Essential Kernel Helper Libraries (crc16, zlib, etc.)
        [ -d "$kdir/kernel/lib" ] && cp -a "$kdir/kernel/lib" "$K_DEST/kernel/" 2>/dev/null || true
        # Complete Filesystem Modules (ext4, jbd2, mbcache, vfat, fat, nls, isofs, squashfs)
        [ -d "$kdir/kernel/fs" ] && cp -a "$kdir/kernel/fs" "$K_DEST/kernel/" 2>/dev/null || true

        # Remove irrelevant bluetooth/SAN modules to keep image compact (preserve WiFi / wireless drivers)
        rm -rf "$K_DEST/kernel/net/bluetooth" \
               "$K_DEST/kernel/drivers/scsi/qla2xxx" \
               "$K_DEST/kernel/drivers/scsi/lpfc" 2>/dev/null || true

        # Copy original modules.* metadata files from Alpine kernel (modules.builtin, modules.order, etc.)
        cp -a "$kdir"/modules.* "$K_DEST/" 2>/dev/null || true
        # Re-generate module dependencies with depmod (depmod -b DIR expects DIR/lib/modules/$kver)
        mkdir -p "$BUILD_DIR/depmod_root/lib/modules"
        rm -rf "$BUILD_DIR/depmod_root/lib/modules/$kver"
        cp -a "$K_DEST" "$BUILD_DIR/depmod_root/lib/modules/$kver"
        depmod -b "$BUILD_DIR/depmod_root" "$kver" 2>/dev/null || true
        if [ -s "$BUILD_DIR/depmod_root/lib/modules/$kver/modules.dep" ]; then
            cp -a "$BUILD_DIR/depmod_root/lib/modules/$kver"/modules.* "$K_DEST/" 2>/dev/null || true
        fi
        # Also create backwards-compatible link at root of modloop
        ln -sf modules/"$kver" "$BUILD_DIR/filtered_modules/$kver" 2>/dev/null || true
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
dropbear
dropbear-ssh
ppp
ppp-daemon
ppp-pppoe
rp-pppoe
wpa_supplicant
iw
wireless-regdb
EOF

# Copy FluxWAN binaries, BPF objects, configs and scripts into apkovl
cp -f "$PROJECT_ROOT/fluxwan" "$APKOVL_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$APKOVL_DIR/opt/fluxwan/config/"
echo "1.4.0" > "$APKOVL_DIR/opt/fluxwan/version"
mkdir -p "$APKOVL_DIR/root/config" "$APKOVL_DIR/config"
ln -sf /opt/fluxwan/config/fluxwan.json "$APKOVL_DIR/root/config/fluxwan.json" 2>/dev/null || true
ln -sf /opt/fluxwan/config/fluxwan.json "$APKOVL_DIR/config/fluxwan.json" 2>/dev/null || true
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

mkdir -p "$APKOVL_DIR/usr/sbin" "$APKOVL_DIR/sbin" "$APKOVL_DIR/usr/lib" "$APKOVL_DIR/lib" "$BUILD_DIR/iso_extract/apks/x86_64"

# Check if running in an Alpine environment with musl libc
IS_ALPINE=0
if [ -f /etc/alpine-release ]; then
    IS_ALPINE=1
fi

CACHE_X86="$PROJECT_ROOT/.cache/x86_64"
mkdir -p "$CACHE_X86"
ALPINE_MIRROR_MAIN="https://dl-cdn.alpinelinux.org/alpine/v3.19/main/x86_64"

fetch_and_unpack_apk() {
    local apk_name="$1"
    local dest="$2"
    if [ ! -s "$CACHE_X86/$apk_name" ]; then
        echo "    * Downloading Alpine package: $apk_name..."
        curl -fL --retry 3 -sS "$ALPINE_MIRROR_MAIN/$apk_name" -o "$CACHE_X86/$apk_name" || true
    fi
    if [ -s "$CACHE_X86/$apk_name" ]; then
        tar -xzf "$CACHE_X86/$apk_name" -C "$dest" 2>/dev/null || true
        cp -f "$CACHE_X86/$apk_name" "$BUILD_DIR/iso_extract/apks/x86_64/" 2>/dev/null || true
    fi
}

if [ "$IS_ALPINE" -eq 1 ]; then
    echo "    * Alpine builder environment detected. Copying native Musl bootloader toolchain..."
    if [ -d /usr/share/syslinux ]; then
        cp -a /usr/share/syslinux/. "$APKOVL_DIR/usr/share/syslinux/" 2>/dev/null || true
    fi

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

    EXTLINUX_BIN=$(command -v extlinux 2>/dev/null || true)
    [ -n "$EXTLINUX_BIN" ] && cp -f "$EXTLINUX_BIN" "$APKOVL_DIR/sbin/extlinux"

    # Embed runtime libraries needed by grub-install on Alpine Musl
    cp -aL /usr/lib/liblzma.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /lib/libdevmapper.so* "$APKOVL_DIR/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libdevmapper.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /lib/libblkid.so* "$APKOVL_DIR/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libblkid.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true

    # Embed networking utilities
    for bin in iptables iptables-save iptables-restore ip conntrack ethtool curl dropbear wpa_supplicant wpa_cli iw rfkill pppd pppoe pppoe-server pppoe-relay; do
        SRC=$(command -v "$bin" 2>/dev/null || true)
        if [ -n "$SRC" ]; then
            cp -f "$SRC" "$APKOVL_DIR/usr/sbin/$bin" 2>/dev/null || true
            cp -f "$SRC" "$APKOVL_DIR/sbin/$bin" 2>/dev/null || true
        fi
    done
    for bin in dropbearkey dropbearconvert dbclient; do
        SRC=$(command -v "$bin" 2>/dev/null || true)
        if [ -n "$SRC" ]; then
            cp -f "$SRC" "$APKOVL_DIR/usr/bin/$bin" 2>/dev/null || true
            cp -f "$SRC" "$APKOVL_DIR/bin/$bin" 2>/dev/null || true
        fi
    done
    cp -aL /usr/lib/libxtables.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libmnl.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libnftnl.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libnetfilter_conntrack.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libnfnetlink.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libelf.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libzstd.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /usr/lib/libcrypt.so* "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
    cp -aL /lib/libcrypt.so* "$APKOVL_DIR/lib/" 2>/dev/null || true
    cp -aL /usr/lib/pppd "$APKOVL_DIR/usr/lib/" 2>/dev/null || true
else
    echo "    * Non-Alpine builder detected! Fetching official Alpine 3.19 Musl bootloader packages..."
    # Pure Alpine packages to prevent copying Ubuntu glibc binaries
    fetch_and_unpack_apk "grub-2.06-r17.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "grub-bios-2.06-r17.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "grub-efi-2.06-r17.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "syslinux-6.04_pre1-r15.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "xz-libs-5.4.5-r1.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "device-mapper-libs-2.03.23-r0.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "libblkid-2.39.3-r0.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "dropbear-2022.83-r4.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "dropbear-ssh-2022.83-r4.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "iptables-1.8.10-r3.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "ethtool-6.6-r0.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "ppp-2.5.0-r5.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "ppp-daemon-2.5.0-r5.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "ppp-pppoe-2.5.0-r5.apk" "$APKOVL_DIR"
    fetch_and_unpack_apk "rp-pppoe-4.0-r1.apk" "$APKOVL_DIR"
fi

# Ensure syslinux, grub and ppp offline packages are in ISO APK repository regardless
fetch_and_unpack_apk "grub-2.06-r17.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "grub-bios-2.06-r17.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "grub-efi-2.06-r17.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "syslinux-6.04_pre1-r15.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "ppp-2.5.0-r5.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "ppp-daemon-2.5.0-r5.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "ppp-pppoe-2.5.0-r5.apk" "$BUILD_DIR/iso_extract"
fetch_and_unpack_apk "rp-pppoe-4.0-r1.apk" "$BUILD_DIR/iso_extract"

# Fetch and embed ZeroTier One into rootfs and offline ISO repo
if [ ! -s "$CACHE_X86/zerotier-one-1.10.2-r0.apk" ]; then
    echo "    * Downloading ZeroTier package: zerotier-one-1.10.2-r0.apk..."
    curl -fL --retry 3 -sS "http://dl-cdn.alpinelinux.org/alpine/v3.17/community/x86_64/zerotier-one-1.10.2-r0.apk" -o "$CACHE_X86/zerotier-one-1.10.2-r0.apk" || true
fi
if [ -s "$CACHE_X86/zerotier-one-1.10.2-r0.apk" ]; then
    tar -xzf "$CACHE_X86/zerotier-one-1.10.2-r0.apk" -C "$APKOVL_DIR" 2>/dev/null || true
    cp -f "$CACHE_X86/zerotier-one-1.10.2-r0.apk" "$BUILD_DIR/iso_extract/apks/x86_64/" 2>/dev/null || true
fi

# Embed Standalone Proxy Engines (Sing-box, Xray, V2Ray) for Zero-Rating Multi-WAN
echo "    * Embedding Standalone Proxy Tunneling engines (Sing-box, Xray, V2Ray)..."
mkdir -p "$APKOVL_DIR/usr/bin" "$APKOVL_DIR/usr/local/bin"
for pbin in sing-box xray v2ray; do
    PB_SRC=""
    for cand in "/usr/local/bin/$pbin" "/usr/bin/$pbin" "/bin/$pbin" "$PROJECT_ROOT/$pbin" "$PROJECT_ROOT/dist/$pbin"; do
        if [ -x "$cand" ] && [ -s "$cand" ]; then
            PB_SRC="$cand"
            break
        fi
    done
    if [ -z "$PB_SRC" ]; then
        PB_SRC=$(command -v "$pbin" 2>/dev/null || true)
    fi
    if [ -n "$PB_SRC" ] && [ -x "$PB_SRC" ]; then
        if [ -L "$PB_SRC" ]; then
            PB_SRC=$(readlink -f "$PB_SRC" 2>/dev/null || realpath "$PB_SRC" 2>/dev/null || echo "$PB_SRC")
        fi
        cp -aL "$PB_SRC" "$APKOVL_DIR/usr/bin/$pbin" 2>/dev/null || true
        cp -aL "$PB_SRC" "$APKOVL_DIR/usr/local/bin/$pbin" 2>/dev/null || true
        chmod +x "$APKOVL_DIR/usr/bin/$pbin" "$APKOVL_DIR/usr/local/bin/$pbin" 2>/dev/null || true
        echo "      -> Embedded proxy engine: $pbin ($PB_SRC)"
    fi
done

chmod +x "$APKOVL_DIR/usr/sbin/"* "$APKOVL_DIR/sbin/"* "$APKOVL_DIR/usr/bin/"* "$APKOVL_DIR/bin/"* 2>/dev/null || true

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

# Also include rcS and rcK for Busybox init (no openrc dependency)
cp -f "$PROJECT_ROOT/appliance/etc/init.d/rcS" "$APKOVL_DIR/etc/init.d/rcS" 2>/dev/null || true
cp -f "$PROJECT_ROOT/appliance/etc/init.d/rcK" "$APKOVL_DIR/etc/init.d/rcK" 2>/dev/null || true
chmod +x "$APKOVL_DIR/etc/init.d/rcS" "$APKOVL_DIR/etc/init.d/rcK" 2>/dev/null || true

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
mkdir -p "$ISO_DIR/opt/fluxwan/boot"
cp -f "$PROJECT_ROOT/fluxwan" "$ISO_DIR/opt/fluxwan/"
cp -f "$PROJECT_ROOT/config/fluxwan.json" "$ISO_DIR/opt/fluxwan/config.json"
cp -f "$DIST_DIR/fluxwan-rootfs.tar.gz" "$ISO_DIR/opt/fluxwan/"
cp -f "$ISO_DIR/boot/vmlinuz-lts" "$ISO_DIR/opt/fluxwan/boot/" 2>/dev/null || true
cp -f "$ISO_DIR/boot/initramfs-lts" "$ISO_DIR/opt/fluxwan/boot/" 2>/dev/null || true
cp -f "$ISO_DIR/boot/modloop-lts" "$ISO_DIR/opt/fluxwan/boot/" 2>/dev/null || true

# Direct injection into initramfs-lts (guarantees /usr/local/bin/fluxwan-menu exists immediately on boot)
echo "[+] Embedding FluxWAN control console and filesystem drivers into initramfs-lts..."
mkdir -p "$BUILD_DIR/initramfs_unpacked"
(cd "$BUILD_DIR/initramfs_unpacked" && zcat "$ISO_DIR/boot/initramfs-lts" | cpio -idmu >/dev/null 2>&1 || true)
cp -a "$APKOVL_DIR/." "$BUILD_DIR/initramfs_unpacked/"
mkdir -p "$BUILD_DIR/initramfs_unpacked/usr/bin" "$BUILD_DIR/initramfs_unpacked/bin" "$BUILD_DIR/initramfs_unpacked/usr/local/bin"
cp -f "$APKOVL_DIR/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/usr/local/bin/" 2>/dev/null || true
cp -f "$APKOVL_DIR/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/usr/bin/" 2>/dev/null || true
cp -f "$APKOVL_DIR/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/bin/" 2>/dev/null || true
chmod +x "$BUILD_DIR/initramfs_unpacked/usr/local/bin/"* "$BUILD_DIR/initramfs_unpacked/usr/bin/"* "$BUILD_DIR/initramfs_unpacked/bin/"* 2>/dev/null || true

# Embed kernel filesystem modules (ext4, jbd2, mbcache, crc16, vfat, fat) directly into initramfs
mkdir -p "$BUILD_DIR/initramfs_unpacked/lib/modules"
cp -a "$BUILD_DIR/filtered_modules/modules/." "$BUILD_DIR/initramfs_unpacked/lib/modules/" 2>/dev/null || true
for kdir in "$BUILD_DIR/initramfs_unpacked/lib/modules/"*; do
    if [ -d "$kdir" ]; then
        depmod -b "$BUILD_DIR/initramfs_unpacked" "$(basename "$kdir")" 2>/dev/null || true
    fi
done

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
  APPEND modules=loop,squashfs,sd-mod,usb-storage,sr-mod,cdrom,isofs,ext4 console=ttyS0,115200 console=tty0
EOF

# Ensure isolinux.cfg also points to the same configuration
cp -f "$ISO_DIR/boot/syslinux/syslinux.cfg" "$ISO_DIR/boot/syslinux/isolinux.cfg"

# Configure GRUB boot (UEFI)
cat <<'EOF' > "$ISO_DIR/boot/grub/grub.cfg"
set timeout=2
set default=0

menuentry "FluxWAN Embedded Network Appliance" {
    linux /boot/vmlinuz-lts modules=loop,squashfs,sd-mod,usb-storage,sr-mod,cdrom,isofs,ext4 console=ttyS0,115200 console=tty0
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
