#!/bin/bash
# ==============================================================================
# FluxWAN Multi-WAN Router - EVE-NG Appliance Image Builder
# ==============================================================================
set -euo pipefail

VERSION="1.2.5"
ISO_FILE="${1:-/tmp/fluxwan-os-x86_64.iso}"
TARGET_DIR="/opt/unetlab/addons/qemu/linux-fluxwan-${VERSION}"
CUSTOM_DIR="/opt/unetlab/addons/qemu/fluxwan-${VERSION}"
DISK_NAME="virtioa.qcow2"

echo "======================================================================"
echo "      FluxWAN EVE-NG Node Appliance Builder (v${VERSION})             "
echo "======================================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root on the EVE-NG server."
    exit 1
fi

if [ ! -f "$ISO_FILE" ]; then
    echo "[!] Error: FluxWAN ISO file not found at: $ISO_FILE"
    echo "    Usage: $0 /path/to/fluxwan-os-x86_64.iso"
    exit 1
fi

echo "[1/4] Preparing image directory..."
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

echo "[2/4] Allocating sparse 2GB QCOW2 virtual disk..."
rm -f "$DISK_NAME"
qemu-img create -f qcow2 "$DISK_NAME" 2G

echo "[3/4] Launching automated non-interactive installer..."
echo "      Booting kernel and installing FluxWAN to $DISK_NAME..."

# Check KVM availability
KVM_FLAG=""
if [ -e /dev/kvm ]; then
    KVM_FLAG="-enable-kvm"
fi

# Run QEMU headless with automated disk installer
qemu-system-x86_64 $KVM_FLAG -m 1024 -smp 2 \
    -cdrom "$ISO_FILE" \
    -drive file="$DISK_NAME",format=qcow2,if=virtio \
    -boot d \
    -nographic \
    -serial mon:stdio \
    -no-reboot

# Also create symlink or copy to custom template folder if templates exist
if [ -d "/opt/unetlab/html/templates/intel" ]; then
    mkdir -p "$CUSTOM_DIR"
    cp -n "$DISK_NAME" "$CUSTOM_DIR/" 2>/dev/null || ln -sf "$TARGET_DIR/$DISK_NAME" "$CUSTOM_DIR/$DISK_NAME"
fi

echo "[4/4] Fixing EVE-NG permissions..."
if [ -x "/opt/unetlab/wrappers/unl_wrapper" ]; then
    /opt/unetlab/wrappers/unl_wrapper -a fixpermissions
fi

echo "======================================================================"
echo " [✓] SUCCESS! FluxWAN node is ready in EVE-NG."
echo "     Available under: linux-fluxwan-${VERSION} (and fluxwan-${VERSION})"
echo "======================================================================"
