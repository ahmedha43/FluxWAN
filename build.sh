#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Master Multi-Target Build System
# Usage:
#   ./build.sh <target>
#
# Available Targets:
#   x86_64   : Build Hybrid Bootable ISO (UEFI + BIOS) for PCs, Servers, VMs
#   rb5009   : Build FIT Image (.itb) & Netboot Bundle for MikroTik RB5009 (ARM64)
#   all      : Build all hardware targets
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-all}"

echo "======================================================================"
echo "   ⚡ FluxWAN Multi-Target Build System                               "
echo "======================================================================"

build_x86_64() {
    echo ""
    echo ">>> [TARGET: x86_64] Building Hybrid Bootable ISO..."
    docker build -f targets/x86_64/Dockerfile.builder -t fluxwan-x86-builder .
    docker run --rm -v "$SCRIPT_DIR:/workspace" -w /workspace fluxwan-x86-builder bash targets/x86_64/build.sh
    mkdir -p dist/x86_64
    cp -f dist/fluxwan-os-x86_64.iso dist/x86_64/ 2>/dev/null || true
    echo ">>> [✓] x86_64 Target Built Successfully: dist/x86_64/fluxwan-os-x86_64.iso"
}

build_rb5009() {
    echo ""
    echo ">>> [TARGET: rb5009] Building MikroTik RB5009 (ARM64) FIT Image..."
    docker build -f targets/rb5009/Dockerfile.builder -t fluxwan-rb5009-builder .
    docker run --rm -v "$SCRIPT_DIR:/workspace" -w /workspace fluxwan-rb5009-builder bash targets/rb5009/build.sh
    mkdir -p dist/rb5009
    cp -f dist/fluxwan-rb5009.itb dist/rb5009/ 2>/dev/null || true
    cp -f dist/fluxwan-rb5009-netboot.tar.gz dist/rb5009/ 2>/dev/null || true
    cp -f targets/rb5009/netboot/FluxWAN-Windows-Flasher.bat dist/rb5009/ 2>/dev/null || true
    echo ">>> [✓] RB5009 Target Built Successfully: dist/rb5009/fluxwan-rb5009.itb"
}

case "$TARGET" in
    x86_64|x86)
        build_x86_64
        ;;
    rb5009|arm64)
        build_rb5009
        ;;
    all)
        build_x86_64
        build_rb5009
        ;;
    *)
        echo "[!] Unknown target: $TARGET"
        echo "    Available targets: x86_64, rb5009, all"
        exit 1
        ;;
esac

echo ""
echo "======================================================================"
echo " [✓] ALL REQUESTED TARGETS BUILT SUCCESSFULLY!"
echo "     Artifacts saved in: $SCRIPT_DIR/dist/"
echo "======================================================================"