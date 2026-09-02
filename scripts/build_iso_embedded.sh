#!/usr/bin/env bash
# ==============================================================================
# FluxWAN Embedded Linux Network Appliance - Hybrid Bootable ISO Builder
# Target: dist/fluxwan-os-x86_64.iso (Hybrid Bootable ISO - UEFI + BIOS)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

exec bash "$PROJECT_ROOT/targets/x86_64/build.sh" "$@"
