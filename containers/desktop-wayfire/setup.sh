#!/bin/bash
# Host setup for the desktop-wayfire workload.
#
# Usage:
#   setup.sh enable   — install SELinux policy module
#   setup.sh disable  — remove SELinux policy module
#
# Idempotent in both directions. Called by workloadctl enable/disable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_NAME="desktop-wayfire"
MODULES_LOAD_CONF="/etc/modules-load.d/vkms.conf"
UDEV_RULE="/etc/udev/rules.d/70-vkms.rules"

enable() {
    echo "  [host] Configuring vkms kernel module..."
    echo "vkms" > "$MODULES_LOAD_CONF"
    cat > "$UDEV_RULE" <<'RULES'
SUBSYSTEM=="drm", DEVPATH=="*/platform/vkms/*", KERNEL=="card*",    SYMLINK+="dri/vkms"
SUBSYSTEM=="drm", DEVPATH=="*/platform/vkms/*", KERNEL=="renderD*", SYMLINK+="dri/vkms-render"
RULES
    udevadm control --reload-rules
    modprobe vkms
    udevadm trigger --subsystem-match=drm --settle
    if [ ! -e /dev/dri/vkms ] || [ ! -e /dev/dri/vkms-render ]; then
        echo "  ERROR: /dev/dri/vkms symlinks not created after udev settle" >&2
        return 1
    fi
    echo "  [host] vkms ready: /dev/dri/vkms, /dev/dri/vkms-render"

    echo "  [host] Installing SELinux policy module..."
    TE_FILE="${SCRIPT_DIR}/${MODULE_NAME}.te"
    if [ ! -f "$TE_FILE" ]; then
        echo "  ERROR: SELinux policy source not found: $TE_FILE" >&2
        return 1
    fi
    WORK_DIR=$(mktemp -d)
    trap 'rm -rf "$WORK_DIR"' EXIT
    cp "$TE_FILE" "$WORK_DIR/"
    checkmodule -M -m -o "$WORK_DIR/${MODULE_NAME}.mod" "$WORK_DIR/${MODULE_NAME}.te"
    semodule_package -o "$WORK_DIR/${MODULE_NAME}.pp" -m "$WORK_DIR/${MODULE_NAME}.mod"
    semodule -i "$WORK_DIR/${MODULE_NAME}.pp"

    echo "  [host] Host setup complete"
}

disable() {
    echo "  [host] Removing SELinux policy module..."
    if semodule -l 2>/dev/null | grep -q "^${MODULE_NAME}"; then
        semodule -r "$MODULE_NAME"
    else
        echo "  [host] SELinux module '${MODULE_NAME}' not installed"
    fi
    echo "  [host] Host teardown complete"
}

case "${1:-}" in
    enable)  enable ;;
    disable) disable ;;
    *)
        echo "Usage: $0 {enable|disable}" >&2
        exit 1
        ;;
esac
