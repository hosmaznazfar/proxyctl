#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this remover as root (for example: sudo $0)." >&2
    exit 2
fi
if [ -L /usr/libexec ] || [ ! -d /usr/libexec ]; then
    echo "/usr/libexec must be an existing real directory." >&2
    exit 1
fi
LIBEXEC_OWNER=$(stat -c '%u:%g' /usr/libexec)
LIBEXEC_MODE=$(stat -c '%a' /usr/libexec)
if [ "$LIBEXEC_OWNER" != "0:0" ]; then
    echo "/usr/libexec must be owned by root:root." >&2
    exit 1
fi
case "$LIBEXEC_MODE" in
    *[2367][0-7]|*[0-7][2367])
        echo "/usr/libexec must not be group- or world-writable." >&2
        exit 1
        ;;
esac

validate_owned_file() {
    destination=$1
    if [ -L "$destination" ]; then
        echo "Refusing to remove a symlink at $destination." >&2
        return 1
    fi
    if [ ! -e "$destination" ]; then
        return 0
    fi
    if [ ! -f "$destination" ]; then
        echo "Refusing to remove a non-regular file: $destination" >&2
        return 1
    fi
    owner=$(stat -c '%u:%g' "$destination")
    if [ "$owner" != "0:0" ]; then
        echo "Refusing to remove a file not owned by root:root: $destination" >&2
        return 1
    fi
}

# Validate the entire bundle before deleting any member, so an unexpected path
# cannot cause a partially completed uninstall.
validate_owned_file /usr/libexec/proxyctl-tun-helper
validate_owned_file /usr/libexec/proxyctl-tun-core-launcher
validate_owned_file /usr/libexec/proxyctl-tun-supervisor

remove_owned_file() {
    destination=$1
    if [ ! -e "$destination" ]; then
        echo "Not installed: $destination"
        return 0
    fi
    if [ "$destination" = "/usr/libexec/proxyctl-tun-helper" ] && command -v setcap >/dev/null 2>&1; then
        setcap -r "$destination" 2>/dev/null || true
    fi
    rm -f -- "$destination"
    echo "Removed $destination"
}

remove_owned_file /usr/libexec/proxyctl-tun-helper
remove_owned_file /usr/libexec/proxyctl-tun-core-launcher
remove_owned_file /usr/libexec/proxyctl-tun-supervisor
