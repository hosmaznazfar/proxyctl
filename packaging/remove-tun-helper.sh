#!/bin/sh
set -eu

DESTINATION=/usr/libexec/proxyctl-tun-helper
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
if [ -L "$DESTINATION" ]; then
    echo "Refusing to remove a symlink at $DESTINATION." >&2
    exit 1
fi
if [ -e "$DESTINATION" ]; then
    if [ ! -f "$DESTINATION" ]; then
        echo "Refusing to remove a non-regular helper path: $DESTINATION" >&2
        exit 1
    fi
    OWNER=$(stat -c '%u:%g' "$DESTINATION")
    if [ "$OWNER" != "0:0" ]; then
        echo "Refusing to remove a helper not owned by root:root." >&2
        exit 1
    fi
    if command -v setcap >/dev/null 2>&1; then
        setcap -r "$DESTINATION" 2>/dev/null || true
    fi
    rm -f -- "$DESTINATION"
    echo "Removed $DESTINATION and its file capabilities."
else
    echo "Helper is not installed."
fi
