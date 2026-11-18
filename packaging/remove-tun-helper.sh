#!/bin/sh
set -eu

DESTINATION=/usr/libexec/proxyctl-tun-helper
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this remover as root (for example: sudo $0)." >&2
    exit 2
fi
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
