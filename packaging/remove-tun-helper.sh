#!/bin/sh
set -eu

DESTINATION=/usr/libexec/proxyctl-tun-helper
if [ "$(id -u)" -ne 0 ]; then
    echo "Run this remover as root (for example: sudo $0)." >&2
    exit 2
fi
if [ -e "$DESTINATION" ]; then
    if command -v setcap >/dev/null 2>&1; then
        setcap -r "$DESTINATION" 2>/dev/null || true
    fi
    rm -f -- "$DESTINATION"
    echo "Removed $DESTINATION and its file capabilities."
else
    echo "Helper is not installed."
fi
