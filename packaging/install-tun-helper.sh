#!/bin/sh
set -eu

SOURCE=${1:-target/release/proxyctl-tun-helper}
DESTINATION=/usr/libexec/proxyctl-tun-helper
CORE_LAUNCHER_SOURCE=${3:-target/release/proxyctl-tun-core-launcher}
CORE_LAUNCHER_DESTINATION=/usr/libexec/proxyctl-tun-core-launcher
SUPERVISOR_SOURCE=${4:-target/release/proxyctl-tun-supervisor}
SUPERVISOR_DESTINATION=/usr/libexec/proxyctl-tun-supervisor

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (for example: sudo $0 [built-helper-path] [proxyctl-binary] [core-launcher-path] [supervisor-path])." >&2
    exit 2
fi
if [ ! -f "$SOURCE" ] || [ ! -x "$SOURCE" ] || [ -L "$SOURCE" ]; then
    echo "Built helper must be a regular, non-symlink executable: $SOURCE" >&2
    exit 2
fi
if [ ! -f "$CORE_LAUNCHER_SOURCE" ] || [ ! -x "$CORE_LAUNCHER_SOURCE" ] || [ -L "$CORE_LAUNCHER_SOURCE" ]; then
    echo "Built core launcher must be a regular, non-symlink executable: $CORE_LAUNCHER_SOURCE" >&2
    exit 2
fi
if [ ! -f "$SUPERVISOR_SOURCE" ] || [ ! -x "$SUPERVISOR_SOURCE" ] || [ -L "$SUPERVISOR_SOURCE" ]; then
    echo "Built recovery supervisor must be a regular, non-symlink executable: $SUPERVISOR_SOURCE" >&2
    exit 2
fi
# Create the standard system executable directory when the host does not
# provide it. Never follow or replace a pre-existing symlink.
if [ ! -e /usr/libexec ] && [ ! -L /usr/libexec ]; then
    install -d -o root -g root -m 0755 /usr/libexec
fi
if [ -L /usr/libexec ] || [ ! -d /usr/libexec ]; then
    echo "/usr/libexec must be a real directory (not a symlink)." >&2
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
if [ -L "$DESTINATION" ] || [ -L "$CORE_LAUNCHER_DESTINATION" ] || [ -L "$SUPERVISOR_DESTINATION" ]; then
    echo "Refusing to replace a symlink in /usr/libexec." >&2
    exit 1
fi
if ! command -v setcap >/dev/null 2>&1 || ! command -v getcap >/dev/null 2>&1; then
    echo "libcap tools (setcap/getcap) are required; no fallback to setuid is allowed." >&2
    exit 2
fi

MAIN_BINARY=${2:-target/release/proxyctl}
if [ -e "$MAIN_BINARY" ]; then
    MAIN_CAPABILITIES=$(getcap "$MAIN_BINARY")
    if [ -n "$MAIN_CAPABILITIES" ]; then
        echo "The ordinary Proxyctl executable has file capabilities; refusing helper installation: $MAIN_CAPABILITIES" >&2
        exit 1
    fi
fi

STAGING=$(mktemp /usr/libexec/.proxyctl-tun-helper.XXXXXX)
CORE_LAUNCHER_STAGING=$(mktemp /usr/libexec/.proxyctl-tun-core-launcher.XXXXXX)
SUPERVISOR_STAGING=$(mktemp /usr/libexec/.proxyctl-tun-supervisor.XXXXXX)
cleanup_staging() {
    if [ -n "${STAGING:-}" ] && [ -e "$STAGING" ]; then
        setcap -r "$STAGING" 2>/dev/null || true
        rm -f -- "$STAGING"
    fi
    if [ -n "${CORE_LAUNCHER_STAGING:-}" ] && [ -e "$CORE_LAUNCHER_STAGING" ]; then
        setcap -r "$CORE_LAUNCHER_STAGING" 2>/dev/null || true
        rm -f -- "$CORE_LAUNCHER_STAGING"
    fi
    if [ -n "${SUPERVISOR_STAGING:-}" ] && [ -e "$SUPERVISOR_STAGING" ]; then
        setcap -r "$SUPERVISOR_STAGING" 2>/dev/null || true
        rm -f -- "$SUPERVISOR_STAGING"
    fi
}
trap cleanup_staging EXIT
trap 'exit 1' HUP INT TERM

install -o root -g root -m 0755 "$SOURCE" "$STAGING"
if ! setcap cap_net_admin=ep "$STAGING"; then
    echo "Could not apply the required file capability; existing helper was left untouched." >&2
    exit 1
fi
install -o root -g root -m 0755 "$CORE_LAUNCHER_SOURCE" "$CORE_LAUNCHER_STAGING"
if [ -n "$(getcap "$CORE_LAUNCHER_STAGING")" ]; then
    echo "Core launcher must not have file capabilities." >&2
    exit 1
fi
install -o root -g root -m 0755 "$SUPERVISOR_SOURCE" "$SUPERVISOR_STAGING"
if [ -n "$(getcap "$SUPERVISOR_STAGING")" ]; then
    echo "Recovery supervisor must not have file capabilities." >&2
    exit 1
fi
ACTUAL=$(getcap "$STAGING")
case "$ACTUAL" in
    "$STAGING cap_net_admin=ep") ;;
    *)
        echo "Unexpected staged helper file capabilities: $ACTUAL; existing helper was left untouched." >&2
        exit 1
        ;;
esac

# Staging is in the destination directory, so rename is atomic and the previous
# working helper remains in place until the replacement is fully prepared.
mv -f -- "$STAGING" "$DESTINATION"
STAGING=
mv -f -- "$CORE_LAUNCHER_STAGING" "$CORE_LAUNCHER_DESTINATION"
CORE_LAUNCHER_STAGING=
mv -f -- "$SUPERVISOR_STAGING" "$SUPERVISOR_DESTINATION"
SUPERVISOR_STAGING=
trap - EXIT HUP INT TERM

echo "Installed $DESTINATION with only cap_net_admin=ep."
echo "Installed $CORE_LAUNCHER_DESTINATION without file capabilities; the Xray service and core run with an empty capability set."
echo "Installed $SUPERVISOR_DESTINATION without file capabilities."
echo "The helper supports the read-only --socket mode and persistent typed --mutation-socket mode."
echo "Start the mutation mode explicitly with: /usr/libexec/proxyctl-tun-helper --mutation-socket PATH"
echo "No setuid bit, service, sudoers rule, or automatic startup was installed."
