#!/bin/sh
# Verify Linux removes routes bound to a TUN device on NETDEV_UNREGISTER while
# preserving unrelated routes in the same private table and elsewhere.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "run this integration test as root (it creates a temporary network namespace)" >&2
    exit 77
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 is required" >&2
    exit 77
fi

namespace="proxyctl-cleanup-$$"
cleanup() {
    ip netns del "$namespace" >/dev/null 2>&1 || true
}
trap cleanup 0 HUP INT TERM

ip netns add "$namespace"
ip -n "$namespace" tuntap add dev pctltest0 mode tun
ip -n "$namespace" link set dev pctltest0 up

# The two default routes represent the resources Proxyctl owns through the TUN link.
ip -n "$namespace" -4 route add default dev pctltest0 table 42420 proto 99
ip -n "$namespace" -6 route add default dev pctltest0 table 42420 proto 99

# Foreign routes deliberately share the private table but use another device.
ip -n "$namespace" -4 route add 198.51.100.0/24 dev lo table 42420 proto static
ip -n "$namespace" -6 route add 2001:db8:4242::/48 dev lo table 42420 proto static

# Match the exact protocol-tagged policy-rule shape used by the TUN backend.
ip -n "$namespace" -4 rule add pref 42420 table 42420 protocol 99
ip -n "$namespace" -6 rule add pref 42420 table 42420 protocol 99

ip -n "$namespace" -4 route show table 42420 | grep -q '^default'
ip -n "$namespace" -6 route show table 42420 | grep -q '^default'
ip -n "$namespace" -4 rule show | grep -q '42420.*99'
ip -n "$namespace" -6 rule show | grep -q '42420.*99'

# Rules are removed by their typed selectors; routes are removed by link teardown.
ip -n "$namespace" -4 rule del pref 42420 table 42420 protocol 99
ip -n "$namespace" -6 rule del pref 42420 table 42420 protocol 99
ip -n "$namespace" link del dev pctltest0

if ip -n "$namespace" -4 route show table 42420 | grep -q '^default'; then
    echo "IPv4 TUN route survived interface unregister" >&2
    exit 1
fi
if ip -n "$namespace" -6 route show table 42420 | grep -q '^default'; then
    echo "IPv6 TUN route survived interface unregister" >&2
    exit 1
fi
ip -n "$namespace" -4 route show table 42420 | grep -q '198.51.100.0/24'
ip -n "$namespace" -6 route show table 42420 | grep -q '2001:db8:4242::/48'

echo "TUN link teardown removed only the IPv4/IPv6 routes bound to that link"
