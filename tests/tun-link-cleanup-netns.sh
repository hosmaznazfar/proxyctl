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
trap cleanup 0
trap 'cleanup; exit 1' HUP INT TERM

ip netns add "$namespace"
ip -n "$namespace" link set dev lo up
ip -n "$namespace" tuntap add dev pctltest0 mode tun
ip -n "$namespace" link set dev pctltest0 up

# The two default routes represent the resources Proxyctl owns through the TUN link.
ip -n "$namespace" -4 route add default dev pctltest0 table 42420 proto 99
ip -n "$namespace" -6 route add default dev pctltest0 table 42420 proto 99

# A foreign multipath route deliberately references both the TUN and loopback.
# Linux may flush the entire fib_info when the TUN nexthop is unregistered, even
# though the other nexthop is still usable. This records that cross-manager side effect.
multipath_route_added=0
if ip -n "$namespace" -4 route add 203.0.113.0/24 table 42420 proto static nexthop dev pctltest0 weight 1 nexthop dev lo weight 1 2>/dev/null; then
    multipath_route_added=1
fi
# Foreign routes deliberately share the private table but use another device.
ip -n "$namespace" -4 route add 198.51.100.0/24 dev lo table 42420 proto static
ip -n "$namespace" -6 route add 2001:db8:4242::/48 dev lo table 42420 proto static

# Match the exact protocol-tagged policy-rule shape used by the TUN backend.
ip -n "$namespace" -4 rule add pref 42420 table 42420 protocol 99
ip -n "$namespace" -6 rule add pref 42420 table 42420 protocol 99
# Same priority/table but a different route-protocol marker must remain foreign.
ip -n "$namespace" -4 rule add pref 42420 table 42420 protocol 98
ip -n "$namespace" -6 rule add pref 42420 table 42420 protocol 98

ip -n "$namespace" -4 route show table 42420 | grep -q '^default'
ip -n "$namespace" -6 route show table 42420 | grep -q '^default'

# Use detailed output because the protocol marker is not part of the default
# human-readable rule format on every supported iproute2/kernel combination.
show_rules() {
    family=$1
    ip -details -n "$namespace" "$family" rule show
}
has_rule_marker() {
    family=$1
    marker=$2
    show_rules "$family" | grep -Eq "42420:.*lookup 42420.*proto $marker([[:space:]]|$)"
}
require_rule_marker() {
    family=$1
    marker=$2
    output=$(show_rules "$family")
    if ! printf '%s\n' "$output" | grep -Eq "42420:.*lookup 42420.*proto $marker([[:space:]]|$)"; then
        printf 'expected %s rule at priority/table 42420 with protocol %s; detailed rules were:\n%s\n' "$family" "$marker" "$output" >&2
        exit 1
    fi
}
require_rule_marker -4 99
require_rule_marker -6 99
require_rule_marker -4 98
require_rule_marker -6 98

# Rules are removed by their typed selectors; routes are removed by link teardown.
ip -n "$namespace" -4 rule del pref 42420 table 42420 protocol 99
ip -n "$namespace" -6 rule del pref 42420 table 42420 protocol 99
if ! has_rule_marker -4 98; then
    echo "foreign IPv4 rule with a different protocol marker was removed" >&2
    exit 1
fi
if ! has_rule_marker -6 98; then
    echo "foreign IPv6 rule with a different protocol marker was removed" >&2
    exit 1
fi
ip -n "$namespace" -4 rule del pref 42420 table 42420 protocol 98
ip -n "$namespace" -6 rule del pref 42420 table 42420 protocol 98
if has_rule_marker -4 99; then
    echo "IPv4 Proxyctl policy rule survived explicit removal" >&2
    exit 1
fi
if has_rule_marker -6 99; then
    echo "IPv6 Proxyctl policy rule survived explicit removal" >&2
    exit 1
fi
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
if [ "$multipath_route_added" -eq 1 ] && ip -n "$namespace" -4 route show table 42420 | grep -q '203.0.113.0/24'; then
    echo "foreign IPv4 multipath route referencing the TUN unexpectedly survived unregister" >&2
    exit 1
fi
ip -n "$namespace" -6 route show table 42420 | grep -q '2001:db8:4242::/48'

if [ "$multipath_route_added" -eq 1 ]; then
    printf "%s\n" "OK (including expected foreign multipath-route flush side effect)" >&2
else
    printf "%s\n" "OK (multipath route unsupported by this kernel/iproute2; that check was skipped)" >&2
fi
