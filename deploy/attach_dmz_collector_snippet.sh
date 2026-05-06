#!/usr/bin/env sh
set -eu

# Safe OVS attachment snippet template for LabShock.
# Adapt interface names to your environment/tooling.
CONTAINER="dmz_collector"
BRIDGE="br-dmz"
IP_CIDR="192.168.10.70/24"
GATEWAY="192.168.10.254"

echo "[info] Attach ${CONTAINER} to ${BRIDGE} with ${IP_CIDR}"
echo "[info] Use your existing veth/ovs helpers. Example flow:"
echo "  1) create veth pair (host side + container side)"
echo "  2) ovs-vsctl add-port ${BRIDGE} <host_veth>"
echo "  3) move <container_veth> into ${CONTAINER} netns"
echo "  4) inside container: ip link set <container_veth> up"
echo "  5) inside container: ip addr add ${IP_CIDR} dev <container_veth>"
echo "  6) inside container: ip route add default via ${GATEWAY}"
echo "  7) verify: curl http://192.168.10.70:9000/health"

