#!/bin/bash
# Complete VPN routing fix for Raspberry Pi

echo "=== Deadlight VPN Routing Setup ==="

# 1. Enable IP forwarding
echo "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# 2. Get default gateway info
DEFAULT_GW=$(ip route | grep default | head -1 | awk '{print $3}')
DEFAULT_DEV=$(ip route | grep default | head -1 | awk '{print $5}')

if [ -z "$DEFAULT_GW" ] || [ -z "$DEFAULT_DEV" ]; then
    echo "ERROR: Could not detect default gateway"
    exit 1
fi

echo "Default gateway: $DEFAULT_GW via $DEFAULT_DEV"

# 3. Create routing table for proxy bypass
echo "Setting up routing table..."
if ! grep -q "100 vpn_bypass" /etc/iproute2/rt_tables; then
    echo "100 vpn_bypass" | sudo tee -a /etc/iproute2/rt_tables
fi

# 4. Flush and recreate vpn_bypass table
sudo ip route flush table vpn_bypass
sudo ip route add default via $DEFAULT_GW dev $DEFAULT_DEV table vpn_bypass
sudo ip route add 10.8.0.0/24 dev tun0 table vpn_bypass

# 5. Flush existing rules for clean slate
sudo ip rule del from all lookup vpn_bypass 2>/dev/null || true
sudo ip rule del from 10.8.0.1 lookup main 2>/dev/null || true

# 6. Add routing rules
# Priority 50: Proxy itself (source 10.8.0.1) uses main table (bypasses VPN routes)
sudo ip rule add from 10.8.0.1 lookup main priority 50

# Priority 100: Everything else from 10.8.0.0/24 uses vpn_bypass table
sudo ip rule add from 10.8.0.0/24 lookup vpn_bypass priority 100

# 7. Setup NAT for VPN clients
echo "Setting up NAT..."
sudo iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_DEV -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_DEV -j MASQUERADE

# 8. Verify setup
echo ""
echo "=== Configuration Complete ==="
echo ""
echo "IP rules:"
sudo ip rule list | grep -E "(main|vpn_bypass|10.8.0)"
echo ""
echo "VPN bypass table:"
sudo ip route show table vpn_bypass
echo ""
echo "Main table (VPN routes):"
ip route show | grep tun0
echo ""
echo "Test: Route check for 93.184.216.34 from proxy (10.8.0.1):"
sudo ip route get 93.184.216.34 from 10.8.0.1
