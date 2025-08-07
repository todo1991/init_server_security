#!/bin/bash
# Script triển khai SSH rate-limiting, tối ưu kernel & network cho Ubuntu VPS
# Tested on Ubuntu 22.04+ (root)

set -e

echo "====== BẮT ĐẦU TRIỂN KHAI VPS ======"

echo "[1/7] Cài đặt các gói cần thiết..."
apt-get update -qq >/dev/null
apt-get install -y -qq nftables openssh-server >/dev/null

echo "[2/7] Tạo cấu hình nftables..."
cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet firewall {
  set ssh_ratelimit_v4 {
    type ipv4_addr
    size 65535
    flags dynamic,timeout
    timeout 1h
  }
  set ssh_ratelimit_v6 {
    type ipv6_addr
    size 65535
    flags dynamic,timeout
    timeout 1h
  }

  chain inbound_ipv4 {
    ct state new tcp dport 22 add @ssh_ratelimit_v4 { ip saddr limit rate 1/hour burst 1 packets } counter accept
  }

  chain inbound_ipv6 {
    ct state new tcp dport 22 add @ssh_ratelimit_v6 { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate 1/hour burst 1 packets } counter accept
  }

  chain inbound {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    meta protocol vmap { ip : jump inbound_ipv4, ip6 : jump inbound_ipv6 }
    ct state vmap { invalid : drop, established : accept, related : accept }
    udp dport 53 counter accept
    tcp dport { 53, 853, 80, 443 } counter accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }
}
EOF

echo "[3/7] Kích hoạt nftables..."
systemctl enable nftables >/dev/null
systemctl restart nftables >/dev/null

echo "[4/7] Tạo PAM script clear rate-limit..."
cat >/usr/local/lib/pam_clear_nft_ratelimits <<'EOS'
#!/bin/bash
CLIENT=$(echo "$SSH_CONNECTION" | awk '{print $1}')
if [[ $CLIENT == *:* ]]; then
  nft delete element inet firewall ssh_ratelimit_v6 { $CLIENT }
else
  nft delete element inet firewall ssh_ratelimit_v4 { $CLIENT }
fi
exit 0
EOS

chown root:root /usr/local/lib/pam_clear_nft_ratelimits
chmod 0540 /usr/local/lib/pam_clear_nft_ratelimits

echo "[5/7] Cấu hình PAM cho sshd..."
if ! grep -q pam_clear_nft_ratelimits /etc/pam.d/sshd; then
  echo "session optional pam_exec.so /usr/local/lib/pam_clear_nft_ratelimits" >> /etc/pam.d/sshd
fi

# --- Tối ưu kernel & network ---
SYSCTL_CONFIG="/etc/sysctl.conf"
LIMITS_CONF="/etc/security/limits.conf"
SYSTEMD_CONF="/etc/systemd/system.conf"

echo "[6/7] Tối ưu kernel & network..."
grep -q "## BEGIN SYSCTL OPTIMIZE" $SYSCTL_CONFIG 2>/dev/null || cat <<EOF >>$SYSCTL_CONFIG

## BEGIN SYSCTL OPTIMIZE
fs.file-max = 1048576

net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535

net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_local_port_range = 1024 65000

net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

net.netfilter.nf_conntrack_max = 131072

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
## END SYSCTL OPTIMIZE
EOF

grep -q "## BEGIN LIMIT NOFILE" $LIMITS_CONF 2>/dev/null || cat <<EOF >>$LIMITS_CONF

## BEGIN LIMIT NOFILE
* soft nofile 1048576
* hard nofile 1048576
## END LIMIT NOFILE
EOF

if ! grep -q "^DefaultLimitNOFILE=" $SYSTEMD_CONF; then
    echo "" >>$SYSTEMD_CONF
    echo "DefaultLimitNOFILE=1048576" >>$SYSTEMD_CONF
fi

echo "[7/7] Áp dụng & reload cấu hình kernel..."
sysctl -p >/dev/null
systemctl daemon-reexec >/dev/null

echo
echo "==> HOÀN TẤT TRIỂN KHAI VPS!"
echo "- Kiểm tra rule: nft list ruleset"
echo "- Đăng xuất SSH hoặc reboot để ulimit mới áp dụng toàn hệ thống."
echo "- Đã tự động tối ưu kernel, network, firewall và SSH rate-limit."
