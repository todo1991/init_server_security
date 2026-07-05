#!/bin/bash
# Script khởi tạo VPS Ubuntu 22.04+: firewall nftables + SSH rate-limit,
# hardening sshd, tối ưu kernel & network. Tương thích Docker.
#
# Chạy: curl -fsSL .../initNewServer.sh | sudo bash
#
# Tùy biến qua biến môi trường:
#   SSH_PORT=2222                        port SSH (mặc định 22)
#   TCP_PORTS="80, 443"                  port TCP mở thêm cho dịch vụ chạy TRÊN HOST (mặc định không mở;
#                                        port publish của Docker đi đường forward, không cần khai ở đây)
#   UDP_PORTS="51820"                    port UDP mở thêm (mặc định không mở)
#   ADMIN_IPS="1.2.3.4, 2001:db8::/48"   IP/dải IP quản trị: accept mọi traffic, bỏ qua rate-limit
#   FORWARD_POLICY=drop                  mặc định accept (cần cho Docker); đặt drop nếu không dùng Docker
#   SSH_DISABLE_PASSWORD=1               tắt đăng nhập SSH bằng mật khẩu (chỉ áp dụng khi đã có authorized_keys)
#
# Chế độ kiểm tra (không cần root, dùng cho test/CI):
#   bash initNewServer.sh render         in cấu hình nftables ra stdout
#   bash initNewServer.sh render-pam     in PAM script ra stdout

set -e

SSH_PORT="${SSH_PORT:-22}"
TCP_PORTS="${TCP_PORTS-}"
UDP_PORTS="${UDP_PORTS-}"
ADMIN_IPS="${ADMIN_IPS-}"
FORWARD_POLICY="${FORWARD_POLICY:-accept}"
SSH_DISABLE_PASSWORD="${SSH_DISABLE_PASSWORD:-0}"

case "$FORWARD_POLICY" in
  accept|drop) ;;
  *) echo "FORWARD_POLICY phải là 'accept' hoặc 'drop'" >&2; exit 1 ;;
esac

# Phân loại ADMIN_IPS thành v4/v6
ADMIN_V4=""
ADMIN_V6=""
IFS=',' read -ra _admin_ips <<<"$ADMIN_IPS"
for _ip in "${_admin_ips[@]}"; do
  _ip=$(echo "$_ip" | tr -d '[:space:]')
  [ -z "$_ip" ] && continue
  if [[ $_ip == *:* ]]; then
    ADMIN_V6="${ADMIN_V6:+$ADMIN_V6, }$_ip"
  else
    ADMIN_V4="${ADMIN_V4:+$ADMIN_V4, }$_ip"
  fi
done

render_nftables_config() {
  local extra_rules="" admin_sets="" admin_rules=""
  [ -n "$TCP_PORTS" ] && extra_rules="${extra_rules}    tcp dport { ${TCP_PORTS} } counter accept
"
  [ -n "$UDP_PORTS" ] && extra_rules="${extra_rules}    udp dport { ${UDP_PORTS} } counter accept
"
  if [ -n "$ADMIN_V4" ]; then
    admin_sets="${admin_sets}  set admin_v4 {
    type ipv4_addr
    flags interval
    elements = { ${ADMIN_V4} }
  }
"
    admin_rules="${admin_rules}    ip saddr @admin_v4 accept
"
  fi
  if [ -n "$ADMIN_V6" ]; then
    admin_sets="${admin_sets}  set admin_v6 {
    type ipv6_addr
    flags interval
    elements = { ${ADMIN_V6} }
  }
"
    admin_rules="${admin_rules}    ip6 saddr @admin_v6 accept
"
  fi

  cat <<EOF
#!/usr/sbin/nft -f

# Chỉ thay thế bảng "inet firewall" của script này, KHÔNG flush toàn bộ ruleset
# để giữ nguyên rule do Docker (iptables-nft) hoặc phần mềm khác quản lý.
add table inet firewall
delete table inet firewall

table inet firewall {
${admin_sets}  set ssh_ratelimit_v4 {
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

  chain ssh_in {
    add @ssh_ratelimit_v4 { ip saddr limit rate 6/minute burst 5 packets } counter accept
    add @ssh_ratelimit_v6 { ip6 saddr & ffff:ffff:ffff:ffff:: limit rate 6/minute burst 5 packets } counter accept
  }

  chain inbound {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
${admin_rules}    ct state vmap { invalid : drop, established : accept, related : accept }

    # ICMP/ICMPv6: bắt buộc cho NDP (IPv6 sẽ chết nếu chặn) và Path MTU Discovery
    icmpv6 type { nd-router-advert, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query } accept
    icmpv6 type echo-request limit rate 10/second accept
    icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
    icmp type echo-request limit rate 10/second accept

    tcp dport ${SSH_PORT} ct state new jump ssh_in
${extra_rules}
    # Log gói bị chặn (giới hạn tần suất): xem bằng journalctl -k | grep nft-drop
    limit rate 5/minute burst 10 packets counter log prefix "nft-drop: "
  }

  chain forward {
    # accept: Docker tự quản lý filter forward bằng rule riêng của nó
    # drop: chặt chẽ hơn, chỉ dùng khi server không chạy Docker/routing
    type filter hook forward priority filter; policy ${FORWARD_POLICY};
  }
}
EOF
}

render_pam_script() {
  cat <<'EOS'
#!/bin/bash
# Xóa rate-limit nftables cho IP vừa đăng nhập SSH thành công.
# Set v6 lưu prefix /64 đã mask nên phải mask địa chỉ client trước khi xóa.
[ "$PAM_TYPE" = "open_session" ] || exit 0

CLIENT=$(echo "$SSH_CONNECTION" | awk '{print $1}')
[ -n "$CLIENT" ] || exit 0
CLIENT=${CLIENT%\%*}  # bỏ zone index (fe80::1%eth0)

# IPv4-mapped IPv6 (::ffff:1.2.3.4) -> xử lý như IPv4
if [[ $CLIENT == ::ffff:*.*.*.* ]]; then
  CLIENT=${CLIENT##*:}
fi

if [[ $CLIENT == *:* ]]; then
  # Khai triển :: rồi lấy 4 nhóm đầu (prefix /64)
  parts=()
  if [[ $CLIENT == *::* ]]; then
    left=${CLIENT%%::*} right=${CLIENT#*::}
    L=() R=()
    [ -n "$left" ] && IFS=: read -ra L <<<"$left"
    [ -n "$right" ] && IFS=: read -ra R <<<"$right"
    parts=("${L[@]}")
    for ((i = ${#L[@]} + ${#R[@]}; i < 8; i++)); do parts+=(0); done
    parts+=("${R[@]}")
  else
    IFS=: read -ra parts <<<"$CLIENT"
  fi
  nft delete element inet firewall ssh_ratelimit_v6 "{ ${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}:: }" 2>/dev/null
else
  nft delete element inet firewall ssh_ratelimit_v4 "{ $CLIENT }" 2>/dev/null
fi
exit 0
EOS
}

case "${1-}" in
  render) render_nftables_config; exit 0 ;;
  render-pam) render_pam_script; exit 0 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "Script cần chạy bằng root: curl ... | sudo bash" >&2
  exit 1
fi

echo "====== BẮT ĐẦU TRIỂN KHAI VPS ======"
echo "Port sẽ mở: SSH=${SSH_PORT} (rate-limit), TCP={${TCP_PORTS:-không}}, UDP={${UDP_PORTS:-không}}"
echo "Admin IP: ${ADMIN_IPS:-không} | Forward policy: ${FORWARD_POLICY}"

echo "[1/8] Kiểm tra xung đột firewall..."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "  - ufw đang bật, tắt để tránh xung đột rule với nftables..."
  ufw disable >/dev/null
fi

echo "[2/8] Cài đặt các gói cần thiết..."
apt-get update -qq >/dev/null
apt-get install -y -qq nftables openssh-server >/dev/null

echo "[3/8] Cài PAM hook clear rate-limit..."
render_pam_script >/usr/local/lib/pam_clear_nft_ratelimits
chown root:root /usr/local/lib/pam_clear_nft_ratelimits
chmod 0540 /usr/local/lib/pam_clear_nft_ratelimits
if ! grep -q pam_clear_nft_ratelimits /etc/pam.d/sshd; then
  echo "session optional pam_exec.so /usr/local/lib/pam_clear_nft_ratelimits" >> /etc/pam.d/sshd
fi

echo "[4/8] Hardening sshd..."
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/00-hardening.conf <<EOF
# sshd lấy giá trị ĐẦU TIÊN gặp được cho mỗi option — tên file 00- để thắng
# các file khác trong sshd_config.d (vd 50-cloud-init.conf).
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
X11Forwarding no
EOF
if grep -qs . /root/.ssh/authorized_keys; then
  echo "PermitRootLogin prohibit-password" >>/etc/ssh/sshd_config.d/00-hardening.conf
else
  echo "  - root chưa có authorized_keys: giữ nguyên PermitRootLogin hiện tại (thêm key rồi chạy lại để siết)."
fi
if [ "$SSH_DISABLE_PASSWORD" = "1" ]; then
  if grep -qs . /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; then
    echo "PasswordAuthentication no" >>/etc/ssh/sshd_config.d/00-hardening.conf
    echo "  - Đã tắt đăng nhập SSH bằng mật khẩu."
  else
    echo "  - CẢNH BÁO: SSH_DISABLE_PASSWORD=1 nhưng không tìm thấy authorized_keys nào — GIỮ đăng nhập mật khẩu để tránh tự khóa."
  fi
fi
sshd -t
systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || true

echo "[5/8] Tạo cấu hình nftables..."
BACKUP=""
if [ -s /etc/nftables.conf ]; then
  BACKUP="/etc/nftables.conf.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a /etc/nftables.conf "$BACKUP"
  echo "  - Đã backup cấu hình cũ: $BACKUP"
fi
render_nftables_config >/etc/nftables.conf

echo "[6/8] Kiểm tra & kích hoạt nftables..."
nft -c -f /etc/nftables.conf
systemctl enable nftables >/dev/null

# Rollback = gỡ bảng của script (mở lại mọi kết nối), không đụng rule của Docker;
# khôi phục file backup (nếu có) để lần boot sau dùng cấu hình cũ.
ROLLBACK_CMD="nft delete table inet firewall 2>/dev/null"
if [ -n "$BACKUP" ]; then
  ROLLBACK_CMD="$ROLLBACK_CMD; cp -a '$BACKUP' /etc/nftables.conf"
fi
ROLLBACK_CMD="$ROLLBACK_CMD; true"

if [ -t 1 ]; then
  # Dây an toàn chống tự khóa: hẹn rollback firewall sau 3 phút, chỉ hủy khi
  # người dùng mở được SSH MỚI và chạy nft-confirm — chính hành động đó chứng
  # minh firewall không khóa họ. (Không đọc phím từ /dev/tty: với
  # 'curl | sudo bash' trên sudo bật use_pty, phím gõ không đến được script.)
  cat >/usr/local/bin/nft-confirm <<'EOS'
#!/bin/bash
if [ "$(id -u)" -ne 0 ]; then
  echo "Chạy: sudo nft-confirm" >&2
  exit 1
fi
systemctl stop nft-rollback.timer >/dev/null 2>&1
systemctl reset-failed nft-rollback.service >/dev/null 2>&1
touch /run/nft-rollback-confirmed
echo "Đã xác nhận — giữ firewall, hủy hẹn rollback."
EOS
  chmod 0755 /usr/local/bin/nft-confirm
  rm -f /run/nft-rollback-confirmed

  systemctl stop nft-rollback.timer >/dev/null 2>&1 || true
  systemctl reset-failed nft-rollback.service >/dev/null 2>&1 || true
  systemd-run --quiet --on-active=180 --unit=nft-rollback bash -c "$ROLLBACK_CMD"
  # Áp dụng bằng nft -f (không restart service: ExecStop của nftables.service
  # flush toàn bộ ruleset, sẽ xóa cả rule của Docker nếu Docker đang chạy)
  nft -f /etc/nftables.conf
  systemctl start nftables >/dev/null 2>&1 || true
  echo
  echo "  !!! Firewall ĐÃ ÁP DỤNG. Trong ~3 phút, hãy MỞ MỘT KẾT NỐI SSH MỚI tới server"
  echo "      và chạy lệnh:  sudo nft-confirm"
  echo "      (SSH mới vào được = firewall không khóa bạn. Không xác nhận -> tự rollback.)"
  CONFIRMED=0
  WAITED=0
  while [ "$WAITED" -lt 168 ]; do
    if [ -f /run/nft-rollback-confirmed ]; then
      CONFIRMED=1
      break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    [ $((WAITED % 30)) -eq 0 ] && echo "  ... chờ xác nhận, còn ~$((180 - WAITED))s trước khi tự rollback"
  done
  if [ "$CONFIRMED" = "1" ]; then
    echo "  - Đã nhận xác nhận, firewall được giữ."
  else
    echo "  - KHÔNG nhận được xác nhận: firewall sẽ TỰ ROLLBACK trong chốc lát."
    echo "    Muốn áp dụng lại: chạy lại script và xác nhận bằng 'sudo nft-confirm'."
  fi
else
  nft -f /etc/nftables.conf
  systemctl start nftables >/dev/null 2>&1 || true
fi

echo "[7/8] Tối ưu kernel & network..."
echo nf_conntrack >/etc/modules-load.d/nf_conntrack.conf

cat >/etc/sysctl.d/99-vps-optimize.conf <<EOF
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
EOF

cat >/etc/security/limits.d/99-nofile.conf <<EOF
* soft nofile 1048576
* hard nofile 1048576
EOF

mkdir -p /etc/systemd/system.conf.d
cat >/etc/systemd/system.conf.d/99-nofile.conf <<EOF
[Manager]
DefaultLimitNOFILE=1048576
EOF

echo "[8/8] Áp dụng & reload cấu hình kernel..."
modprobe nf_conntrack 2>/dev/null || true
sysctl --system >/dev/null
systemctl daemon-reexec >/dev/null

echo
echo "==> HOÀN TẤT TRIỂN KHAI VPS!"
echo "- Kiểm tra rule:            nft list ruleset"
echo "- Xem gói bị firewall chặn: journalctl -k | grep nft-drop"
echo "- SSH rate-limit: 6 kết nối mới/phút (burst 5) mỗi IP (IPv6 theo /64), tự xóa khi đăng nhập thành công."
echo "- Docker: port publish (-p) đi qua chain forward nên KHÔNG bị firewall này chặn;"
echo "  dịch vụ chỉ dùng nội bộ hãy bind 127.0.0.1:PORT thay vì 0.0.0.0."
echo "- Đổi rule sau này: sửa /etc/nftables.conf rồi 'systemctl reload nftables'"
echo "  (KHÔNG dùng 'restart' trên máy chạy Docker — ExecStop sẽ flush cả rule của Docker)."
echo "- Đăng xuất SSH hoặc reboot để ulimit mới áp dụng toàn hệ thống."
