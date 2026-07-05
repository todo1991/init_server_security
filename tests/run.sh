#!/bin/bash
# Test: cú pháp bash, shellcheck (nếu có), cấu hình nftables render ra hợp lệ,
# logic PAM clear rate-limit. Chạy bằng root để nft kiểm tra đầy đủ (CI dùng sudo);
# không root thì chỉ kiểm tra được mức cú pháp.
set -e
cd "$(dirname "$0")/.." || exit 1
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== bash -n"
bash -n initNewServer.sh

echo "== shellcheck"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck initNewServer.sh tests/run.sh
  bash initNewServer.sh render-pam >"$TMP/pam.sh"
  shellcheck "$TMP/pam.sh"
else
  echo "  (bỏ qua: shellcheck chưa cài)"
fi

echo "== nft -c các biến thể cấu hình"
check_nft() {
  local out
  if out=$(nft -c -f "$1" 2>&1); then
    return 0
  fi
  if printf '%s\n' "$out" | grep -v "Operation not permitted" | grep -q "Error:"; then
    printf '%s\n' "$out"
    return 1
  fi
  return 0
}
i=0
render_case() {
  i=$((i + 1))
  env "$@" bash initNewServer.sh render >"$TMP/nft_$i.conf"
  check_nft "$TMP/nft_$i.conf"
  echo "  OK: ${*:-mặc định}"
}
render_case
render_case SSH_PORT=2222 TCP_PORTS="80, 443, 8080" UDP_PORTS="51820"
render_case TCP_PORTS="80, 443"
render_case ADMIN_IPS="203.0.113.7, 198.51.100.0/24, 2001:db8::/48"
render_case BLOCK_IPS="203.0.113.99, 192.0.2.0/24, 2001:db8:bad::/48"
render_case FORWARD_POLICY=drop
if [ "$(id -u)" -ne 0 ]; then
  echo "  (không phải root: mới kiểm tra được cú pháp, chưa kiểm tra kernel-level)"
fi

echo "== cấu hình không được flush toàn bộ ruleset (sẽ phá rule của Docker)"
if bash initNewServer.sh render | grep -q "flush ruleset"; then
  echo "FAIL: cấu hình chứa 'flush ruleset'"
  exit 1
fi
bash initNewServer.sh render | grep -q "delete table inet firewall"
echo "  OK"

echo "== FORWARD_POLICY không hợp lệ phải bị từ chối"
if FORWARD_POLICY=xxx bash initNewServer.sh render >/dev/null 2>&1; then
  echo "FAIL: FORWARD_POLICY=xxx lẽ ra phải lỗi"
  exit 1
fi
echo "  OK"

echo "== logic PAM script"
bash initNewServer.sh render-pam >"$TMP/pam.sh"
mkdir -p "$TMP/stub"
printf '#!/bin/bash\necho "$*"\n' >"$TMP/stub/nft"
chmod +x "$TMP/stub/nft"

assert() {
  local pam_type=$1 conn=$2 want=$3 got
  got=$(PATH="$TMP/stub:$PATH" PAM_TYPE="$pam_type" SSH_CONNECTION="$conn" bash "$TMP/pam.sh")
  if [ "$got" != "$want" ]; then
    echo "FAIL: PAM_TYPE=$pam_type SSH_CONNECTION='$conn'"
    echo "  muốn: '$want'"
    echo "  nhận: '$got'"
    exit 1
  fi
  echo "  OK: '${conn%% *}' -> ${want:-<không gọi nft>}"
}

D4="delete element inet firewall ssh_ratelimit_v4"
D6="delete element inet firewall ssh_ratelimit_v6"
assert open_session "203.0.113.7 5 x 22" "$D4 { 203.0.113.7 }"
assert open_session "2001:db8:12:34:abcd::1 5 x 22" "$D6 { 2001:db8:12:34:: }"
assert open_session "2001:db8::9 5 x 22" "$D6 { 2001:db8:0:0:: }"
assert open_session "::1 5 x 22" "$D6 { 0:0:0:0:: }"
assert open_session "fe80::1234%eth0 5 x 22" "$D6 { fe80:0:0:0:: }"
assert open_session "::ffff:198.51.100.5 5 x 22" "$D4 { 198.51.100.5 }"
assert open_session "2001:0db8:aaaa:bbbb:cccc:dddd:eeee:ffff 5 x 22" "$D6 { 2001:0db8:aaaa:bbbb:: }"
assert close_session "203.0.113.7 5 x 22" ""
assert open_session "" ""

echo
echo "Tất cả test PASS"
