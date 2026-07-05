# init_server_security

Script khởi tạo VPS Ubuntu 22.04+:

- **Firewall nftables**: chặn mặc định, chỉ mở SSH (thêm port khác qua `TCP_PORTS`/`UDP_PORTS` khi cần); tự tắt ufw nếu đang bật để tránh xung đột; log gói bị chặn (`journalctl -k | grep nft-drop`)
- **SSH rate-limit**: 6 kết nối mới/phút mỗi IP (IPv6 tính theo /64), tự xóa limit khi đăng nhập thành công (PAM hook)
- **Tự động ban brute-force**: IP vượt rate-limit mà vẫn nã dồn dập (>20 kết nối/phút phần vượt) bị đưa vào blackhole 24h — fail2ban thuần nftables, không thêm process; xem bằng `journalctl -k | grep nft-ban`
- **Chặn tay**: biến `BLOCK_IPS` hoặc sửa nóng `nft add element inet firewall block_v4 { 1.2.3.4 }` (gỡ: `delete element`)
- **Chống tự khóa**: whitelist IP quản trị (`ADMIN_IPS`) + tự rollback firewall sau ~3 phút nếu không xác nhận SSH vẫn vào được
- **Hardening sshd**: MaxAuthTries, LoginGraceTime, MaxStartups...; chỉ siết root login / password login khi đã có authorized_keys
- **Tương thích Docker**: forward policy mặc định `accept`, Docker tự quản lý filter của nó
- **Tối ưu kernel & network**: BBR + fq, ulimit 1048576, buffer TCP, syncookies...

## Triển khai

```
curl -fsSL https://raw.githubusercontent.com/todo1991/init_server_security/refs/heads/main/initNewServer.sh | sudo bash
```

Sau khi firewall áp dụng, **mở một kết nối SSH mới** tới server và chạy `sudo nft-confirm` trong vòng ~3 phút — chính việc SSH mới vào được là bằng chứng bạn không bị khóa. Không xác nhận → firewall tự rollback về cấu hình cũ.

## Tùy biến

Truyền qua biến môi trường (khuyến nghị tải script về xem trước khi chạy):

```
curl -fsSLO https://raw.githubusercontent.com/todo1991/init_server_security/refs/heads/main/initNewServer.sh
sudo SSH_PORT=2222 TCP_PORTS="80, 443" ADMIN_IPS="1.2.3.4" SSH_DISABLE_PASSWORD=1 bash initNewServer.sh
```

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `SSH_PORT` | `22` | Port SSH (được rate-limit) |
| `TCP_PORTS` | *(không)* | Port TCP mở thêm cho dịch vụ chạy **trên host**, ví dụ `80, 443` nếu nginx cài trực tiếp. Port publish của Docker không cần khai ở đây |
| `UDP_PORTS` | *(không)* | Port UDP mở thêm, ví dụ `51820` cho WireGuard |
| `ADMIN_IPS` | *(không)* | IP/CIDR quản trị (cách nhau dấu phẩy, v4+v6): accept mọi traffic, không rate-limit |
| `BLOCK_IPS` | *(không)* | IP/CIDR chặn hẳn mọi traffic (drop trước cả rate-limit) |
| `FORWARD_POLICY` | `accept` | `accept` để tương thích Docker; `drop` nếu server không dùng Docker/routing |
| `SSH_DISABLE_PASSWORD` | `0` | `1` = tắt đăng nhập SSH bằng mật khẩu (script tự từ chối nếu chưa có authorized_keys nào) |

## Quản lý IP bị chặn

Firewall có 3 loại danh sách, xem bằng `nft list set`:

```
nft list set inet firewall block_v4          # chặn tay (block_v6 cho IPv6)
nft list set inet firewall ssh_blackhole_v4  # tự động ban 24h, kèm "expires" đếm ngược
nft list set inet firewall ssh_ratelimit_v4  # đang bị theo dõi rate-limit (chưa chặn)
```

Thao tác thường dùng:

```
# Chặn / gỡ chặn tay một IP (áp dụng ngay, không cần reload)
nft add element inet firewall block_v4 { 1.2.3.4 }
nft delete element inet firewall block_v4 { 1.2.3.4 }

# Gỡ ban tự động trước hạn
nft delete element inet firewall ssh_blackhole_v4 { 1.2.3.4 }

# Lịch sử: gói bị chặn / IP bị tự ban
journalctl -k | grep nft-drop
journalctl -k | grep nft-ban
```

Lưu ý: IP thêm bằng `nft add element` sẽ mất khi reload/reboot — muốn chặn bền vững, chạy lại script với `BLOCK_IPS="1.2.3.4, ..."` (hoặc thêm vào `elements` của set `block_v4` trong `/etc/nftables.conf` rồi `systemctl reload nftables`). Set `ssh_blackhole` là động, tự hết hạn sau 24h, không cần dọn.

## Lưu ý khi dùng Docker

- **Cài Docker trước hay sau script đều được**: firewall chỉ quản lý bảng `inet firewall` riêng (không `flush ruleset`), Docker tự tạo và quản lý rule của nó. Chạy lại script trên máy đang chạy Docker cũng an toàn.
- Port publish qua `-p` được Docker DNAT và đi qua chain **forward**, nên **không bị firewall này chặn** — dịch vụ chỉ dùng nội bộ hãy publish dạng `127.0.0.1:5432:5432` thay vì `-p 5432:5432`.
- Giữ `FORWARD_POLICY=accept` (mặc định); Docker tự quản lý filter forward và isolation giữa các network của nó.
- Đổi rule sau này: sửa `/etc/nftables.conf` rồi `systemctl reload nftables`. **Không dùng `restart`** trên máy chạy Docker — ExecStop của nftables.service chạy `nft flush ruleset`, xóa cả rule của Docker (phải `systemctl restart docker` mới có mạng lại).

## Test

```
bash tests/run.sh          # cú pháp + render cấu hình nftables + logic PAM script
sudo bash tests/run.sh     # kèm kiểm tra nft kernel-level đầy đủ
```

CI (GitHub Actions) chạy bộ test này trên mỗi push/PR.
