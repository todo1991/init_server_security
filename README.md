# init_server_security

Script khởi tạo VPS Ubuntu 22.04+:

- **Firewall nftables**: chặn mặc định, chỉ mở port khai báo; tự tắt ufw nếu đang bật để tránh xung đột; log gói bị chặn (`journalctl -k | grep nft-drop`)
- **SSH rate-limit**: 6 kết nối mới/phút mỗi IP (IPv6 tính theo /64), tự xóa limit khi đăng nhập thành công (PAM hook)
- **Chống tự khóa**: whitelist IP quản trị (`ADMIN_IPS`) + tự rollback firewall sau ~3 phút nếu không xác nhận SSH vẫn vào được
- **Hardening sshd**: MaxAuthTries, LoginGraceTime, MaxStartups...; chỉ siết root login / password login khi đã có authorized_keys
- **Tương thích Docker**: forward policy mặc định `accept`, Docker tự quản lý filter của nó
- **Tối ưu kernel & network**: BBR + fq, ulimit 1048576, buffer TCP, syncookies...

## Triển khai

```
curl -fsSL https://raw.githubusercontent.com/todo1991/init_server_security/refs/heads/main/initNewServer.sh | sudo bash
```

Sau khi firewall áp dụng, script yêu cầu **mở một kết nối SSH mới** để kiểm tra rồi nhấn Enter xác nhận. Không xác nhận → tự rollback về cấu hình cũ sau ~3 phút (giữ lại bằng tay: `systemctl stop nft-rollback.timer`).

## Tùy biến

Truyền qua biến môi trường (khuyến nghị tải script về xem trước khi chạy):

```
curl -fsSLO https://raw.githubusercontent.com/todo1991/init_server_security/refs/heads/main/initNewServer.sh
sudo SSH_PORT=2222 TCP_PORTS="80, 443" ADMIN_IPS="1.2.3.4" SSH_DISABLE_PASSWORD=1 bash initNewServer.sh
```

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `SSH_PORT` | `22` | Port SSH (được rate-limit) |
| `TCP_PORTS` | `80, 443` | Port TCP mở thêm; đặt rỗng (`TCP_PORTS=`) để không mở |
| `UDP_PORTS` | *(không)* | Port UDP mở thêm, ví dụ `51820` cho WireGuard |
| `ADMIN_IPS` | *(không)* | IP/CIDR quản trị (cách nhau dấu phẩy, v4+v6): accept mọi traffic, không rate-limit |
| `FORWARD_POLICY` | `accept` | `accept` để tương thích Docker; `drop` nếu server không dùng Docker/routing |
| `SSH_DISABLE_PASSWORD` | `0` | `1` = tắt đăng nhập SSH bằng mật khẩu (script tự từ chối nếu chưa có authorized_keys nào) |

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
