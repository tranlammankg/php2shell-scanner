# Hướng Dẫn Phòng Ngừa & Tăng Cường An Ninh (Hardening Guide)
### Bảo Vệ Hệ Thống Trước Lỗ Hổng PHP2Shell (CVE-2026-109618 & CVE-2026-109619)

---

## 1. Nâng Cấp Bản Vá Chính Thức (Ưu Tiên Số 1)

Cách xử lý triệt để và an toàn nhất là cập nhật phiên bản PHP trên tất cả máy chủ lên bản vá khẩn cấp:

* **PHP 8.2** $\rightarrow$ **`8.2.35`** trở lên
* **PHP 8.3** $\rightarrow$ **`8.3.36`** trở lên
* **PHP 8.4** $\rightarrow$ **`8.4.27`** trở lên
* **PHP 8.5** $\rightarrow$ **`8.5.12`** trở lên

### Lệnh cập nhật theo từng môi trường:

#### Trên Ubuntu / Debian:
```bash
# Cập nhật danh sách gói
sudo apt update

# Nếu dùng PPA của Ondřej Surý:
sudo apt --only-upgrade install php8.3 php8.3-fpm php8.3-cli php8.3-common

# Kiểm tra lại phiên bản
php -v

# Khởi động lại dịch vụ PHP-FPM và Web Server
sudo systemctl restart php8.3-fpm
sudo systemctl restart nginx   # hoặc apache2
```

#### Trên RHEL / CentOS / Rocky Linux / AlmaLinux:
```bash
# Cập nhật qua dnf/yum với kho Remi
sudo dnf clean all
sudo dnf upgrade php php-fpm -y
sudo systemctl restart php-fpm
sudo systemctl restart nginx   # hoặc httpd
```

#### Trên Docker Container:
Thay đổi base image trong `Dockerfile` lên tag mới nhất đã có bản vá và build lại:
```dockerfile
# Ví dụ: Nâng cấp image
FROM php:8.3.36-fpm-alpine
# hoặc
FROM php:8.4.27-fpm-bullseye
```
Chạy rebuild và deploy lại container:
```bash
docker-compose build --pull
docker-compose up -d --force-recreate
```

---

## 2. Các Biện Pháp Giảm Thiểu Tạm Thời (Mitigations)
*(Dành cho các hệ thống chưa thể nâng cấp ngay lập tức hoặc đang chạy phiên bản EOL)*

### A. Tinh Chỉnh Cấu Hình `php.ini`
Mở file cấu hình `php.ini` của bạn (ví dụ: `/etc/php/8.3/fpm/php.ini`):

```ini
; 1. Vô hiệu hóa tính năng Upload Progress (Ngắt vector tấn công CVE-2026-109619)
session.upload_progress.enabled = Off

; 2. Ẩn thông tin phiên bản PHP để tránh bị dò quét tự động
expose_php = Off

; 3. Không hiển thị chi tiết lỗi PHP ra trình duyệt (tránh lộ heap memory)
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php_errors.log

; 4. Giới hạn các hàm thực thi nguy hiểm nếu ứng dụng không dùng đến
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```
*Lưu ý: Sau khi sửa `php.ini`, bắt buộc phải reload lại service PHP-FPM / Apache.*

---

### B. Tăng Cường Cấu Hình Nginx
Thêm vào file cấu hình `nginx.conf` hoặc vhost của bạn:

```nginx
server {
    listen 80;
    server_name example.com;

    # 1. Ẩn banner máy chủ và PHP
    server_tokens off;
    proxy_hide_header X-Powered-By;
    fastcgi_hide_header X-Powered-By;

    # 2. Giới hạn dung lượng tải lên hợp lý để hạn chế kích hoạt OOM memory limit
    client_max_body_size 16M;
    client_body_buffer_size 128k;

    # 3. Chặn tuyệt đối việc truy cập các file test/thông tin nhạy cảm
    location ~* /(phpinfo|info|test|version)\.php$ {
        deny all;
        return 404;
    }

    # 4. Chặn các file ẩn (.git, .env...)
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
```

---

### C. Tăng Cường Cấu Hình Apache
Trong file cấu hình Apache hoặc file `.htaccess`:

```apache
# Ẩn phiên bản Apache và các module
ServerTokens Prod
ServerSignature Off

# Ẩn header X-Powered-By
<IfModule mod_headers.c>
    Header unset X-Powered-By
</IfModule>

# Chặn truy cập file phpinfo
<FilesMatch "^(phpinfo|info|test|version)\.php$">
    Require all denied
</FilesMatch>
```

---

## 3. Cấu Hình Tường Lửa Ứng Dụng Web (WAF)

Nếu bạn sử dụng Cloudflare, AWS WAF hoặc ModSecurity:
- **Cloudflare WAF:** Bật bộ quy tắc **Cloudflare Managed Ruleset** và kích hoạt rule khẩn cấp liên quan đến CVE-2026-109618 / CVE-2026-109619.
- **Tùy chỉnh WAF Rule (Custom WAF):**
  - Chặn hoặc thách thức (Challenge) các request gửi `multipart/form-data` chứa `PHP_SESSION_UPLOAD_PROGRESS` bất thường.
  - Rate-limit các request gửi payload dung lượng lớn liên tục đến cùng một URI.

---

## 4. Giám Sát Phát Hiện Xâm Nhập (EDR / SIEM)

Do PHP2Shell là lỗ hổng RCE, khi kẻ tấn công khai thác thành công, tiến trình `php-fpm` hoặc `httpd` thường sẽ sinh ra (spawn) các tiến trình con dòng lệnh bất thường.

**Dấu hiệu bất thường cần cảnh báo ngay trong SIEM/EDR:**
- Tiến trình cha `php-fpm`, `apache2`, `httpd`, `frankenphp` gọi các tiến trình con:
  - `/bin/sh`, `/bin/bash`, `/bin/dash`
  - `curl`, `wget`, `python`, `perl`, `nc`, `ncat`
  - Các script nằm trong `/tmp/`, `/dev/shm/`, hoặc thư mục uploads của CMS.
