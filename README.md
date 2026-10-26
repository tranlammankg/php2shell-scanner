<div align="center">

# 🛡️ PHP2Shell Vulnerability Scanner & Hardening Toolkit
### Audit Tool for CVE-2026-109618 & CVE-2026-109619 (PHP2Shell RCE)

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib)-brightgreen.svg)](#)
[![Docker Support](https://img.shields.io/badge/docker-ready-2496ED.svg)](Dockerfile)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Công cụ rà soát an toàn hệ thống, tự động phát hiện lỗ hổng PHP2Shell và cẩm nang khắc phục/phòng thủ toàn diện dành cho Quản trị viên máy chủ và Webmaster.*

</div>

---

## 📌 1. Lỗ Hổng PHP2Shell Là Gì?

**PHP2Shell** là tên gọi của cặp lỗ hổng thực thi mã từ xa (**RCE**) nghiêm trọng được phát hiện trong lõi của ngôn ngữ PHP, công bố vào tháng 10/2026:

* **CVE-2026-109618 (CVSS 9.8 - Out-of-Memory / Heap Corruption):** Xảy ra khi PHP gặp fatal error hoặc vượt giới hạn bộ nhớ (`memory_limit`). Cơ chế dọn dẹp bằng `longjmp()` xử lý sai các cấu trúc heap đang dở dang, dẫn đến ghi đè bộ nhớ tùy ý.
* **CVE-2026-109619 (CVSS 9.2 - Stale Global State / Use-After-Free):** Cơ chế theo dõi tiến trình upload (`session.upload_progress`) để lại con trỏ toàn cục trỏ vào vùng nhớ đã giải phóng. Request kế tiếp của cùng một worker process sẽ kích hoạt Use-After-Free (UAF).

> [!WARNING]
> **Mức độ rủi ro:** Kẻ tấn công có thể khai thác từ xa **không cần đăng nhập (unauthenticated)** đối với hầu hết các ứng dụng web chạy trên nền tảng PHP chưa được vá (bao gồm WordPress, Laravel, Symfony, Drupal...).

---

## 🎯 2. Ma Trận Bản Vá Khẩn Cấp (Patched Matrix)

| Nhánh PHP | Phiên bản dính lỗ hổng | Phiên bản ĐÃ VÁ AN TOÀN | Trạng thái |
| :---: | :---: | :---: | :---: |
| **PHP 8.5** | `< 8.5.12` | **`>= 8.5.12`** | ✅ Đã có bản vá |
| **PHP 8.4** | `< 8.4.27` | **`>= 8.4.27`** | ✅ Đã có bản vá |
| **PHP 8.3** | `< 8.3.36` | **`>= 8.3.36`** | ✅ Đã có bản vá |
| **PHP 8.2** | `< 8.2.35` | **`>= 8.2.35`** | ✅ Đã có bản vá |
| **PHP $\le$ 8.1** | Mọi phiên bản 5.x, 7.x, 8.0, 8.1 | *Không có bản vá chính thức* | ❌ **Hết hạn hỗ trợ (EOL)** - Bắt buộc nâng cấp |

---

## 🚀 3. Hướng Dẫn Sử Dụng Scanner

Công cụ `php2shell_scanner.py` sử dụng **thư viện chuẩn Python (Standard Library)**, không cần `pip install` bất cứ gói ngoài nào.

### A. Quét Trực Tiếp Trên Máy Chủ (Local Host Audit)
Tự động tìm kiếm các bản PHP cài đặt trên OS, các service đang chạy (PHP-FPM, Apache, Nginx...) và kiểm tra cấu hình `php.ini`:
```bash
python3 php2shell_scanner.py --local
```

### B. Quét Thụ Động Từ Xa Một Website (Remote URL Check)
Kiểm tra banner HTTP headers (`X-Powered-By`, `Server`) và kiểm tra xem web có để lộ tệp cấu hình nguy hiểm như `phpinfo.php`:
```bash
python3 php2shell_scanner.py --url https://your-website.com
```

### C. Quét Hàng Loạt Từ Danh Sách File (Batch Scan)
Chuẩn bị file `targets.txt` chứa danh sách domain cần quét:
```bash
python3 php2shell_scanner.py --file targets.txt
```
Xuất báo cáo định dạng Markdown:
```bash
python3 php2shell_scanner.py --file targets.txt --markdown > report.md
```

### D. Kiểm Tra Nhanh Phiên Bản Chỉ Định
```bash
python3 php2shell_scanner.py --check-version 8.3.20
```

### E. Chạy Bằng Docker (Không Cần Cài Python)
```bash
# Build image
docker build -t php2shell-scanner .

# Quét từ xa
docker run --rm php2shell-scanner --url https://your-website.com

# Kiểm tra phiên bản
docker run --rm php2shell-scanner --check-version 8.2.34
```

---

## 🛡️ 4. Tóm Tắt Biện Pháp Khắc Phục Khẩn Cấp

> Xem chi tiết cẩm nang từng bước tại: **[`HARDENING.md`](HARDENING.md)**

1. **Nâng cấp gói PHP hệ điều hành:**
   ```bash
   # Debian / Ubuntu (Ondřej Surý PPA):
   sudo apt update && sudo apt --only-upgrade install php*-cli php*-fpm
   sudo systemctl restart php*-fpm
   ```
2. **Cấu hình giảm thiểu tức thì trong `php.ini` (Workaround):**
   ```ini
   ; Vô hiệu hóa vector upload progress
   session.upload_progress.enabled = Off

   ; Ẩn phiên bản PHP để tránh bị dò quét
   expose_php = Off
   display_errors = Off
   ```
3. **Ẩn Header trên Nginx:**
   ```nginx
   proxy_hide_header X-Powered-By;
   fastcgi_hide_header X-Powered-By;
   server_tokens off;
   ```
4. **Triển khai Web Application Firewall (WAF):** Thiết lập quy tắc chặn các request multipart dung lượng bất thường hoặc lặp đi lặp lại.

---

## 📁 5. Cấu Trúc Thư Mục Repository

```text
├── php2shell_scanner.py   # Script quét chính (Zero dependencies)
├── Dockerfile             # Chạy container hóa độc lập
├── HARDENING.md           # Cẩm nang cấu hình phòng thủ chi tiết cho Nginx/Apache/php.ini
├── targets.example.txt    # File mẫu danh sách mục tiêu quét hàng loạt
├── .github/workflows/     # CI/CD tự động kiểm thử
├── SECURITY.md            # Chính sách bảo mật & tuyên bố trách nhiệm
├── LICENSE                # Giấy phép mã nguồn mở MIT
└── README.md              # Tài liệu hướng dẫn
```

---

## ⚖️ Tuyên Bố Trách Nhiệm (Disclaimer)
*Công cụ này được phát triển hoàn toàn vì mục đích phòng vệ, kiểm thử an ninh hợp pháp và hỗ trợ cộng đồng bảo vệ hạ tầng web. Tác giả không chịu trách nhiệm đối với bất kỳ hành vi lạm dụng hay quét trái phép nào.*
