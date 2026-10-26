#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PHP2Shell Vulnerability Scanner & System Audit Tool
Reference: CVE-2026-109618 & CVE-2026-109619 (PHP2Shell)
Author: Antigravity Security Research
License: MIT
"""

import sys
import os
import re
import subprocess
import argparse
import json
import urllib.request
import urllib.error
import ssl
from typing import Dict, List, Optional, Tuple, Any

# Safe patched version matrix
# Format: major.minor -> minimum safe patch version
PATCHED_VERSIONS: Dict[Tuple[int, int], int] = {
    (8, 2): 35,  # PHP 8.2.35+
    (8, 3): 36,  # PHP 8.3.36+
    (8, 4): 27,  # PHP 8.4.27+
    (8, 5): 12,  # PHP 8.5.12+
}

# Terminal Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Initialize ANSI Virtual Terminal Processing on Windows Command Prompt / PowerShell
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        hStdOut = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(hStdOut, ctypes.byref(mode)):
            kernel32.SetConsoleMode(hStdOut, mode.value | 0x0004)
        else:
            os.system('')
    except Exception:
        try:
            os.system('')
        except Exception:
            pass

def colorize(text: str, color: str, enable: bool = True) -> str:
    if not enable or not sys.stdout.isatty():
        return text
    return f"{color}{text}{Colors.RESET}"

def parse_php_version(version_str: str) -> Optional[Tuple[int, int, int, str]]:
    """
    Extract (major, minor, patch, extra) from string like '8.3.12-1+ubuntu22.04' or 'PHP 8.2.34'
    """
    pattern = r'(?:PHP\s+)?([0-9]+)\.([0-9]+)\.([0-9]+)(.*)'
    match = re.search(pattern, version_str)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3))
    extra = match.group(4).strip()
    return (major, minor, patch, extra)

def evaluate_php_version(version_str: str) -> Dict[str, Any]:
    """
    Evaluates whether a given PHP version string is vulnerable to PHP2Shell.
    """
    parsed = parse_php_version(version_str)
    if not parsed:
        return {
            "version": version_str,
            "status": "UNKNOWN",
            "reason": f"Could not parse valid semantic version from '{version_str}'",
            "vulnerable": False
        }

    major, minor, patch, extra = parsed
    clean_version = f"{major}.{minor}.{patch}"
    branch = (major, minor)

    # Check EOL versions (< 8.2)
    if major < 8 or (major == 8 and minor < 2):
        return {
            "version": clean_version,
            "full_version": version_str.strip(),
            "status": "VULNERABLE (CRITICAL / EOL)",
            "vulnerable": True,
            "reason": (
                f"PHP {clean_version} is End-of-Life (EOL) and intrinsically vulnerable to PHP2Shell "
                "(CVE-2026-109618 & CVE-2026-109619). No upstream security patch is provided for branches < 8.2."
            ),
            "recommendation": "Upgrade immediately to an actively supported release (PHP 8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+)."
        }

    # Actively patched branches (8.2, 8.3, 8.4, 8.5)
    if branch in PATCHED_VERSIONS:
        safe_patch = PATCHED_VERSIONS[branch]
        if patch < safe_patch:
            return {
                "version": clean_version,
                "full_version": version_str.strip(),
                "status": "VULNERABLE (CRITICAL)",
                "vulnerable": True,
                "reason": (
                    f"PHP {clean_version} is vulnerable to PHP2Shell RCE flaws (CVE-2026-109618 & CVE-2026-109619). "
                    f"Patched version for branch {major}.{minor} is {major}.{minor}.{safe_patch}."
                ),
                "recommendation": f"Update PHP package to version {major}.{minor}.{safe_patch} or higher immediately."
            }
        else:
            return {
                "version": clean_version,
                "full_version": version_str.strip(),
                "status": "PATCHED (SECURE)",
                "vulnerable": False,
                "reason": f"PHP {clean_version} meets or exceeds the emergency patch requirement (>= {major}.{minor}.{safe_patch}).",
                "recommendation": "Maintain regular update cadence and review php.ini security hardening."
            }

    # Versions newer than 8.5 (or hypothetical future branches)
    if major > 8 or (major == 8 and minor > 5):
        return {
            "version": clean_version,
            "full_version": version_str.strip(),
            "status": "PATCHED (FUTURE_BRANCH)",
            "vulnerable": False,
            "reason": f"PHP {clean_version} is from a newer branch that post-dates the PHP2Shell disclosure.",
            "recommendation": "Keep up to date with official release channels."
        }

    return {
        "version": clean_version,
        "full_version": version_str.strip(),
        "status": "UNKNOWN",
        "vulnerable": False,
        "reason": f"Unrecognized version branch: {major}.{minor}",
        "recommendation": "Verify your PHP installation manually."
    }

def find_system_php_binaries() -> List[str]:
    """
    Search system PATH and standard directories for installed PHP binaries.
    """
    candidates = [
        "php", "php.exe", "php8.5", "php8.4", "php8.3", "php8.2", "php8.1", "php8.0", "php7.4",
        "php-fpm", "php-fpm.exe", "php-cgi", "php-cgi.exe"
    ]
    standard_paths = [
        "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin",
        "/usr/sbin", "/usr/local/sbin", "/opt/homebrew/sbin"
    ]
    if sys.platform == "win32":
        standard_paths.extend([
            r"C:\xampp\php",
            r"C:\laragon\bin\php",
            r"C:\php",
            r"C:\Program Files\PHP",
            r"C:\Program Files (x86)\PHP",
        ])
        laragon_php = r"C:\laragon\bin\php"
        if os.path.isdir(laragon_php):
            try:
                for sub in os.listdir(laragon_php):
                    standard_paths.append(os.path.join(laragon_php, sub))
            except Exception:
                pass

    found_bins = set()

    # Search PATH via 'which' or shutil.which
    import shutil
    for name in candidates:
        bin_path = shutil.which(name)
        if bin_path and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
            found_bins.add(os.path.realpath(bin_path))

    # Also search standard directory paths
    for base_dir in standard_paths:
        if os.path.isdir(base_dir):
            for name in candidates:
                p = os.path.join(base_dir, name)
                if os.path.isfile(p) and os.access(p, os.X_OK):
                    found_bins.add(os.path.realpath(p))

    return sorted(list(found_bins))

def query_binary_version(bin_path: str) -> Optional[str]:
    """
    Executes a binary with -v to capture the first line containing version details.
    """
    try:
        proc = subprocess.run(
            [bin_path, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        output = proc.stdout.strip() or proc.stderr.strip()
        for line in output.splitlines():
            if "PHP " in line:
                return line.strip()
    except Exception:
        pass
    return None

def check_running_services() -> List[Dict[str, str]]:
    """
    Checks running processes for PHP-FPM, Apache, Nginx, LiteSpeed, FrankenPHP.
    """
    services = []
    keywords = ["php-fpm", "apache2", "httpd", "nginx", "litespeed", "frankenphp", "caddy"]
    try:
        if sys.platform == "darwin" or sys.platform.startswith("linux"):
            ps_cmd = ["ps", "-eo", "pid,user,comm,args"]
            proc = subprocess.run(ps_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            for line in proc.stdout.splitlines():
                line_lower = line.lower()
                for kw in keywords:
                    if kw in line_lower:
                        parts = line.strip().split(maxsplit=3)
                        services.append({
                            "keyword": kw,
                            "pid": parts[0] if len(parts) > 0 else "?",
                            "user": parts[1] if len(parts) > 1 else "?",
                            "command": parts[3] if len(parts) > 3 else (parts[2] if len(parts) > 2 else line.strip())
                        })
                        break
        elif sys.platform == "win32":
            proc = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            for line in proc.stdout.splitlines():
                line_lower = line.lower()
                for kw in keywords:
                    if kw in line_lower:
                        parts = [col.strip(' "') for col in line.split(',')]
                        services.append({
                            "keyword": kw,
                            "pid": parts[1] if len(parts) > 1 else "?",
                            "user": "SYSTEM/USER",
                            "command": parts[0] if len(parts) > 0 else line.strip()
                        })
                        break
    except Exception:
        pass
    return services

def check_php_ini_mitigations() -> List[Dict[str, Any]]:
    """
    Checks active php.ini configurations for settings related to PHP2Shell vector mitigations.
    """
    mitigation_findings = []
    php_bin = shutil_which_php()
    if not php_bin:
        return mitigation_findings

    checks = [
        {
            "setting": "session.upload_progress.enabled",
            "description": "Upload progress tracking (CVE-2026-109619 vector)",
            "safe_val": "0",
            "advice": "Setting 'session.upload_progress.enabled = Off' mitigates stale memory/UAF triggers via upload state."
        },
        {
            "setting": "display_errors",
            "description": "Prevent exposing internal PHP runtime memory offsets/paths",
            "safe_val": "0",
            "advice": "Setting 'display_errors = Off' prevents leakage of sensitive worker memory in error states."
        }
    ]

    for item in checks:
        key = item["setting"]
        try:
            res = subprocess.run(
                [php_bin, "-r", f"echo ini_get('{key}');"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            val = res.stdout.strip()
            # In PHP, "1" or "On" is active; "0" or "" is disabled
            is_enabled = val in ["1", "On", "on", "true"]
            mitigation_findings.append({
                "setting": key,
                "current_value": val if val else "0 (Off)",
                "risk": "ATTENTION" if (key == "session.upload_progress.enabled" and is_enabled) else "OPTIMAL",
                "description": item["description"],
                "advice": item["advice"]
            })
        except Exception:
            pass

    return mitigation_findings

def shutil_which_php() -> Optional[str]:
    import shutil
    return shutil.which("php")

def scan_remote_url(target_url: str, check_endpoints: bool = True) -> Dict[str, Any]:
    """
    Passive remote banner probe to check exposed PHP versions via HTTP headers.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    results: Dict[str, Any] = {
        "target": target_url,
        "reachable": False,
        "headers_found": {},
        "php_version_detected": None,
        "evaluation": None,
        "exposed_files": []
    }

    # Relax SSL context for auditing legacy or self-signed internal endpoints
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        target_url,
        headers={"User-Agent": "PHP2Shell-Vulnerability-Audit-Scanner/1.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=8, context=ctx) as response:
            results["reachable"] = True
            headers = dict(response.info())
            results["headers_found"] = headers

            # Check X-Powered-By
            powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
            server_hdr = headers.get("Server") or headers.get("server")

            detected_ver = None
            if powered_by and "php" in powered_by.lower():
                detected_ver = powered_by
            elif server_hdr and "php" in server_hdr.lower():
                detected_ver = server_hdr

            if detected_ver:
                results["php_version_detected"] = detected_ver
                results["evaluation"] = evaluate_php_version(detected_ver)

    except urllib.error.HTTPError as e:
        results["reachable"] = True
        headers = dict(e.headers)
        results["headers_found"] = headers
        powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered_by and "php" in powered_by.lower():
            results["php_version_detected"] = powered_by
            results["evaluation"] = evaluate_php_version(powered_by)
    except Exception as e:
        results["error"] = str(e)
        return results

    # Optional sensitive info check
    if check_endpoints and results["reachable"]:
        sensitive_paths = ["/phpinfo.php", "/info.php", "/test.php", "/version.php"]
        base_url = target_url.rstrip("/")
        for path in sensitive_paths:
            test_url = base_url + path
            try:
                sub_req = urllib.request.Request(
                    test_url,
                    headers={"User-Agent": "PHP2Shell-Vulnerability-Audit-Scanner/1.0"}
                )
                with urllib.request.urlopen(sub_req, timeout=4, context=ctx) as sub_res:
                    if sub_res.status == 200:
                        body_sample = sub_res.read(2048).decode("utf-8", errors="ignore")
                        if "PHP Version" in body_sample or "phpinfo()" in body_sample:
                            results["exposed_files"].append(test_url)
                            # Extract version from phpinfo output if not found yet
                            m = re.search(r"PHP Version\s*([0-9]+\.[0-9]+\.[0-9]+)", body_sample)
                            if m and not results["php_version_detected"]:
                                results["php_version_detected"] = m.group(1)
                                results["evaluation"] = evaluate_php_version(m.group(1))
            except Exception:
                pass

    return results

def print_banner():
    banner = r"""
  ____  _   _ ____ ____  ____  _          _ _ 
 |  _ \| | | |  _ \___ \/ ___|| |__   ___| | |
 | |_) | |_| | |_) |__) \___ \| '_ \ / _ \ | |
 |  __/|  _  |  __// __/ ___) | | | |  __/ | |
 |_|   |_| |_|_|  |_____|____/|_| |_|\___|_|_|
   Audit & Vulnerability Detection Scanner
   References: CVE-2026-109618 | CVE-2026-109619
    """
    print(colorize(banner, Colors.CYAN))

def run_local_audit(use_color: bool = True) -> Dict[str, Any]:
    print(colorize("\n[*] BẮT ĐẦU QUÉT HỆ THỐNG CỤC BỘ (LOCAL SYSTEM AUDIT)...", Colors.BOLD, use_color))
    report: Dict[str, Any] = {
        "binaries_detected": [],
        "running_services": [],
        "ini_mitigations": [],
        "is_system_vulnerable": False
    }

    # 1. Discover PHP binaries
    php_bins = find_system_php_binaries()
    if not php_bins:
        print(colorize("[-] Không tìm thấy file nhị phân PHP nào trong PATH hoặc các thư mục chuẩn.", Colors.YELLOW, use_color))
    else:
        print(colorize(f"[+] Tìm thấy {len(php_bins)} file thực thi PHP:", Colors.GREEN, use_color))
        for b in php_bins:
            v_str = query_binary_version(b)
            if v_str:
                eval_res = evaluate_php_version(v_str)
                report["binaries_detected"].append({
                    "path": b,
                    "raw_version": v_str,
                    "evaluation": eval_res
                })
                if eval_res.get("vulnerable"):
                    report["is_system_vulnerable"] = True
                    status_col = Colors.RED
                else:
                    status_col = Colors.GREEN

                print(f"    • {b} -> {v_str}")
                print(f"      Status: {colorize(eval_res['status'], status_col, use_color)}")
                print(f"      Chi tiết: {eval_res['reason']}")
                if eval_res.get("vulnerable"):
                    print(f"      {colorize('Khuyến nghị: ' + eval_res['recommendation'], Colors.YELLOW, use_color)}")

    # 2. Check running web and PHP services
    services = check_running_services()
    report["running_services"] = services
    if services:
        print(colorize(f"\n[+] Phát hiện các dịch vụ web/PHP đang hoạt động ({len(services)} tiến trình):", Colors.CYAN, use_color))
        for s in services[:10]:  # Limit display to top 10
            print(f"    • [PID {s['pid']}] User: {s['user']} | Service: {s['keyword']} -> {s['command'][:70]}")
        if len(services) > 10:
            print(f"    ... và {len(services) - 10} tiến trình khác.")
    else:
        print(colorize("\n[-] Không phát hiện tiến trình web server / PHP-FPM nào đang chạy.", Colors.BLUE, use_color))

    # 3. Check PHP.ini mitigations
    ini_checks = check_php_ini_mitigations()
    report["ini_mitigations"] = ini_checks
    if ini_checks:
        print(colorize("\n[+] Kiểm tra cấu hình php.ini (Phòng thủ / Giảm thiểu rủi ro):", Colors.CYAN, use_color))
        for m in ini_checks:
            tag = "[LƯU Ý]" if m["risk"] == "ATTENTION" else "[OK]"
            tag_col = Colors.YELLOW if m["risk"] == "ATTENTION" else Colors.GREEN
            print(f"    {colorize(tag, tag_col, use_color)} {m['setting']} = {m['current_value']}")
            print(f"       {m['advice']}")

    # Final verdict
    print("\n" + "="*70)
    if report["is_system_vulnerable"]:
        print(colorize("[NGUY CƠ CAO] HỆ THỐNG CỦA BẠN CHỨA PHIÊN BẢN PHP BỊ ẢNH HƯỞNG BỞI PHP2SHELL!", Colors.RED + Colors.BOLD, use_color))
        print(colorize("Hành động cần làm: Nâng cấp ngay lên phiên bản PHP an toàn hoặc áp dụng biện pháp phòng vệ.", Colors.YELLOW, use_color))
    elif not php_bins and not services:
        print(colorize("[AN TOÀN] Không phát hiện môi trường PHP hoặc web server nào trên máy này.", Colors.GREEN, use_color))
    else:
        print(colorize("[AN TOÀN] Các phiên bản PHP kiểm tra được đều đã được vá hoặc không thuộc dải nguy hiểm.", Colors.GREEN + Colors.BOLD, use_color))
    print("="*70)

    return report

def run_remote_audit(target_url: str, check_endpoints: bool = True, use_color: bool = True) -> Dict[str, Any]:
    print(colorize(f"\n[*] BẮT ĐẦU QUÉT TỪ XA TỚI TARGET: {target_url}", Colors.BOLD, use_color))
    res = scan_remote_url(target_url, check_endpoints=check_endpoints)

    if not res.get("reachable"):
        print(colorize(f"[-] Không thể kết nối tới mục tiêu: {res.get('error', 'Unknown network error')}", Colors.RED, use_color))
        return res

    print(colorize(f"[+] Kết nối thành công tới {target_url}", Colors.GREEN, use_color))
    
    headers = res.get("headers_found", {})
    if "Server" in headers:
        print(f"    • Server Header: {headers['Server']}")
    if "X-Powered-By" in headers:
        print(f"    • X-Powered-By: {headers['X-Powered-By']}")

    detected = res.get("php_version_detected")
    eval_res = res.get("evaluation")

    if detected and eval_res:
        print(colorize(f"\n[+] Phát hiện phiên bản PHP: {detected}", Colors.CYAN, use_color))
        status_col = Colors.RED if eval_res.get("vulnerable") else Colors.GREEN
        print(f"    • Trạng thái: {colorize(eval_res['status'], status_col, use_color)}")
        print(f"    • Đánh giá: {eval_res['reason']}")
        if eval_res.get("vulnerable"):
            print(f"    • {colorize('Khuyến nghị: ' + eval_res['recommendation'], Colors.YELLOW, use_color)}")
    else:
        print(colorize("\n[-] Không tìm thấy banner phiên bản PHP công khai qua HTTP headers thông thường.", Colors.YELLOW, use_color))
        print("    (Máy chủ có thể đã ẩn header 'X-Powered-By' và 'Server', đây là một cấu hình tốt).")

    exposed = res.get("exposed_files", [])
    if exposed:
        print(colorize("\n[CẢNH BÁO] Phát hiện tệp thông tin nhạy cảm công khai:", Colors.RED + Colors.BOLD, use_color))
        for url in exposed:
            print(f"    • {url}")
        print(colorize("    => Cần xóa hoặc bảo vệ tệp phpinfo/test để tránh lộ lọt cấu hình hệ thống!", Colors.YELLOW, use_color))

    return res

def main():
    parser = argparse.ArgumentParser(
        description="PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Security Scanner & Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ sử dụng:
  python3 php2shell_scanner.py --local
  python3 php2shell_scanner.py --url https://mywebsite.com
  python3 php2shell_scanner.py --check-version 8.3.12
  python3 php2shell_scanner.py --local --json
        """
    )

    parser.add_argument("--local", action="store_true", help="Quét và kiểm tra môi trường PHP trên máy chủ hiện tại")
    parser.add_argument("--url", type=str, help="Quét từ xa mục tiêu web URL (kiểm tra header và banner)")
    parser.add_argument("--file", "-f", type=str, help="Đọc danh sách các URL từ file để quét hàng loạt (mỗi dòng một URL)")
    parser.add_argument("--no-endpoints", action="store_true", help="Không thử tìm các file nhạy cảm như /phpinfo.php khi quét URL")
    parser.add_argument("--check-version", type=str, help="Kiểm tra trực tiếp một chuỗi phiên bản PHP (ví dụ: '8.3.20')")
    parser.add_argument("--json", action="store_true", help="Xuất kết quả dưới dạng JSON")
    parser.add_argument("--markdown", action="store_true", help="Xuất báo cáo tổng hợp dưới dạng Markdown")
    parser.add_argument("--no-color", action="store_true", help="Tắt màu sắc terminal")

    args = parser.parse_args()
    use_color = not args.no_color and not args.json and not args.markdown

    if not args.json and not args.markdown:
        print_banner()

    if args.check_version:
        res = evaluate_php_version(args.check_version)
        if args.json:
            print(json.dumps(res, indent=2))
        elif args.markdown:
            print(f"| Phiên bản | Trạng thái | Đánh giá | Khuyến nghị |")
            print(f"| :--- | :--- | :--- | :--- |")
            print(f"| `{args.check_version}` | **{res['status']}** | {res['reason']} | {res.get('recommendation', 'N/A')} |")
        else:
            status_col = Colors.RED if res.get("vulnerable") else Colors.GREEN
            print(f"Phiên bản: {args.check_version}")
            print(f"Trạng thái: {colorize(res['status'], status_col, use_color)}")
            print(f"Giải thích: {res['reason']}")
            if res.get("recommendation"):
                print(f"Khuyến nghị: {colorize(res['recommendation'], Colors.YELLOW, use_color)}")
        return

    if args.file:
        if not os.path.isfile(args.file):
            print(colorize(f"[-] Không tìm thấy file: {args.file}", Colors.RED, use_color))
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        
        if not args.json and not args.markdown:
            print(colorize(f"[*] Đọc thấy {len(targets)} targets từ {args.file}...", Colors.BOLD, use_color))

        batch_reports = []
        for t in targets:
            rep = scan_remote_url(t, check_endpoints=(not args.no_endpoints))
            batch_reports.append(rep)
            if not args.json and not args.markdown:
                eval_res = rep.get("evaluation")
                if rep.get("reachable"):
                    det = rep.get("php_version_detected") or "Hidden / Not detected"
                    st = eval_res["status"] if eval_res else "INFO_ONLY"
                    col = Colors.RED if (eval_res and eval_res.get("vulnerable")) else Colors.GREEN
                    print(f"  • {t:<35} | PHP: {det:<20} | {colorize(st, col, use_color)}")
                else:
                    print(f"  • {t:<35} | {colorize('Unreachable', Colors.YELLOW, use_color)}")

        if args.json:
            print(json.dumps(batch_reports, indent=2))
        elif args.markdown:
            print(f"# Báo cáo quét hàng loạt ({len(targets)} mục tiêu)\n")
            print("| Target URL | Trạng thái | Phiên bản PHP phát hiện | Đánh giá |")
            print("| :--- | :--- | :--- | :--- |")
            for rep in batch_reports:
                tgt = rep.get("target")
                if not rep.get("reachable"):
                    print(f"| `{tgt}` | Không thể kết nối | - | Kiểm tra lại kết nối mạng |")
                else:
                    det = rep.get("php_version_detected") or "Ẩn (Không lộ)"
                    ev = rep.get("evaluation")
                    st = ev["status"] if ev else "Không xác định"
                    rec = ev["recommendation"] if ev and ev.get("vulnerable") else "Bình thường"
                    print(f"| `{tgt}` | **{st}** | `{det}` | {rec} |")
        return

    if args.url:
        report = run_remote_audit(args.url, check_endpoints=(not args.no_endpoints), use_color=use_color)
        if args.json:
            print(json.dumps(report, indent=2))
        elif args.markdown:
            print(f"# Báo cáo rà soát mục tiêu: {report.get('target')}\n")
            ev = report.get("evaluation")
            st = ev["status"] if ev else "Không phát hiện banner"
            print(f"- **Target:** `{report.get('target')}`")
            print(f"- **Khả năng kết nối:** {'Thành công' if report.get('reachable') else 'Thất bại'}")
            print(f"- **PHP Version:** `{report.get('php_version_detected', 'N/A')}`")
            print(f"- **Kết luận:** **{st}**")
            if ev and ev.get("vulnerable"):
                print(f"- **Khuyến nghị khẩn cấp:** {ev.get('recommendation')}")
        return

    # Default to --local if no flags provided or --local is set
    report = run_local_audit(use_color=use_color)
    if args.json:
        print(json.dumps(report, indent=2))
    elif args.markdown:
        print(f"# Báo cáo kiểm tra an toàn hệ thống cục bộ (Local Host)\n")
        print(f"- **Thời điểm kiểm tra:** `{report.get('timestamp', 'N/A')}`")
        print(f"- **Trạng thái tổng thể:** **{'CÓ NGUY CƠ CAO (VULNERABLE)' if report.get('is_system_vulnerable') else 'AN TOÀN (PATCHED/SECURE)'}**")
        print(f"\n### Danh sách PHP Binaries")
        if not report.get("binaries_detected"):
            print("Không tìm thấy file nhị phân PHP nào.")
        else:
            for b in report["binaries_detected"]:
                ev = b["evaluation"]
                print(f"- `{b['path']}`: **{ev['status']}** ({b['raw_version']})")


if __name__ == "__main__":
    main()
