# Dockerfile for PHP2Shell Scanner
FROM python:3.12-alpine

LABEL maintainer="Antigravity Security Research"
LABEL description="Audit & Vulnerability Detection Scanner for PHP2Shell (CVE-2026-109618 & CVE-2026-109619)"

WORKDIR /app

# Copy scanner script and example target list
COPY php2shell_scanner.py /app/php2shell_scanner.py
COPY targets.example.txt /app/targets.example.txt

# Set permissions
RUN chmod +x /app/php2shell_scanner.py

ENTRYPOINT ["python3", "/app/php2shell_scanner.py"]
CMD ["--help"]
