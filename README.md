# Local System Auditor (sysaudit.py)

A lightweight, CLI system auditing utility written in Python. Designed for automated system administration, cron execution, and security verification.

## 🚀 Features
- **Security Check:** Recursively scans a targeted directory for unsafe, world-writable (`o+w`) files.
- **Resource Monitoring:** Grabs and lists the top 5 CPU/Memory consuming processes using `psutil`.
- **Disk Integrity:** Monitors mounted storage partitions and alerts if any partitions exceed a customizable threshold limit (default: 90%).
- **Automation Ready:** Outputs results in standard human-readable format or structured JSON. Exits with a non-zero status code (`1`) on system warnings for easy integration with monitoring systems or CI/CD pipelines.

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/sysaudit.git](https://github.com/ayoubmouhib/sysaudit.git)
   cd sysaudit