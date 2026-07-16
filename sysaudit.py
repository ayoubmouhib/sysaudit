import argparse
import json
import logging
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Error: 'psutil' library is required. Install it using: pip install psutil", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def parse_cli_arguments():
    # Set up the argument parser
    parser = argparse.ArgumentParser(description="System Auditor CLI Tool - Checks permissions, processes, and disk usage.")

    # Define our flags
    parser.add_argument("--path", type=str, default=".", help="Directory to recursively scan for unsafe (world-writable) files.")
    parser.add_argument("--threshold", type=int, default=90, help="Disk usage warning threshold percentage (default: 90%%).")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format instead of human-readable text.")

    args = parser.parse_args()
    # print(f"Parsed arguments: {args}")
    return args


def check_permissions(search_path: str) -> list[dict]:
    """Recursively scans a path looking for world-writable (o+w) files."""
    findings = []
    base_path = Path(search_path)

    if not base_path.exists():
        logging.warning(f"Path does not exist: {search_path}")
        return findings
    
    for path in base_path.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                file_stat = path.stat()
                permissions = file_stat.st_mode

                if permissions & stat.S_IWOTH:
                    findings.append({
                        "file": str(path.resolve()),
                        "permissions": oct(permissions & 0o777),
                        "owner": path.owner() if hasattr(path, "owner") else "unknow"
                    })
        except PermissionError:
            continue
        except Exception as e:
            logging.debug(f"Error scanning {path}: {e}")
    
    return findings

def check_processes(limit=5) -> list[dict]:
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            info['cpu_percent'] = info['cpu_percent'] or 0.0
            info['memory_percent'] = round(info['memory_percent'] or 0.0, 2)
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    sorted_proc = sorted(processes, key=lambda p: (p['cpu_percent'], p['memory_percent']), reverse=True)

    return sorted_proc[:limit]


def check_disk(threshold_percent: int) -> list[dict]:
    """Checks all mounted disk partitions and flags any breaching the limit."""
    warnings = []
    
    # Get all mounted disk partitions (physical disks only)
    for partition in psutil.disk_partitions(all=False):
        # Skip read-only mount points or virtual loop devices to avoid noise
        if "loop" in partition.device or partition.mountpoint == "":
            continue
            
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            if usage.percent >= threshold_percent:
                warnings.append({
                    "device": partition.device,
                    "mount_point": partition.mountpoint,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "percent_used": usage.percent,
                    "threshold": threshold_percent
                })
        except (PermissionError, FileNotFoundError):
            # Some system-mounted partitions might restrict access
            continue
            
    return warnings

def render_text(report: dict):
    """Prints a clean, colorized (optional) terminal interface for operators."""
    print("\n" + "="*50)
    print(f"📋 SYSTEM AUDIT REPORT -- {report['timestamp']}")
    print("="*50)

    # 1. File permissions
    print("\n🔒 [SECURITY: WORLD-WRITABLE FILES]")
    if report["unsafe_files"]:
        for file in report["unsafe_files"]:
            print(f"  ❌ FAIL: {file['file']} (Perms: {file['permissions']}, Owner: {file['owner']})")
    else:
        print("  ✅ PASS: No world-writable files discovered.")

    # 2. Disk usage
    print("\n💾 [STORAGE: PARTITION INTEGRITY]")
    if report["disk_warnings"]:
        for disk in report["disk_warnings"]:
            print(f"  ❌ ALARM: {disk['mount_point']} ({disk['device']}) is {disk['percent_used']}% full! "
                  f"({disk['used_gb']}GB / {disk['total_gb']}GB)")
    else:
        print("  ✅ PASS: All disk partitions are within safe limits.")

    # 3. Process breakdown
    print("\n🔥 [RESOURCE MONITOR: TOP 5 PROCESSES]")
    for i, proc in enumerate(report["top_processes"], 1):
        print(f"  {i}. {proc['name']} (PID: {proc['pid']}) -> CPU: {proc['cpu_percent']}% | RAM: {proc['memory_percent']}%")

    print("\n" + "="*50)


def main():
    args = parse_cli_arguments()
    
    # Gather metrics
    unsafe_files = check_permissions(args.path)
    top_procs = check_processes(limit=5)
    disk_warnings = check_disk(args.threshold)
    
    # Aggregate into a single state report
    report = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "unsafe_files": unsafe_files,
        "top_processes": top_procs,
        "disk_warnings": disk_warnings,
        "audit_passed": len(unsafe_files) == 0 and len(disk_warnings) == 0
    }
    
    # Render Output
    if args.json:
        # Machine-readable output (stdout)
        print(json.dumps(report, indent=2))
    else:
        # Human-friendly logging and printing
        render_text(report)
        
    # Exit code implementation:
    # Exit with 1 (Failure) if we found security risks or disk alarms, otherwise 0 (Success)
    if not report["audit_passed"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()