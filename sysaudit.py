import argparse
import collections
import fnmatch
import json
import logging
import os
import stat
import sys
import yaml
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

    # FIX: Accept BOTH --config and --config-path, routing both to args.config
    parser.add_argument(
        "--config", "--config-path", 
        dest="config", 
        type=str, 
        default=None, 
        help="Path to YAML configuration file for scoped target auditing."
    )

    # Keep these for backward compatibility
    parser.add_argument("--path", type=str, default=".", help="Directory to recursively scan for unsafe files.")
    parser.add_argument("--threshold", type=int, default=90, help="Disk usage warning threshold percentage.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")
    parser.add_argument("--exclude", nargs="*", default=[], help="Path globs to exclude from permission scans.")
    parser.add_argument("--max-findings", type=int, default=20, help="Maximum number of findings to display in text mode.")
    parser.add_argument("--only-failures", action="store_true", help="Print only the security findings summary and skip process/disk sections in text mode.")

    args = parser.parse_args()
    return args


def _should_ignore(path: str, relative_path: str, ignore_patterns: list[str]) -> bool:
    if not ignore_patterns:
        return False
    return any(fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(path, pattern) for pattern in ignore_patterns)


def check_permissions(base_path: str, max_depth=None, ignore_patterns=None, alert_on_permissive=True, exclude_patterns=None) -> list:
    """
    Scans a directory path for unsafe file configurations while respecting 
    scoped filters like max recursion depth and pattern exclusions.
    """
    unsafe_files = []
    base_path = os.path.expanduser(base_path)
    ignore_patterns = list(ignore_patterns or [])
    exclude_patterns = list(exclude_patterns or [])
    default_excludes = [".git/*", "node_modules/*", "__pycache__/*", ".venv/*", ".cache/*", "build/*", "dist/*", "vendor/*"]
    ignore_patterns = ignore_patterns + default_excludes + exclude_patterns
    
    # Calculate base depth to track relative subdirectory levels
    base_depth = base_path.rstrip(os.sep).count(os.sep)

    for root, dirs, files in os.walk(base_path):
        current_depth = root.count(os.sep) - base_depth
        if max_depth is not None and current_depth >= max_depth:
            dirs.clear()

        dirs[:] = [d for d in dirs if not _should_ignore(os.path.join(root, d), os.path.relpath(os.path.join(root, d), base_path), ignore_patterns)]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, base_path)

            if _should_ignore(filepath, rel_path, ignore_patterns):
                continue

            try:
                stat_info = os.stat(filepath)
                mode = stat_info.st_mode
                is_unsafe = False
                if alert_on_permissive:
                    if (mode & 0o002) or ((mode & 0o777) in (0o777, 0o666)):
                        is_unsafe = True
                else:
                    if (mode & 0o002):
                        is_unsafe = True

                if is_unsafe:
                    unsafe_files.append({
                        "path": filepath,
                        "permissions": oct(mode & 0o777),
                        "size": stat_info.st_size
                    })
            except (PermissionError, FileNotFoundError):
                continue

    return unsafe_files

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

def build_summary(unsafe_files: list[dict], disk_warnings: list[dict]) -> dict:
    counts = collections.Counter(file.get("permissions", "unknown") for file in unsafe_files)
    return {
        "total_findings": len(unsafe_files),
        "high_risk_findings": sum(1 for file in unsafe_files if file.get("permissions") in {"0o777", "0o666"}),
        "permission_breakdown": dict(counts),
        "disk_warning_count": len(disk_warnings),
    }


def render_text(report: dict, max_findings: int = 20, only_failures: bool = False):
    """Prints a clean terminal interface for operators."""
    print("\n" + "=" * 50)
    print(f"📋 SYSTEM AUDIT REPORT -- {report['timestamp']}")
    print("=" * 50)

    summary = report.get("summary", {})
    print("\n📊 [SUMMARY]")
    print(f"  Findings: {summary.get('total_findings', 0)}")
    print(f"  High-risk findings: {summary.get('high_risk_findings', 0)}")
    if summary.get("permission_breakdown"):
        breakdown = ", ".join(f"{perm}={count}" for perm, count in summary["permission_breakdown"].items())
        print(f"  Permission breakdown: {breakdown}")
    print(f"  Disk warnings: {summary.get('disk_warning_count', 0)}")

    print("\n🔒 [SECURITY: WORLD-WRITABLE FILES]")
    if report["unsafe_files"]:
        display_files = report["unsafe_files"][:max_findings]
        for file in display_files:
            path = file.get("path") or file.get("file") or "<unknown>"
            permissions = file.get("permissions", "unknown")
            size = file.get("size", "unknown")
            print(f"  ❌ FAIL: {path} (Perms: {permissions}, Size: {size})")
        if len(report["unsafe_files"]) > max_findings:
            print(f"  ... {len(report['unsafe_files']) - max_findings} more findings omitted")
    else:
        print("  ✅ PASS: No world-writable files discovered.")

    if not only_failures:
        print("\n💾 [STORAGE: PARTITION INTEGRITY]")
        if report["disk_warnings"]:
            for disk in report["disk_warnings"]:
                print(f"  ❌ ALARM: {disk['mount_point']} ({disk['device']}) is {disk['percent_used']}% full! "
                      f"({disk['used_gb']}GB / {disk['total_gb']}GB)")
        else:
            print("  ✅ PASS: All disk partitions are within safe limits.")

        print("\n🔥 [RESOURCE MONITOR: TOP 5 PROCESSES]")
        for i, proc in enumerate(report["top_processes"], 1):
            print(f"  {i}. {proc['name']} (PID: {proc['pid']}) -> CPU: {proc['cpu_percent']}% | RAM: {proc['memory_percent']}%")

    print("\n" + "=" * 50)


def main():
    import sys
    with open("/tmp/audit_args.log", "w") as f:
        f.write(" ".join(sys.argv))
    # ---------------------------------------

    
    args = parse_cli_arguments()
    
    # Initialize containers for aggregated results
    unsafe_files = []
    disk_threshold = args.threshold
    
    # ----------------------------------------------------------------------
    # Mode 1: Multi-Target Configuration File Execution
    # ----------------------------------------------------------------------
    if args.config:
        if not os.path.exists(args.config):
            err_msg = f"Error: Configuration file context not found at {args.config}"
            if args.json:
                print(json.dumps({"error": err_msg, "audit_passed": False}))
            else:
                print(err_msg, file=sys.stderr)
            sys.exit(2)

        try:
            with open(args.config, "r") as f:
                config_data = yaml.safe_load(f) or {}
            
            targets = config_data.get("targets", [])
            for target in targets:
                # Extract customized tracking specifications per target block
                if isinstance(target, dict):
                    path_str = target.get("path")
                    max_depth = target.get("max_depth")
                    ignore_patterns = target.get("ignore_patterns", [])
                    alert_on_permissive = target.get("alert_on_permissive", True)
                else:
                    # Fallback structural defaults if a flat string path is used
                    path_str = target
                    max_depth = None
                    ignore_patterns = []
                    alert_on_permissive = True
                
                if path_str:
                    expanded_path = os.path.expanduser(path_str)
                    if os.path.exists(expanded_path):
                        # Run the newly optimized advanced permissions scan
                        findings = check_permissions(
                            base_path=expanded_path,
                            max_depth=max_depth,
                            ignore_patterns=ignore_patterns,
                            alert_on_permissive=alert_on_permissive,
                            exclude_patterns=args.exclude,
                        )
                        unsafe_files.extend(findings)
                        
        except Exception as e:
            err_msg = f"Error processing YAML configuration profile: {e}"
            if args.json:
                print(json.dumps({"error": err_msg, "audit_passed": False}))
            else:
                print(err_msg, file=sys.stderr)
            sys.exit(2)

    # ----------------------------------------------------------------------
    # Mode 2: Backward-Compatible Single Path Fallback
    # ----------------------------------------------------------------------
    else:
        unsafe_files = check_permissions(args.path, exclude_patterns=args.exclude)
    
    # Global system indicators remain consistent across both execution types
    top_procs = check_processes(limit=5)
    disk_warnings = check_disk(disk_threshold)
    report_summary = build_summary(unsafe_files, disk_warnings)
    
    # Aggregate into a single state report
    report = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "unsafe_files": unsafe_files,
        "top_processes": top_procs,
        "disk_warnings": disk_warnings,
        "summary": report_summary,
        "audit_passed": len(unsafe_files) == 0 and len(disk_warnings) == 0
    }
    
    # Render Output
    if args.json:
        # Machine-readable output (stdout captured by fleetaudit.py)
        print(json.dumps(report, indent=2))
    else:
        # Human-friendly logging and printing
        render_text(report, max_findings=args.max_findings, only_failures=args.only_failures)
        
    # Exit code implementation:
    if not report["audit_passed"]:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()