#!/usr/bin/env python3
"""
fleet_audit.py — Concurrent SSH Fleet Auditor

Pushes sysaudit.py to a fleet of remote Linux hosts over SSH (key-based auth
only), executes it remotely in --json mode, and aggregates the results into
a single fleet-wide report with a summary and a non-zero exit code if any
host is unreachable, fails auth, errors out, or fails its audit.

Usage:
    python3 fleet_audit.py --inventory hosts.txt --ssh-user ops \
        --key-path ~/.ssh/id_ed25519 --remote-path /var/www --workers 10 \
        --output fleet_report.json
"""

import argparse
import json
import logging
import shlex
import socket
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

try:
    import paramiko
except ImportError:
    print("Error: 'paramiko' is required. Install it using: pip install paramiko", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("fleet_audit")

REMOTE_SCRIPT_NAME = "sysaudit.py"


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class HostResult:
    ip: str
    status: str                      # ONLINE | OFFLINE | AUTH_FAILED | EXECUTION_ERROR
    success: bool
    audit: Optional[dict] = None     # parsed JSON report from sysaudit.py, if any
    error: Optional[str] = None
    raw_stderr: Optional[str] = None


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_cli_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fleet Auditor — runs sysaudit.py across many servers over SSH (key-based auth only)."
    )
    parser.add_argument("--inventory", required=True, help="Path to a file with one host/IP per line.")
    parser.add_argument("--ssh-user", required=True, help="SSH username used to connect to every host.")
    parser.add_argument("--key-path", required=True, help="Path to the private SSH key (e.g. ~/.ssh/id_ed25519).")
    parser.add_argument("--local-script", default="sysaudit.py", help="Local path to sysaudit.py to push to each host.")
    
    # ADD THIS LINE (and remove --remote-path and --remote-threshold if you no longer use them):
    parser.add_argument("--config-path", default="auditor_config.yaml", help="Local path to the YAML configuration file.")
    
    parser.add_argument("--workers", type=int, default=10, help="Max concurrent SSH connections (default: 10).")
    parser.add_argument("--timeout", type=int, default=8, help="Per-host SSH connect timeout in seconds.")
    parser.add_argument("--output", default="fleet_report.json", help="Path to write the aggregated JSON report.")
    return parser.parse_args()


def load_inventory(path: str) -> list[str]:
    """Reads one host/IP per line, ignoring blank lines and '#' comments."""
    inventory_path = Path(path)
    if not inventory_path.exists():
        log.error(f"Inventory file not found: {path}")
        sys.exit(1)

    hosts = []
    for line in inventory_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            hosts.append(line)

    if not hosts:
        log.error("Inventory file is empty — nothing to audit.")
        sys.exit(1)

    return hosts


# --------------------------------------------------------------------------
# Worker: runs once per host, in its own thread
# --------------------------------------------------------------------------

def run_remote_audit(
    ip: str,
    ssh_user: str,
    key_path: str,
    local_script_path: str,
    local_config_path: str,  # Changed argument
    timeout: int,
) -> HostResult:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    # Create unique temp paths for BOTH the script and the configuration payload
    run_id = uuid.uuid4().hex[:8]
    remote_script_path = f"/tmp/{REMOTE_SCRIPT_NAME}.{run_id}"
    remote_config_path = f"/tmp/auditor_config.yaml.{run_id}"
    sftp = None

    try:
        log.info(f"Connecting to {ip}...")
        client.connect(
            hostname=ip,
            username=ssh_user,
            key_filename=key_path,
            timeout=timeout,
        )

        # --- Push BOTH files via SFTP -------------------------------------
        sftp = client.open_sftp()
        sftp.put(local_script_path, remote_script_path)
        sftp.put(local_config_path, remote_config_path)  # Pushing the YAML file

        # --- Build and run the remote command safely -----------------------
        # Instead of parsing single paths, tell sysaudit.py to read the uploaded config
        command = " ".join([
            "python3",
            shlex.quote(remote_script_path),
            "--config", shlex.quote(remote_config_path),
            "--json",
        ])
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

        raw_out = stdout.read().decode("utf-8", errors="replace")
        raw_err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()

        if exit_code not in (0, 1):
            return HostResult(
                ip=ip, status="EXECUTION_ERROR", success=False,
                error=f"Remote script exited with unexpected code {exit_code}",
                raw_stderr=raw_err or None,
            )

        try:
            audit_report = json.loads(raw_out)
        except json.JSONDecodeError:
            return HostResult(
                ip=ip, status="EXECUTION_ERROR", success=False,
                error="Could not parse JSON output from remote script",
                raw_stderr=raw_err or None,
            )

        log.info(f"{ip} audited successfully (audit_passed={audit_report.get('audit_passed')})")
        return HostResult(
            ip=ip, status="ONLINE", success=bool(audit_report.get("audit_passed")),
            audit=audit_report,
        )

    except paramiko.AuthenticationException:
        return HostResult(ip=ip, status="AUTH_FAILED", success=False, error="SSH key was rejected by the host")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, paramiko.SSHException) as e:
        return HostResult(ip=ip, status="OFFLINE", success=False, error=f"Network error: {e}")
    except Exception as e:
        return HostResult(ip=ip, status="EXECUTION_ERROR", success=False, error=f"Unexpected error: {e}")

    finally:
        # --- Clean up BOTH temporary files from the remote server ----------
        if sftp is not None:
            for path in (remote_script_path, remote_config_path):
                try:
                    sftp.remove(path)
                except Exception:
                    pass
            sftp.close()
        client.close()


# --------------------------------------------------------------------------
# Coordinator: fans the worker out across the fleet
# --------------------------------------------------------------------------

def orchestrate(hosts: list[str], args: argparse.Namespace) -> dict[str, HostResult]:
    results: dict[str, HostResult] = {}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                run_remote_audit,
                ip, args.ssh_user, args.key_path, args.local_script,
                args.config_path, args.timeout,  # Passing config_path down
            ): ip
            for ip in hosts
        }

        for future in as_completed(futures):
            ip = futures[future]
            try:
                results[ip] = future.result()
            except Exception as e:
                results[ip] = HostResult(ip=ip, status="ORCHESTRATOR_ERROR", success=False, error=str(e))

    return results


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def render_fleet_summary(results: dict[str, HostResult]) -> bool:
    """Prints a human-readable summary. Returns True if the whole fleet is clean."""
    total = len(results)
    passed = sum(1 for r in results.values() if r.status == "ONLINE" and r.success)
    audit_failed = sum(1 for r in results.values() if r.status == "ONLINE" and not r.success)
    unreachable = sum(1 for r in results.values() if r.status == "OFFLINE")
    auth_failed = sum(1 for r in results.values() if r.status == "AUTH_FAILED")
    exec_errors = sum(1 for r in results.values() if r.status in ("EXECUTION_ERROR", "ORCHESTRATOR_ERROR"))

    print("\n" + "=" * 60)
    print(f"📋 FLEET AUDIT SUMMARY — {total} hosts")
    print("=" * 60)
    print(f"  ✅ Passed:            {passed}")
    print(f"  ❌ Failed audit:      {audit_failed}")
    print(f"  🔌 Unreachable:       {unreachable}")
    print(f"  🔑 Auth failed:       {auth_failed}")
    print(f"  💥 Execution errors:  {exec_errors}")
    print("=" * 60)

    for ip, r in sorted(results.items()):
        if r.status == "ONLINE" and r.success:
            continue  # keep the detail section focused on hosts needing attention
        print(f"  [{r.status}] {ip} — {r.error or 'see full report'}")

    print("=" * 60 + "\n")
    return audit_failed == 0 and unreachable == 0 and auth_failed == 0 and exec_errors == 0


def write_json_report(results: dict[str, HostResult], output_path: str) -> None:
    serializable = {ip: asdict(r) for ip, r in results.items()}
    Path(output_path).write_text(json.dumps(serializable, indent=2))
    log.info(f"Full report written to {output_path}")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main() -> None:
    args = parse_cli_arguments()

    if not Path(args.local_script).exists():
        log.error(f"Local script not found: {args.local_script}")
        sys.exit(1)

    # ADD THIS CHECK:
    if not Path(args.config_path).exists():
        log.error(f"Configuration file not found: {args.config_path}")
        sys.exit(1)

    hosts = load_inventory(args.inventory)
    log.info(f"Loaded {len(hosts)} hosts from {args.inventory}")

    results = orchestrate(hosts, args)
    write_json_report(results, args.output)
    fleet_clean = render_fleet_summary(results)

    sys.exit(0 if fleet_clean else 1)

if __name__ == "__main__":
    main()