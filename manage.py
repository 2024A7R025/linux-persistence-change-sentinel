"""
Sentinel Management CLI
Safe unified interface for baseline creation, persistence auditing,
harmless mock attack simulations, and dashboard launching.
"""

import os
import sys
import json
import argparse
from datetime import datetime, timezone

# Add project root to sys.path so 'sentinel' package can be imported directly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sentinel.scanner import PersistenceScanner
from sentinel.baseline import BaselineManager
from sentinel.detector import ChangeDetector
from sentinel.utils import colorize

# Reconfigure stdout for UTF-8 compatibility on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

MOCK_ROOT = os.path.join(BASE_DIR, "mock_linux")
DEFAULT_BASELINE = os.path.join(BASE_DIR, "baseline.json")
DEFAULT_EVENTS = os.path.join(BASE_DIR, "dashboard", "events.json")


def cmd_baseline(args):
    """Generates baseline snapshot of persistence files."""
    root_dir = args.root_dir or MOCK_ROOT
    baseline_path = args.baseline or DEFAULT_BASELINE

    print("\n" + "=" * 60)
    print("  [SENTINEL] GENERATING BASELINE SNAPSHOT")
    print("=" * 60)
    print(f"Target Root : {root_dir}")
    print(f"Target File : {baseline_path}")

    scanner = PersistenceScanner(root_dir=root_dir, cache_diff_content=True)
    manager = BaselineManager(baseline_path=baseline_path)

    data = manager.generate(scanner)
    manager.save(data)

    tracked_count = sum(1 for item in data["items"].values() if item.get("exists"))
    missing_count = sum(1 for item in data["items"].values() if not item.get("exists"))

    print(f"\n[+] Baseline created successfully!")
    print(f"    - Existing persistence items recorded: {tracked_count}")
    print(f"    - Potential vectors monitored (absent): {missing_count}")
    print(f"    - Integrity Checksum: {data['integrity_checksum'][:16]}...")
    print("=" * 60 + "\n")


def cmd_scan(args):
    """Scans current filesystem state and compares against saved baseline."""
    root_dir = args.root_dir or MOCK_ROOT
    baseline_path = args.baseline or DEFAULT_BASELINE
    events_path = args.output or DEFAULT_EVENTS

    print("\n" + "=" * 60)
    print("  [SENTINEL] AUDITING PERSISTENCE INTEGRITY")
    print("=" * 60)
    print(f"Target Root : {root_dir}")
    print(f"Baseline    : {baseline_path}")

    manager = BaselineManager(baseline_path=baseline_path)
    if not manager.exists():
        print(f"\n[!] Error: Baseline not found at {baseline_path}.")
        print("    Run 'python manage.py baseline' first to establish a clean state.\n")
        sys.exit(1)

    try:
        baseline_data = manager.load()
    except Exception as e:
        print(f"\n[!] Error loading baseline: {e}\n")
        sys.exit(1)

    scanner = PersistenceScanner(root_dir=root_dir, cache_diff_content=True)
    current_items = scanner.scan_all()

    detector = ChangeDetector(baseline_data.get("items", {}), is_demo=True)
    events = detector.detect(current_items)

    # Save to events.json for dashboard
    os.makedirs(os.path.dirname(events_path), exist_ok=True)
    events_payload = {
        "is_demo": True,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "summary": {
            "total": len(events),
            "critical": sum(1 for e in events if e.severity == "CRITICAL"),
            "high": sum(1 for e in events if e.severity == "HIGH"),
            "medium": sum(1 for e in events if e.severity == "MEDIUM"),
            "low": sum(1 for e in events if e.severity == "LOW"),
        },
        "events": [e.to_dict() for e in events]
    }

    with open(events_path, "w", encoding="utf-8") as f:
        json.dump(events_payload, f, indent=2)

    # Console output
    if not events:
        print("\n[OK] Audit Complete: 0 changes detected.")
        print("    Filesystem state matches baseline snapshot.")
    else:
        print(f"\n[!] Audit Complete: {len(events)} change(s) detected!\n")
        print(f"{'TYPE':<12} {'SEVERITY':<10} {'PATH':<35} {'MITRE ID':<12} {'DETAILS'}")
        print("-" * 90)
        for e in events:
            demo_tag = "[DEMO] " if e.is_demo else ""
            print(f"{demo_tag + e.change_type:<12} {e.severity:<10} {e.virtual_path:<35} {e.mitre_id:<12} {e.details}")
            if e.diff:
                print("    --- Diff Preview ---")
                for diff_line in e.diff.splitlines()[:5]:
                    print("    " + diff_line)
                if len(e.diff.splitlines()) > 5:
                    print("    ...")

    print("=" * 60)
    print(f"Results recorded to: {events_path}")
    print("View live in dashboard at: http://127.0.0.1:8080\n")


def cmd_simulate(args):
    """Safely simulates a persistence modification inside mock_linux only."""
    action = args.action
    print("\n" + "=" * 60)
    print("  [SIMULATION] SAFE TEST (MOCK_LINUX ONLY)")
    print("=" * 60)

    if action == "modify":
        crontab_path = os.path.join(MOCK_ROOT, "etc", "crontab")
        if not os.path.isfile(crontab_path):
            print(f"[!] Error: {crontab_path} does not exist.")
            return

        with open(crontab_path, "a", encoding="utf-8") as f:
            f.write("\n# [DEMO SIMULATION] Added benign persistence test entry\n")
            f.write("0 3 * * * root /bin/echo 'Simulated persistence check' > /dev/null\n")

        print("[+] Modified: mock_linux/etc/crontab")
        print("    Appended a harmless test comment and demo cron entry.")
        print("    Next: Run 'python manage.py scan' to test detection.")

    elif action == "add":
        cron_d_dir = os.path.join(MOCK_ROOT, "etc", "cron.d")
        os.makedirs(cron_d_dir, exist_ok=True)
        demo_file = os.path.join(cron_d_dir, "demo_backup")

        with open(demo_file, "w", encoding="utf-8") as f:
            f.write("# [DEMO SIMULATION] New cron drop-in file (harmless demonstration)\n")
            f.write("0 1 * * * root /bin/echo 'Sample drop-in'\n")

        print(f"[+] Added new file: mock_linux/etc/cron.d/demo_backup")
        print("    Created a harmless new persistence file.")
        print("    Next: Run 'python manage.py scan' to test detection.")

    elif action == "delete":
        service_path = os.path.join(MOCK_ROOT, "etc", "systemd", "system", "sample.service")
        if os.path.isfile(service_path):
            os.remove(service_path)
            print("[+] Removed: mock_linux/etc/systemd/system/sample.service")
            print("    Deleted sample service file to test deletion detection.")
            print("    Next: Run 'python manage.py scan' to test detection.")
        else:
            print("[!] sample.service does not exist to delete.")

    print("=" * 60 + "\n")


def cmd_reset(args):
    """Restores mock_linux to clean baseline state and clears event logs."""
    print("\n" + "=" * 60)
    print("  [RESET] RESTORING MOCK ENVIRONMENT")
    print("=" * 60)

    # 1. Restore baseline files if baseline.json exists
    if os.path.isfile(DEFAULT_BASELINE):
        with open(DEFAULT_BASELINE, "r", encoding="utf-8") as f:
            base_data = json.load(f)
        for path, item in base_data.get("items", {}).items():
            if item.get("exists") and item.get("content_cache") is not None:
                real_p = item.get("real_path")
                if real_p:
                    os.makedirs(os.path.dirname(real_p), exist_ok=True)
                    with open(real_p, "w", encoding="utf-8", newline="\n") as f:
                        f.write(item["content_cache"])

    # 2. Remove any added demo files in cron.d
    cron_demo = os.path.join(MOCK_ROOT, "etc", "cron.d", "demo_backup")
    if os.path.isfile(cron_demo):
        os.remove(cron_demo)

    # 3. Clear events.json
    empty_events = {
        "is_demo": True,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "total_events": 0,
        "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "events": []
    }
    with open(DEFAULT_EVENTS, "w", encoding="utf-8") as f:
        json.dump(empty_events, f, indent=2)

    print("[OK] mock_linux/ restored to clean default state.")
    print("[OK] dashboard/events.json reset to 0 events.")
    print("=" * 60 + "\n")


def cmd_dashboard(args):
    """Starts the web dashboard server on localhost:8080."""
    from dashboard.server import run_dashboard_server
    run_dashboard_server(host=args.host, port=args.port)


def main():
    parser = argparse.ArgumentParser(
        description="Linux Persistence Change Sentinel - Security Auditing Tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Baseline command
    p_base = subparsers.add_parser("baseline", help="Capture baseline of persistence vectors")
    p_base.add_argument("--root-dir", help="Root directory to scan (defaults to mock_linux)")
    p_base.add_argument("--baseline", help="Path to write baseline.json")

    # Scan command
    p_scan = subparsers.add_parser("scan", help="Scan and detect persistence changes")
    p_scan.add_argument("--root-dir", help="Root directory to scan (defaults to mock_linux)")
    p_scan.add_argument("--baseline", help="Path to baseline.json")
    p_scan.add_argument("--output", help="Path to save events.json for dashboard")

    # Simulate command
    p_sim = subparsers.add_parser("simulate", help="Simulate a harmless persistence change inside mock_linux")
    p_sim.add_argument("action", choices=["modify", "add", "delete"], help="Type of change to simulate")

    # Reset command
    subparsers.add_parser("reset", help="Restore mock_linux to pristine clean state")

    # Dashboard command
    p_dash = subparsers.add_parser("dashboard", help="Start local web dashboard")
    p_dash.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    p_dash.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    commands = {
        "baseline": cmd_baseline,
        "scan": cmd_scan,
        "simulate": cmd_simulate,
        "reset": cmd_reset,
        "dashboard": cmd_dashboard,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
