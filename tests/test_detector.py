"""
Unit tests for the Sentinel persistence change detector and scanner.
Uses Python's standard unittest library (zero external dependencies).
"""

import os
import sys
import unittest
import tempfile
import shutil

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sentinel.rules import PersistenceVector
from sentinel.scanner import PersistenceScanner
from sentinel.baseline import BaselineManager
from sentinel.detector import ChangeDetector


class TestSentinelDetector(unittest.TestCase):

    def setUp(self):
        """Create a temporary sandbox mock environment for isolated testing."""
        self.temp_dir = tempfile.mkdtemp(prefix="sentinel_test_")
        self.mock_etc = os.path.join(self.temp_dir, "etc")
        os.makedirs(self.mock_etc, exist_ok=True)

        # Create a sample crontab in sandbox
        self.crontab_path = os.path.join(self.mock_etc, "crontab")
        with open(self.crontab_path, "w", encoding="utf-8") as f:
            f.write("# Clean baseline crontab\n17 * * * * root /bin/sample_hourly\n")

        # Define minimal test vectors
        self.vectors = [
            PersistenceVector(
                id="cron_system",
                name="System Crontab",
                path_pattern="/etc/crontab",
                mitre_id="T1053.003",
                mitre_name="Scheduled Task/Job: Cron",
                severity="HIGH",
                description="Central crontab file",
            ),
            PersistenceVector(
                id="cron_d",
                name="Cron Drop-in",
                path_pattern="/etc/cron.d",
                mitre_id="T1053.003",
                mitre_name="Scheduled Task/Job: Cron",
                severity="HIGH",
                description="Drop-in cron tasks",
                is_directory=True,
            ),
        ]

        self.baseline_path = os.path.join(self.temp_dir, "baseline.json")
        self.scanner = PersistenceScanner(vectors=self.vectors, root_dir=self.temp_dir)
        self.baseline_mgr = BaselineManager(baseline_path=self.baseline_path)

        # Generate and save baseline
        baseline_data = self.baseline_mgr.generate(self.scanner)
        self.baseline_mgr.save(baseline_data)
        self.baseline_items = baseline_data["items"]

    def tearDown(self):
        """Remove temporary sandbox."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_clean_scan_no_changes(self):
        """Test that a clean filesystem generates exactly zero change events."""
        current_items = self.scanner.scan_all()
        detector = ChangeDetector(self.baseline_items, is_demo=True)
        events = detector.detect(current_items)

        self.assertEqual(len(events), 0, "Clean scan should find 0 persistence changes.")

    def test_detect_modified_file(self):
        """Test detection of an unauthorized line added to an existing crontab."""
        # Modify the crontab
        with open(self.crontab_path, "a", encoding="utf-8") as f:
            f.write("0 2 * * * root /bin/unauthorized_script\n")

        current_items = self.scanner.scan_all()
        detector = ChangeDetector(self.baseline_items, is_demo=True)
        events = detector.detect(current_items)

        self.assertEqual(len(events), 1, "Should detect exactly 1 modified file.")
        event = events[0]
        self.assertEqual(event.change_type, "MODIFIED")
        self.assertEqual(event.virtual_path, "/etc/crontab")
        self.assertEqual(event.mitre_id, "T1053.003")
        self.assertEqual(event.severity, "HIGH")
        self.assertTrue(event.is_demo, "Event should be marked as demo.")
        self.assertIsNotNone(event.diff, "Diff should be generated for modified text.")
        self.assertIn("+0 2 * * * root /bin/unauthorized_script", event.diff)

    def test_detect_added_file(self):
        """Test detection of a newly created drop-in persistence file."""
        cron_d_dir = os.path.join(self.mock_etc, "cron.d")
        os.makedirs(cron_d_dir, exist_ok=True)
        new_file = os.path.join(cron_d_dir, "rogue_task")
        with open(new_file, "w", encoding="utf-8") as f:
            f.write("# Injected persistent task\n* * * * * root /tmp/malicious\n")

        current_items = self.scanner.scan_all()
        detector = ChangeDetector(self.baseline_items, is_demo=True)
        events = detector.detect(current_items)

        self.assertEqual(len(events), 1, "Should detect newly added file.")
        event = events[0]
        self.assertEqual(event.change_type, "ADDED")
        self.assertEqual(event.virtual_path, "/etc/cron.d/rogue_task")
        self.assertEqual(event.mitre_id, "T1053.003")
        self.assertIsNotNone(event.diff)
        self.assertIn("+* * * * * root /tmp/malicious", event.diff)

    def test_detect_deleted_file(self):
        """Test detection when an established persistence configuration is deleted."""
        os.remove(self.crontab_path)

        current_items = self.scanner.scan_all()
        detector = ChangeDetector(self.baseline_items, is_demo=True)
        events = detector.detect(current_items)

        self.assertEqual(len(events), 1, "Should detect removed file.")
        event = events[0]
        self.assertEqual(event.change_type, "DELETED")
        self.assertEqual(event.virtual_path, "/etc/crontab")


if __name__ == "__main__":
    unittest.main()
