"""
Baseline management: creating, saving, loading, and updating persistence baselines.
"""

import os
import json
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from sentinel.scanner import PersistenceItemSnapshot, PersistenceScanner

class BaselineManager:
    """
    Manages persistence baseline creation, persistence to disk, and integrity validation.
    """

    def __init__(self, baseline_path: str):
        self.baseline_path = os.path.abspath(baseline_path)

    def generate(self, scanner: PersistenceScanner) -> Dict[str, Any]:
        """
        Scans current state and generates baseline dictionary.
        """
        snapshots = scanner.scan_all()
        items_dict = {path: snap.to_dict() for path, snap in snapshots.items()}

        hostname = socket.gethostname()
        created_at = datetime.now(timezone.utc).isoformat()

        baseline_data = {
            "version": "1.0.0",
            "created_at": created_at,
            "hostname": hostname,
            "root_dir": scanner.root_dir,
            "total_items": len(items_dict),
            "items": items_dict,
        }

        # Calculate checksum over normalized items JSON to detect baseline tampering
        content_to_sign = json.dumps(items_dict, sort_keys=True).encode("utf-8")
        baseline_data["integrity_checksum"] = hashlib.sha256(content_to_sign).hexdigest()

        return baseline_data

    def save(self, baseline_data: Dict[str, Any]) -> str:
        """
        Writes baseline data to disk atomically with restricted permissions.
        """
        parent_dir = os.path.dirname(self.baseline_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        temp_path = self.baseline_path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=2)

        # On POSIX systems, chmod 600 so unprivileged users cannot read or modify
        if hasattr(os, "chmod"):
            try:
                os.chmod(temp_path, 0o600)
            except Exception:
                pass

        # Atomic replace
        if os.path.exists(self.baseline_path):
            os.replace(temp_path, self.baseline_path)
        else:
            os.rename(temp_path, self.baseline_path)

        return self.baseline_path

    def load(self) -> Dict[str, Any]:
        """
        Loads baseline from disk and verifies integrity checksum.
        """
        if not os.path.isfile(self.baseline_path):
            raise FileNotFoundError(f"Baseline file not found at: {self.baseline_path}")

        with open(self.baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Integrity check
        items = data.get("items", {})
        expected_hash = data.get("integrity_checksum")
        if expected_hash:
            calculated_hash = hashlib.sha256(json.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()
            if calculated_hash != expected_hash:
                raise ValueError("CRITICAL: Baseline file integrity check failed! The baseline has been tampered with or corrupted.")

        return data

    def exists(self) -> bool:
        return os.path.isfile(self.baseline_path)

    def update_specific_items(self, approved_virtual_paths: List[str], scanner: PersistenceScanner) -> Dict[str, Any]:
        """
        Updates specific paths in the baseline (e.g. after authorized administrative change).
        """
        current_baseline = self.load()
        items = current_baseline.get("items", {})

        current_scan = scanner.scan_all()
        for path in approved_virtual_paths:
            if path in current_scan:
                items[path] = current_scan[path].to_dict()
            elif path in items:
                # If deleted and approved, remove from baseline or mark non-existent
                items[path]["exists"] = False
                items[path]["sha256"] = None

        current_baseline["items"] = items
        current_baseline["total_items"] = len(items)
        current_baseline["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        # Recalculate checksum
        content_to_sign = json.dumps(items, sort_keys=True).encode("utf-8")
        current_baseline["integrity_checksum"] = hashlib.sha256(content_to_sign).hexdigest()

        self.save(current_baseline)
        return current_baseline
