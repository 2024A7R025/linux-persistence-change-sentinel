"""
Change detection engine comparing current persistence state against baseline snapshots.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from sentinel.scanner import PersistenceItemSnapshot
from sentinel.utils import generate_diff

@dataclass
class DetectionEvent:
    virtual_path: str
    real_path: str
    change_type: str        # ADDED, MODIFIED, METADATA_CHANGED, DELETED
    vector_id: str
    vector_name: str
    mitre_id: str
    mitre_name: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    details: str
    is_demo: bool = True    # Explicitly marks events from mock/demo environment
    diff: Optional[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ChangeDetector:
    """
    Evaluates current persistence scan results against a baseline
    and produces structured security detection events without assuming
    every change is malicious.
    """

    def __init__(self, baseline_items: Dict[str, Any], is_demo: bool = True):
        self.baseline_items = baseline_items
        self.is_demo = is_demo

    def detect(self, current_items: Dict[str, PersistenceItemSnapshot]) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []

        # 1. Inspect all items in current scan
        for path, cur in current_items.items():
            base = self.baseline_items.get(path)

            if cur.exists:
                if base is None or not base.get("exists", False):
                    # Newly created persistence configuration
                    diff_text = generate_diff(
                        "",
                        cur.content_cache or "",
                        from_label="Baseline: (File did not exist)",
                        to_label=f"Current: {cur.virtual_path}"
                    ) if cur.content_cache else None

                    details = f"New persistence configuration file detected. SHA-256: {cur.sha256[:12]}..." if cur.sha256 else "New persistence configuration file detected."
                    
                    events.append(DetectionEvent(
                        virtual_path=cur.virtual_path,
                        real_path=cur.real_path,
                        change_type="ADDED",
                        vector_id=cur.vector_id,
                        vector_name=cur.vector_name,
                        mitre_id=cur.mitre_id,
                        mitre_name=cur.mitre_name,
                        severity=cur.severity,
                        details=details,
                        is_demo=self.is_demo,
                        diff=diff_text,
                    ))

                else:
                    # Item existed in baseline and still exists - check content hash
                    base_hash = base.get("sha256")
                    if cur.sha256 != base_hash:
                        diff_text = generate_diff(
                            base.get("content_cache") or "",
                            cur.content_cache or "",
                            from_label=f"Baseline: {cur.virtual_path}",
                            to_label=f"Current: {cur.virtual_path}"
                        ) if (base.get("content_cache") or cur.content_cache) else None

                        events.append(DetectionEvent(
                            virtual_path=cur.virtual_path,
                            real_path=cur.real_path,
                            change_type="MODIFIED",
                            vector_id=cur.vector_id,
                            vector_name=cur.vector_name,
                            mitre_id=cur.mitre_id,
                            mitre_name=cur.mitre_name,
                            severity=cur.severity,
                            details="Configuration content modified since baseline snapshot.",
                            is_demo=self.is_demo,
                            diff=diff_text,
                        ))

                    else:
                        # Check permissions / metadata changes
                        base_meta = base.get("metadata", {})
                        meta_changes = []

                        if base_meta.get("mode") != cur.metadata.get("mode"):
                            meta_changes.append(f"Permissions changed: {base_meta.get('mode')} -> {cur.metadata.get('mode')}")

                        if base_meta.get("owner") != cur.metadata.get("owner"):
                            meta_changes.append(f"Owner changed: {base_meta.get('owner')} -> {cur.metadata.get('owner')}")

                        if meta_changes:
                            events.append(DetectionEvent(
                                virtual_path=cur.virtual_path,
                                real_path=cur.real_path,
                                change_type="METADATA_CHANGED",
                                vector_id=cur.vector_id,
                                vector_name=cur.vector_name,
                                mitre_id=cur.mitre_id,
                                mitre_name=cur.mitre_name,
                                severity=cur.severity,
                                details="; ".join(meta_changes),
                                is_demo=self.is_demo,
                                diff=None,
                            ))

            else:
                if base and base.get("exists", False):
                    # Item existed in baseline but was removed
                    events.append(DetectionEvent(
                        virtual_path=cur.virtual_path,
                        real_path=cur.real_path,
                        change_type="DELETED",
                        vector_id=cur.vector_id,
                        vector_name=cur.vector_name,
                        mitre_id=cur.mitre_id,
                        mitre_name=cur.mitre_name,
                        severity=cur.severity,
                        details="Persistence configuration file was removed.",
                        is_demo=self.is_demo,
                        diff=None,
                    ))

        # 2. Check for any baseline items missing from current scan iteration entirely
        for base_path, base_item in self.baseline_items.items():
            if base_item.get("exists", False) and base_path not in current_items:
                events.append(DetectionEvent(
                    virtual_path=base_path,
                    real_path=base_item.get("real_path", base_path),
                    change_type="DELETED",
                    vector_id=base_item.get("vector_id", "unknown"),
                    vector_name=base_item.get("vector_name", "Unknown Vector"),
                    mitre_id=base_item.get("mitre_id", "T1053"),
                    mitre_name=base_item.get("mitre_name", "Persistence"),
                    severity=base_item.get("severity", "MEDIUM"),
                    details="Baseline configuration file is no longer present.",
                    is_demo=self.is_demo,
                    diff=None,
                ))

        return events
