"""
Filesystem scanner that audits Linux persistence locations and captures their state.
"""

import os
import glob
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

from sentinel.rules import PersistenceVector, DEFAULT_VECTORS
from sentinel.utils import (
    compute_sha256,
    get_file_metadata,
    read_text_safe,
    resolve_system_root,
    discover_user_homes,
)

@dataclass
class PersistenceItemSnapshot:
    virtual_path: str         # The standard Linux path, e.g. /etc/crontab
    real_path: str            # Physical filesystem path (with root_prefix applied)
    vector_id: str            # ID of the matched PersistenceVector
    vector_name: str
    mitre_id: str
    mitre_name: str
    severity: str
    exists: bool
    sha256: Optional[str]
    metadata: Dict[str, Any]
    content_cache: Optional[str] = None  # Cached text for computing unified diffs later

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PersistenceScanner:
    """
    Scans system and user-space persistence vectors based on configured rules.
    Supports a custom root_dir for mock testing environments.
    """

    def __init__(
        self,
        vectors: Optional[List[PersistenceVector]] = None,
        root_dir: Optional[str] = None,
        cache_diff_content: bool = True,
        max_cache_bytes: int = 128 * 1024,  # Cache up to 128KB per text file
    ):
        self.vectors = vectors if vectors is not None else DEFAULT_VECTORS
        self.root_dir = os.path.abspath(root_dir) if root_dir else None
        self.cache_diff_content = cache_diff_content
        self.max_cache_bytes = max_cache_bytes

    def _normalize_virtual_path(self, physical_path: str) -> str:
        """
        Converts a physical path back to standard Linux virtual path (e.g. /etc/crontab).
        """
        if self.root_dir:
            # Strip root_dir prefix
            rel = os.path.relpath(physical_path, self.root_dir)
            clean = "/" + rel.replace("\\", "/").lstrip("./")
            return clean
        clean = physical_path.replace("\\", "/")
        if not clean.startswith("/"):
            clean = "/" + clean
        return clean

    def scan_single_file(self, real_path: str, vector: PersistenceVector, custom_virtual_path: Optional[str] = None) -> PersistenceItemSnapshot:
        """
        Takes a snapshot of a single file's state.
        """
        virtual_path = custom_virtual_path or self._normalize_virtual_path(real_path)
        exists = os.path.exists(real_path) or os.path.islink(real_path)
        
        if not exists:
            return PersistenceItemSnapshot(
                virtual_path=virtual_path,
                real_path=real_path,
                vector_id=vector.id,
                vector_name=vector.name,
                mitre_id=vector.mitre_id,
                mitre_name=vector.mitre_name,
                severity=vector.severity,
                exists=False,
                sha256=None,
                metadata={},
                content_cache=None,
            )

        meta = get_file_metadata(real_path)
        file_hash = compute_sha256(real_path) if not meta.get("is_symlink") else None
        
        content = None
        if self.cache_diff_content and not meta.get("is_symlink"):
            content = read_text_safe(real_path, max_bytes=self.max_cache_bytes)

        return PersistenceItemSnapshot(
            virtual_path=virtual_path,
            real_path=real_path,
            vector_id=vector.id,
            vector_name=vector.name,
            mitre_id=vector.mitre_id,
            mitre_name=vector.mitre_name,
            severity=vector.severity,
            exists=True,
            sha256=file_hash,
            metadata=meta,
            content_cache=content,
        )

    def scan_directory(self, dir_real_path: str, vector: PersistenceVector, recursive: bool = False) -> List[PersistenceItemSnapshot]:
        """
        Scans all files inside a directory.
        """
        snapshots = []
        if not os.path.isdir(dir_real_path):
            return snapshots

        try:
            if recursive:
                for root, _, files in os.walk(dir_real_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        snapshots.append(self.scan_single_file(full_path, vector))
            else:
                for entry in os.scandir(dir_real_path):
                    if entry.is_file() or entry.is_symlink():
                        snapshots.append(self.scan_single_file(entry.path, vector))
        except (OSError, PermissionError):
            pass

        return snapshots

    def scan_all(self) -> Dict[str, PersistenceItemSnapshot]:
        """
        Runs a complete persistence scan across all configured vectors.
        Returns a dictionary keyed by virtual_path.
        """
        results: Dict[str, PersistenceItemSnapshot] = {}

        # 1. User-relative persistence (e.g. ~/.bashrc, ~/.ssh/authorized_keys)
        user_homes = discover_user_homes(self.root_dir)
        user_vectors = [v for v in self.vectors if v.is_user_relative]
        
        for username, home_path in user_homes:
            for vector in user_vectors:
                target_path = os.path.join(home_path, vector.path_pattern.replace("/", os.sep))
                
                if vector.is_directory:
                    if os.path.isdir(target_path):
                        dir_snaps = self.scan_directory(target_path, vector, recursive=vector.recursive)
                        for snap in dir_snaps:
                            results[snap.virtual_path] = snap
                else:
                    snap = self.scan_single_file(target_path, vector)
                    # We record it even if not exists, so we detect creation later
                    results[snap.virtual_path] = snap

        # 2. System-wide persistence vectors
        system_vectors = [v for v in self.vectors if not v.is_user_relative]
        for vector in system_vectors:
            # Check for glob pattern (e.g. /etc/cron.*)
            if "*" in vector.path_pattern or "?" in vector.path_pattern:
                resolved_glob = resolve_system_root(vector.path_pattern, self.root_dir)
                for matched_path in glob.glob(resolved_glob):
                    if os.path.isdir(matched_path):
                        dir_snaps = self.scan_directory(matched_path, vector, recursive=vector.recursive)
                        for snap in dir_snaps:
                            results[snap.virtual_path] = snap
                    elif os.path.isfile(matched_path):
                        snap = self.scan_single_file(matched_path, vector)
                        results[snap.virtual_path] = snap
                continue

            real_target = resolve_system_root(vector.path_pattern, self.root_dir)
            
            if vector.is_directory:
                if os.path.isdir(real_target):
                    dir_snaps = self.scan_directory(real_target, vector, recursive=vector.recursive)
                    for snap in dir_snaps:
                        results[snap.virtual_path] = snap
            else:
                snap = self.scan_single_file(real_target, vector)
                results[snap.virtual_path] = snap

        return results
