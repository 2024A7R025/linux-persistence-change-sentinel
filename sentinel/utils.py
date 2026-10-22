"""
Cross-platform filesystem, hashing, metadata, and formatting utilities.
"""

import os
import sys
import hashlib
import difflib
import stat
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

# Terminal color escape codes
COLORS = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "BG_RED": "\033[41m",
}

def colorize(text: str, color_key: str, enabled: bool = True) -> str:
    """Apply ANSI color codes if enabled."""
    if not enabled or color_key not in COLORS:
        return text
    return f"{COLORS[color_key]}{text}{COLORS['RESET']}"


def compute_sha256(filepath: str, chunk_size: int = 65536) -> Optional[str]:
    """
    Computes SHA-256 hash of a file streaming by chunks.
    Returns None if file cannot be read or is a special non-regular file.
    """
    if not os.path.isfile(filepath):
        return None
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def get_file_metadata(filepath: str) -> Dict[str, Any]:
    """
    Retrieves file metadata cross-platform with graceful fallbacks.
    """
    try:
        # Use lstat to not follow symlinks directly when inspecting link status
        st = os.lstat(filepath)
        is_symlink = stat.S_ISLNK(st.st_mode)
        symlink_target = os.readlink(filepath) if is_symlink else None
        
        # Permissions in octal
        mode_octal = oct(stat.S_IMODE(st.st_mode))
        
        # UID and GID (posix only, fallback to st_uid/st_gid or None)
        uid = getattr(st, "st_uid", 0)
        gid = getattr(st, "st_gid", 0)
        
        owner_name = str(uid)
        group_name = str(gid)
        
        # On POSIX, attempt to look up username and group name
        if hasattr(os, "getuid"):
            try:
                import pwd
                owner_name = pwd.getpwuid(uid).pw_name
            except Exception:
                pass
            try:
                import grp
                group_name = grp.getgrgid(gid).gr_name
            except Exception:
                pass

        mtime_iso = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        
        return {
            "size": st.st_size,
            "mode": mode_octal,
            "uid": uid,
            "gid": gid,
            "owner": owner_name,
            "group": group_name,
            "mtime": st.st_mtime,
            "mtime_iso": mtime_iso,
            "is_symlink": is_symlink,
            "symlink_target": symlink_target,
            "is_suid": bool(st.st_mode & stat.S_ISUID),
            "is_sgid": bool(st.st_mode & stat.S_ISGID),
        }
    except (OSError, PermissionError) as e:
        return {
            "error": str(e),
            "size": 0,
            "mode": "0",
            "uid": -1,
            "gid": -1,
            "owner": "unknown",
            "group": "unknown",
            "mtime": 0,
            "mtime_iso": "",
            "is_symlink": False,
            "symlink_target": None,
            "is_suid": False,
            "is_sgid": False,
        }


def read_text_safe(filepath: str, max_bytes: int = 512 * 1024) -> Optional[str]:
    """
    Reads text content safely for diffing. Returns None if binary or unreadable.
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read(max_bytes + 1)
            if len(raw) > max_bytes:
                return None  # File too large for inline diff
            # Detect binary content (null bytes)
            if b"\x00" in raw:
                return None
            return raw.decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def generate_diff(old_content: Optional[str], new_content: Optional[str], from_label: str = "Baseline", to_label: str = "Current") -> str:
    """
    Generates unified diff between two text strings.
    """
    old_lines = (old_content or "").splitlines(keepends=True)
    new_lines = (new_content or "").splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=from_label,
        tofile=to_label,
        lineterm=""
    )
    return "\n".join(diff)


def resolve_system_root(virtual_path: str, root_prefix: Optional[str] = None) -> str:
    """
    Maps a Linux virtual path like /etc/crontab to either:
    - Root prefix path: e.g. <root_prefix>/etc/crontab
    - Native path: e.g. /etc/crontab or on Windows adapted safely.
    """
    normalized = virtual_path.lstrip("/\\")
    if root_prefix:
        return os.path.normpath(os.path.join(root_prefix, normalized))
    if sys.platform == "win32":
        # If running on Windows without a root_dir, normalize relative to current dir or drive root
        return os.path.normpath(os.path.join("C:\\", normalized))
    return os.path.normpath("/" + normalized)


def discover_user_homes(root_prefix: Optional[str] = None) -> List[Tuple[str, str]]:
    """
    Finds home directories of users to scan user-level persistence.
    Returns list of (username, absolute_path_to_home).
    """
    homes = []
    
    # 1. Root user home
    root_home = resolve_system_root("/root", root_prefix)
    if os.path.isdir(root_home):
        homes.append(("root", root_home))
        
    # 2. Standard /home directory users
    home_dir = resolve_system_root("/home", root_prefix)
    if os.path.isdir(home_dir):
        try:
            for entry in os.scandir(home_dir):
                if entry.is_dir() and not entry.name.startswith("."):
                    homes.append((entry.name, entry.path))
        except (OSError, PermissionError):
            pass
            
    # 3. Fallback for testing environments without standard /home
    if not homes and root_prefix:
        # Check if root_prefix itself has user folders
        test_user = os.path.join(root_prefix, "home", "user")
        if os.path.isdir(test_user):
            homes.append(("user", test_user))

    return homes
