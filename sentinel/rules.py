"""
Persistence Vector Definitions and MITRE ATT&CK Mappings.
"""

from dataclasses import dataclass
from typing import List, Optional

@dataclass
class PersistenceVector:
    id: str
    name: str
    path_pattern: str  # e.g., "/etc/cron*" or "/etc/ld.so.preload" or user relative
    mitre_id: str
    mitre_name: str
    severity: str      # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    is_user_relative: bool = False  # If True, scanned in user homes (e.g. ~/.bashrc)
    recursive: bool = False
    is_directory: bool = False


DEFAULT_VECTORS: List[PersistenceVector] = [
    # 1. Dynamic Linker Preloading (T1574.006) - CRITICAL
    PersistenceVector(
        id="ld_so_preload",
        name="Dynamic Linker Preload",
        path_pattern="/etc/ld.so.preload",
        mitre_id="T1574.006",
        mitre_name="Hijack Execution Flow: Dynamic Linker Preloading",
        severity="CRITICAL",
        description="Shared libraries injected into every executed process to hook syscalls or rootkit systems.",
    ),
    PersistenceVector(
        id="ld_so_conf",
        name="Dynamic Linker Configuration",
        path_pattern="/etc/ld.so.conf.d",
        mitre_id="T1574.006",
        mitre_name="Hijack Execution Flow: Dynamic Linker Preloading",
        severity="HIGH",
        description="Custom library search paths that can hijack legitimate system shared libraries.",
        recursive=True,
        is_directory=True,
    ),

    # 2. Cron Jobs & Scheduled Tasks (T1053.003) - HIGH
    PersistenceVector(
        id="cron_system",
        name="System Crontab",
        path_pattern="/etc/crontab",
        mitre_id="T1053.003",
        mitre_name="Scheduled Task/Job: Cron",
        severity="HIGH",
        description="Central system crontab file containing scheduled commands.",
    ),
    PersistenceVector(
        id="cron_d",
        name="Cron Drop-in Directory",
        path_pattern="/etc/cron.d",
        mitre_id="T1053.003",
        mitre_name="Scheduled Task/Job: Cron",
        severity="HIGH",
        description="Drop-in cron tasks scheduled at system-level.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="cron_periodic",
        name="Periodic Cron Directories",
        path_pattern="/etc/cron.*",
        mitre_id="T1053.003",
        mitre_name="Scheduled Task/Job: Cron",
        severity="HIGH",
        description="Cron hourly, daily, weekly, monthly task execution directories.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="cron_spool",
        name="User Spool Crontabs",
        path_pattern="/var/spool/cron/crontabs",
        mitre_id="T1053.003",
        mitre_name="Scheduled Task/Job: Cron",
        severity="HIGH",
        description="Individual user-level crontab files scheduled via crontab -e.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="anacron",
        name="Anacron Configuration",
        path_pattern="/etc/anacrontab",
        mitre_id="T1053.003",
        mitre_name="Scheduled Task/Job: Cron",
        severity="HIGH",
        description="Anacron jobs scheduled for systems that do not run 24/7.",
    ),

    # 3. Systemd Services and Timers (T1543.002) - HIGH
    PersistenceVector(
        id="systemd_system",
        name="Systemd System Units",
        path_pattern="/etc/systemd/system",
        mitre_id="T1543.002",
        mitre_name="Create or Modify System Process: Systemd Service",
        severity="HIGH",
        description="Persistent services, timers, and sockets configured by administrators or attackers.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="systemd_user_global",
        name="Systemd Global User Units",
        path_pattern="/etc/systemd/user",
        mitre_id="T1543.002",
        mitre_name="Create or Modify System Process: Systemd Service",
        severity="MEDIUM",
        description="Systemd units intended to run across user sessions.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="systemd_user_home",
        name="User Systemd Units",
        path_pattern=".config/systemd/user",
        mitre_id="T1543.002",
        mitre_name="Create or Modify System Process: Systemd Service",
        severity="MEDIUM",
        description="User-specific systemd units running under persistent user manager.",
        is_user_relative=True,
        recursive=True,
        is_directory=True,
    ),

    # 4. SSH Authorized Keys (T1098.004) - HIGH
    PersistenceVector(
        id="ssh_authorized_keys",
        name="SSH Authorized Keys",
        path_pattern=".ssh/authorized_keys",
        mitre_id="T1098.004",
        mitre_name="Account Manipulation: SSH Authorized Keys",
        severity="HIGH",
        description="Public keys authorized to log in via SSH without passwords.",
        is_user_relative=True,
    ),
    PersistenceVector(
        id="ssh_authorized_keys2",
        name="SSH Authorized Keys 2",
        path_pattern=".ssh/authorized_keys2",
        mitre_id="T1098.004",
        mitre_name="Account Manipulation: SSH Authorized Keys",
        severity="HIGH",
        description="Secondary SSH authorized keys file recognized by older OpenSSH daemons.",
        is_user_relative=True,
    ),
    PersistenceVector(
        id="sshd_config",
        name="OpenSSH Server Configuration",
        path_pattern="/etc/ssh/sshd_config",
        mitre_id="T1098.004",
        mitre_name="Account Manipulation: SSH Authorized Keys",
        severity="HIGH",
        description="SSH daemon settings (e.g. PermitRootLogin, AuthorizedKeysCommand, ProxyCommand).",
    ),
    PersistenceVector(
        id="sshd_config_d",
        name="OpenSSH Server Drop-in Configuration",
        path_pattern="/etc/ssh/sshd_config.d",
        mitre_id="T1098.004",
        mitre_name="Account Manipulation: SSH Authorized Keys",
        severity="HIGH",
        description="Drop-in configuration snippets overriding SSH daemon behavior.",
        recursive=True,
        is_directory=True,
    ),

    # 5. Shell Profiles and Startup Hooks (T1546.004) - MEDIUM/HIGH
    PersistenceVector(
        id="shell_etc_profile",
        name="System-wide Shell Profile",
        path_pattern="/etc/profile",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="HIGH",
        description="Executed for every login shell for all users on the system.",
    ),
    PersistenceVector(
        id="shell_etc_profile_d",
        name="System-wide Profile Drop-in",
        path_pattern="/etc/profile.d",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="HIGH",
        description="Shell scripts sourced automatically during any user login shell.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="shell_etc_bashrc",
        name="System-wide Bashrc",
        path_pattern="/etc/bash.bashrc",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="HIGH",
        description="Executed for all non-login interactive bash shells across all users.",
    ),
    PersistenceVector(
        id="shell_user_bashrc",
        name="User Bashrc",
        path_pattern=".bashrc",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="MEDIUM",
        description="User bash configuration file executed on interactive shell start.",
        is_user_relative=True,
    ),
    PersistenceVector(
        id="shell_user_profile",
        name="User Shell Profile",
        path_pattern=".profile",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="MEDIUM",
        description="User shell login script executed when the user logs in.",
        is_user_relative=True,
    ),
    PersistenceVector(
        id="shell_user_bash_profile",
        name="User Bash Profile",
        path_pattern=".bash_profile",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="MEDIUM",
        description="Bash specific login script executed on user login.",
        is_user_relative=True,
    ),
    PersistenceVector(
        id="shell_user_zshrc",
        name="User Zshrc",
        path_pattern=".zshrc",
        mitre_id="T1546.004",
        mitre_name="Event Triggered Execution: Unix Shell Configuration Modification",
        severity="MEDIUM",
        description="User Zsh configuration file executed when interactive zsh starts.",
        is_user_relative=True,
    ),

    # 6. Privilege Escalation & Authentication Configuration (T1548.001, T1098) - HIGH/CRITICAL
    PersistenceVector(
        id="sudoers_file",
        name="Sudoers Master File",
        path_pattern="/etc/sudoers",
        mitre_id="T1548.001",
        mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        severity="CRITICAL",
        description="Defines sudo privileges; attackers can add NOPASSWD or root-level aliases.",
    ),
    PersistenceVector(
        id="sudoers_d",
        name="Sudoers Drop-in Directory",
        path_pattern="/etc/sudoers.d",
        mitre_id="T1548.001",
        mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        severity="CRITICAL",
        description="Drop-in sudoer rules, frequently abused to grant passwordless root access.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="pam_configs",
        name="PAM Configuration Directory",
        path_pattern="/etc/pam.d",
        mitre_id="T1556.003",
        mitre_name="Modify Authentication Process: Pluggable Authentication Modules",
        severity="CRITICAL",
        description="PAM configurations; malicious modules can log credentials or backdoor authentication.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="passwd_file",
        name="Passwd User Account Database",
        path_pattern="/etc/passwd",
        mitre_id="T1098",
        mitre_name="Account Manipulation",
        severity="HIGH",
        description="System account list; rogue UID 0 accounts or new rogue users may be injected.",
    ),

    # 7. Boot or Logon Initialization Scripts (T1037.004) - HIGH
    PersistenceVector(
        id="rc_local",
        name="RC Local Script",
        path_pattern="/etc/rc.local",
        mitre_id="T1037.004",
        mitre_name="Boot or Logon Initialization Scripts: RC Scripts",
        severity="HIGH",
        description="Legacy startup script executed as root at boot completion.",
    ),
    PersistenceVector(
        id="init_d",
        name="SysV Init Scripts",
        path_pattern="/etc/init.d",
        mitre_id="T1037.004",
        mitre_name="Boot or Logon Initialization Scripts: RC Scripts",
        severity="HIGH",
        description="Traditional SysVinit startup scripts executed during runlevel transitions.",
        recursive=True,
        is_directory=True,
    ),

    # 8. Kernel Modules / Drivers (T1547.006) - CRITICAL
    PersistenceVector(
        id="kernel_modules",
        name="Kernel Modules Configuration",
        path_pattern="/etc/modules",
        mitre_id="T1547.006",
        mitre_name="Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        severity="CRITICAL",
        description="List of kernel modules loaded automatically during system boot.",
    ),
    PersistenceVector(
        id="modules_load_d",
        name="Kernel Modules Load Drop-in",
        path_pattern="/etc/modules-load.d",
        mitre_id="T1547.006",
        mitre_name="Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        severity="CRITICAL",
        description="Drop-in directory for autoloaded kernel modules.",
        recursive=True,
        is_directory=True,
    ),
    PersistenceVector(
        id="modprobe_d",
        name="Modprobe Driver Options",
        path_pattern="/etc/modprobe.d",
        mitre_id="T1547.006",
        mitre_name="Boot or Logon Autostart Execution: Kernel Modules and Extensions",
        severity="HIGH",
        description="Kernel module alias and install hooks that can trigger arbitrary commands on module load.",
        recursive=True,
        is_directory=True,
    ),

    # 9. Udev Rules (T1546) - HIGH
    PersistenceVector(
        id="udev_rules",
        name="Udev Device Event Rules",
        path_pattern="/etc/udev/rules.d",
        mitre_id="T1546",
        mitre_name="Event Triggered Execution: Udev Rules",
        severity="HIGH",
        description="Udev rules executed by the kernel on hardware, device, or network events (RUN+=...).",
        recursive=True,
        is_directory=True,
    ),
]
