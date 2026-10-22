# 🛡️ Linux Persistence Change Sentinel

A lightweight, modular cybersecurity auditing and change detection tool designed to detect persistence mechanisms on Linux systems mapped to the **MITRE ATT&CK** framework (Tactic `TA0003: Persistence`).

This repository includes:
1. **Sentinel Core Engine:** File integrity scanner, cryptographic baseline snapshot manager, and change detector (`sentinel/`).
2. **Safe Mock Sandbox (`mock_linux/`):** Simulated Linux configuration tree (`/etc/crontab`, `/etc/sudoers`, systemd units, SSH keys) allowing 100% safe demonstration and testing on Windows without administrator privileges or risking system files.
3. **SOC Cyber Dashboard (`dashboard/`):** A zero-dependency web interface running on Python's built-in `http.server` with live metrics, severity badges, and unified line diff inspection.

---

## 🔒 Safety & Design Principles
* **Zero External Dependencies:** Built entirely with Python's standard library (`hashlib`, `json`, `difflib`, `http.server`, `unittest`). No `pip install` required.
* **No Administrator Privileges:** Runs safely under standard user permissions.
* **Strict Sandbox Isolation:** All demonstrations and simulated changes occur inside `mock_linux/`. Real Windows or Linux system files are **never** accessed or modified.
* **Harmless Content:** Simulated configuration lines are purely demonstrative and never executed.

---

## 🚀 Quick Start Guide (Windows PowerShell)

Open PowerShell and navigate to the project directory:

```powershell
cd "c:\Users\ARUN\OneDrive\Desktop\linux-persistence-change-sentinel"
```

### Step 1: Run the Unit Tests
Verify the detection engine, diff generator, and baseline logic:

```powershell
python -m unittest tests/test_detector.py
```
*Expected Output: `Ran 4 tests in ... OK`*

---

### Step 2: Create a Clean Baseline
Take a baseline snapshot of the clean mock environment:

```powershell
python manage.py baseline
```
This generates `baseline.json` containing cryptographic SHA-256 hashes, file permissions, and metadata.

---

### Step 3: Run an Initial Clean Audit
Audit the mock environment against the baseline:

```powershell
python manage.py scan
```
*Expected Output: `Audit Complete: 0 changes detected. Filesystem state matches baseline snapshot.`*

---

### Step 4: Simulate a Persistence Change (Safe Demo)
Simulate a persistence change inside the harmless mock folder:

```powershell
# Option A: Simulate an unauthorized line added to mock crontab
python manage.py simulate modify

# Option B: Simulate a new rogue drop-in cron file
python manage.py simulate add

# Option C: Simulate deletion of a security service
python manage.py simulate delete
```

---

### Step 5: Audit and Detect the Change
Run the scan again to see Sentinel detect the change:

```powershell
python manage.py scan
```
Sentinel will display:
* Change Type: `[DEMO] MODIFIED` or `[DEMO] ADDED`
* Severity: `HIGH`
* Path: `/etc/crontab`
* MITRE ATT&CK: `T1053.003 (Scheduled Task/Job: Cron)`
* Line-by-line diff preview (+ added line)

---

### Step 6: Launch the Web Dashboard
Launch the local web visualizer:

```powershell
python manage.py dashboard
```
Open your browser and navigate to:
👉 **[http://127.0.0.1:8080](http://127.0.0.1:8080)**

The dashboard features:
* Real-time monitoring status and alert counters.
* Prominent **DEMO MODE** indicators.
* Severity filtering (Critical, High, Medium, Low).
* Interactive **"View Diff"** modal displaying color-coded line changes.

---

### Step 7: Reset to Clean State
Whenever you want to restore the mock environment to a clean state:

```powershell
python manage.py reset
```

---

## 📁 Project Structure

```
linux-persistence-change-sentinel/
├── sentinel/
│   ├── __init__.py           # Package marker & metadata
│   ├── rules.py              # MITRE ATT&CK persistence vector catalog
│   ├── utils.py              # SHA-256 hashing, metadata & unified diff utilities
│   ├── scanner.py            # Filesystem auditing engine
│   ├── baseline.py           # Snapshot creator & tamper-evident storage
│   └── detector.py           # Change detection & diff analysis engine
├── mock_linux/               # Safe simulated Linux filesystem for testing
│   ├── etc/
│   │   ├── crontab           # Sample crontab
│   │   ├── sudoers           # Sample sudoers
│   │   └── systemd/system/   # Sample systemd unit
│   └── home/student/         # Sample user home (.bashrc, .ssh/authorized_keys)
├── dashboard/
│   ├── server.py             # Built-in Python HTTP server (127.0.0.1:8080)
│   └── index.html            # Dark-theme SOC visualizer & diff viewer
├── tests/
│   └── test_detector.py      # Automated unittest suite
├── manage.py                 # Safe CLI runner (baseline, scan, simulate, dashboard, reset)
└── README.md                 # Documentation and instructions
```

---

## 🎯 Monitored MITRE ATT&CK Vectors

| Vector ID | Target Linux Path | MITRE ID | Tactic / Technique | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `ld_so_preload` | `/etc/ld.so.preload` | `T1574.006` | Dynamic Linker Preloading | **CRITICAL** |
| `sudoers_file` | `/etc/sudoers` | `T1548.001` | Sudo & Sudo Caching | **CRITICAL** |
| `cron_system` | `/etc/crontab` | `T1053.003` | Scheduled Task: Cron | **HIGH** |
| `cron_d` | `/etc/cron.d/` | `T1053.003` | Scheduled Task: Cron | **HIGH** |
| `systemd_system` | `/etc/systemd/system/` | `T1543.002` | System Process: Systemd Service | **HIGH** |
| `ssh_authorized_keys` | `~/.ssh/authorized_keys` | `T1098.004` | Account Manipulation: SSH Keys | **HIGH** |
| `shell_user_bashrc` | `~/.bashrc` | `T1546.004` | Shell Configuration Modification | **MEDIUM** |



## Live Demo

[Open Linux Persistence Change Sentinel Dashboard](https://linux-persistence-change-sentinel-kcxzkytrltpu2nterzyvwh.streamlit.app/)

**Note:** The current hosted version displays saved demo data and does not perform real-time monitoring of a Linux system.


