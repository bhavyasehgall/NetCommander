# NetCommander

**A cross-platform GUI Firewall & Network Security Manager**
Built with Python · PyQt6 · iptables / netsh

> Author: **Bhavya Sehgal**
> Version: 1.0

---

## 📋 Project Description

NetCommander is a desktop security tool that gives users a clean, beginner-friendly graphical interface to manage firewalls, monitor network activity, scan ports, and control system services — without needing to memorise any command-line syntax.

It runs natively on **Windows** (using `netsh` / Windows Firewall) and all major **Linux** distributions including **Kali Linux** and **Ubuntu** (using `iptables` / `systemctl`).

---

## ✨ Key Features

| Page | Features |
|------|----------|
| 🏠 **Dashboard** | Live system stats — hostname, OS, uptime, active connections, firewall rules, services up, blocked IPs |
| 🔒 **Firewall** | Add/delete rules, Quick Templates, Block/Unblock IP, Export rules, Port Scanner (nmap) |
| 🛠️ **Services** | Start/Stop/Status for SSH, Apache2, vsftpd, xrdp |
| 🌐 **Network Monitor** | Live interfaces (`ipconfig`/`ip addr`), active connections with live filter, suspicious port alerter |
| 📡 **Ping / DNS** | Ping with packet count, Traceroute, Forward & Reverse DNS lookup |
| 🗂️ **IP History** | Persistent blocked-IP log with timestamps, re-block from history |
| ❓ **Help** | Full beginner guide for every feature + port reference table |
| 👤 **About** | Author info, tech stack, description |

---

## 🖥️ Supported Platforms

| Platform | Firewall Backend | Service Manager |
|----------|-----------------|-----------------|
| Windows 10/11 | `netsh advfirewall` | `sc.exe` |
| Kali Linux | `iptables` | `systemctl` |
| Ubuntu / Debian | `iptables` | `systemctl` |
| Other Linux | `iptables` | `systemctl` |

---

## 🧰 Technologies Used

- **Python 3.8+** — Core language
- **PyQt6** — GUI framework (cross-platform)
- **iptables** — Firewall rule management on Linux
- **netsh** — Firewall rule management on Windows
- **nmap** — Port scanning (external, must be installed)
- **systemctl** — Service management on Linux
- **sc.exe** — Service management on Windows
- **netstat / ss** — Active connection monitoring
- **nslookup / dig** — DNS resolution
- **ping / traceroute** — Network diagnostics
- **JSON** — Persistent blocked-IP history storage

---

## ⚙️ Setup & Installation

### 1. Clone / Download the project

```bash
git clone <your-repo-url>
cd NetCommander
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Install system tools (if not already present)

**Linux (Kali / Ubuntu):**
```bash
sudo apt update
sudo apt install nmap traceroute dnsutils net-tools
```

**Windows:**
- Download and install [nmap for Windows](https://nmap.org/download.html)
- Add nmap to your system PATH

### 4. Run the application

**Linux (requires sudo for iptables):**
```bash
sudo python BhavyaSehgal_NetCommander.py
```

**Windows (run as Administrator):**
```
python BhavyaSehgal_NetCommander.py
```
Or right-click → *Run as administrator*

---

## 📁 Project Files

| File | Description |
|------|-------------|
| `BhavyaSehgal_NetCommander.py` | Main application source code |
| `requirements.txt` | Python dependencies |
| `README.md` | This file |
| `BhavyaSehgal_ProjectReport.docx` | Full project documentation |
| `block_history.json` | Auto-generated — stores blocked IP history |

---

## 🔐 Permissions Note

Firewall and service commands require elevated privileges:

- **Windows** — Right-click the terminal → *Run as administrator*
- **Linux** — Run with `sudo`, or configure passwordless sudo for `iptables`

Without the correct permissions, commands will fail gracefully and errors will be shown in the Activity Log panel.

---

## 📸 Interface Overview

```
┌─────────────────────────────────────────────────────────────┐
│  NetCommander                                               │
├──────────┬──────────────────────────────────────────────────┤
│ 🏠 Dash  │                                                  │
│ 🔒 FW    │   [Page Content Area]                            │
│ 🛠️ Svc  │                                                  │
│ 🌐 Net   │                                                  │
│ 📡 DNS   ├──────────────────────────────────────────────────┤
│ 🗂️ Hist │   📋 Activity Log  [Export] [Clear]              │
│ ❓ Help  │   [timestamped colour-coded log entries]         │
│ 👤 About │                                                  │
└──────────┴──────────────────────────────────────────────────┘
```

---

## 👤 Author

**Bhavya Sehgal**
Project: NetCommander
Version: 1.0
License: MIT — free to use and modify
