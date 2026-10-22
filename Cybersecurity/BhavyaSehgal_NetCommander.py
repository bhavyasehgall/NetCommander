import sys
import subprocess
import re
import platform
import datetime
import json
import os
import socket
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QComboBox, QVBoxLayout, QHBoxLayout, QTextEdit, QMessageBox,
    QGridLayout, QGroupBox, QCheckBox, QFileDialog, QFrame,
    QSizePolicy, QStackedWidget, QListWidget, QListWidgetItem,
    QProgressBar, QSplitter, QScrollArea, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCharFormat, QTextCursor, QClipboard
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize

# Persistent blocked-IP history file
BLOCK_HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "block_history.json")

# Ports flagged as suspicious
SUSPICIOUS_PORTS = {
    "4444": "Metasploit default shell",
    "31337": "Back Orifice / Elite",
    "1337": "Common backdoor",
    "6666": "IRC / malware",
    "6667": "IRC / malware",
    "9001": "Tor relay",
    "9050": "Tor SOCKS proxy",
    "5554": "Sasser worm",
    "3127": "MyDoom backdoor",
    "1080": "SOCKS proxy / malware",
    "8888": "Common backdoor / jupyter",
    "12345": "NetBus trojan",
    "27374": "Sub7 trojan",
}

# ─────────────────────────────────────────────
# Platform detection
# ─────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

# ─────────────────────────────────────────────
# Design tokens
# ─────────────────────────────────────────────
CLR_BG       = "#0f1117"
CLR_SURFACE  = "#1a1d2e"
CLR_CARD     = "#1e2235"
CLR_BORDER   = "#2e3250"
CLR_ACCENT   = "#4f6ef7"
CLR_ACCENT2  = "#7c5cdb"
CLR_SUCCESS  = "#22c55e"
CLR_DANGER   = "#ef4444"
CLR_WARN     = "#f59e0b"
CLR_TEXT     = "#e2e8f0"
CLR_MUTED    = "#8892a4"
CLR_SIDEBAR  = "#12151f"

# ─────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────
def validate_ip(ip):
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    m = re.match(pattern, ip)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())

def validate_port(port):
    return port.isdigit() and 0 < int(port) <= 65535

# ─────────────────────────────────────────────
# Safe subprocess helper
# ─────────────────────────────────────────────
def run_cmd(cmd, timeout=15):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: '{cmd[0]}'. Is it installed and on PATH?"
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s."
    except PermissionError:
        return -1, "", f"Permission denied running: {' '.join(cmd)}"
    except Exception as e:
        return -1, "", str(e)

# ─────────────────────────────────────────────
# Platform-aware firewall helpers
# ─────────────────────────────────────────────
def fw_add_rule(proto, port, action, src_ip=None):
    if IS_WINDOWS:
        win_action = "block" if action in ("DROP", "REJECT") else "allow"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=NetCommander_{proto}_{port}", "dir=in",
            f"action={win_action}", f"protocol={proto}",
            f"localport={port}", "enable=yes"
        ]
        if src_ip:
            cmd += [f"remoteip={src_ip}"]
        return run_cmd(cmd)
    else:
        cmd = ["sudo", "iptables", "-A", "INPUT"]
        if src_ip:
            cmd += ["-s", src_ip]
        cmd += ["-p", proto, "--dport", port]
        if action == "REJECT":
            cmd += ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"]
        else:
            cmd += ["-j", action]
        return run_cmd(cmd)

def fw_list_rules():
    if IS_WINDOWS:
        return run_cmd(["netsh", "advfirewall", "firewall", "show", "rule",
                        "name=all", "dir=in", "verbose"])
    return run_cmd(["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"])

def fw_flush_rules():
    if IS_WINDOWS:
        return run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=all", "dir=in"])
    return run_cmd(["sudo", "iptables", "-F", "INPUT"])

def fw_block_ip(ip):
    if IS_WINDOWS:
        return run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=NetCommander_BLOCK_{ip}", "dir=in",
                        "action=block", f"remoteip={ip}", "enable=yes"])
    return run_cmd(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def fw_unblock_ip(ip):
    if IS_WINDOWS:
        return run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name=NetCommander_BLOCK_{ip}"])
    return run_cmd(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

# ─────────────────────────────────────────────
# Platform-aware service helpers
# ─────────────────────────────────────────────
WINDOWS_SERVICE_MAP = {
    "ssh": "sshd", "apache2": "W3SVC",
    "vsftpd": "FTPSVC", "xrdp": "TermService",
}

SERVICES = {"ssh": "22", "apache2": "80", "vsftpd": "21", "xrdp": "3389"}

def svc_start(service):
    if IS_WINDOWS:
        return run_cmd(["sc", "start", WINDOWS_SERVICE_MAP.get(service, service)])
    return run_cmd(["sudo", "systemctl", "start", service])

def svc_stop(service):
    if IS_WINDOWS:
        return run_cmd(["sc", "stop", WINDOWS_SERVICE_MAP.get(service, service)])
    return run_cmd(["sudo", "systemctl", "stop", service])

def svc_status(service):
    if IS_WINDOWS:
        rc, out, _ = run_cmd(["sc", "query", WINDOWS_SERVICE_MAP.get(service, service)])
        if rc != 0:
            return "not found"
        if "RUNNING" in out:
            return "active"
        if "STOPPED" in out:
            return "inactive"
        return "unknown"
    rc, out, _ = run_cmd(["systemctl", "is-active", service])
    if rc == -1:
        return "not found"
    return out.strip() or "unknown"

# ─────────────────────────────────────────────
# Nmap worker thread
# ─────────────────────────────────────────────
class NmapWorker(QThread):
    finished = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, ip, scan_type="-Pn"):
        super().__init__()
        self.ip = ip
        self.scan_type = scan_type

    def run(self):
        self.progress.emit(20)
        rc, out, err = run_cmd(["nmap", self.scan_type, self.ip], timeout=120)
        self.progress.emit(100)
        self.finished.emit(out if rc == 0 else f"[Error]\n{err}")

# ─────────────────────────────────────────────
# Reusable UI components
# ─────────────────────────────────────────────
def make_card(title=""):
    box = QGroupBox(title)
    box.setStyleSheet(f"""
        QGroupBox {{
            background-color: {CLR_CARD};
            border: 1px solid {CLR_BORDER};
            border-radius: 10px;
            margin-top: 14px;
            padding: 6px;
            font-weight: bold;
            color: {CLR_TEXT};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 14px;
            padding: 0 6px;
            color: {CLR_ACCENT};
            font-size: 13px;
        }}
    """)
    return box

def make_btn(label, color=CLR_ACCENT, text_color="#ffffff"):
    btn = QPushButton(label)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setStyleSheet(f"""
        QPushButton {{
            background-color: {color};
            color: {text_color};
            border: none;
            border-radius: 6px;
            padding: 7px 16px;
            font-size: 13px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: {color}cc;
        }}
        QPushButton:pressed {{
            background-color: {color}88;
        }}
        QPushButton:disabled {{
            background-color: {CLR_BORDER};
            color: {CLR_MUTED};
        }}
    """)
    return btn

def make_input(placeholder=""):
    inp = QLineEdit()
    inp.setPlaceholderText(placeholder)
    inp.setStyleSheet(f"""
        QLineEdit {{
            background-color: {CLR_SURFACE};
            color: {CLR_TEXT};
            border: 1px solid {CLR_BORDER};
            border-radius: 6px;
            padding: 7px 10px;
            font-size: 13px;
        }}
        QLineEdit:focus {{
            border: 1px solid {CLR_ACCENT};
        }}
    """)
    return inp

def make_combo(items):
    cb = QComboBox()
    cb.addItems(items)
    cb.setStyleSheet(f"""
        QComboBox {{
            background-color: {CLR_SURFACE};
            color: {CLR_TEXT};
            border: 1px solid {CLR_BORDER};
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 13px;
        }}
        QComboBox::drop-down {{ border: none; }}
        QComboBox QAbstractItemView {{
            background-color: {CLR_SURFACE};
            color: {CLR_TEXT};
            selection-background-color: {CLR_ACCENT};
        }}
    """)
    return cb

def make_label(text, bold=False, muted=False, size=13):
    lbl = QLabel(text)
    color = CLR_MUTED if muted else CLR_TEXT
    weight = "700" if bold else "400"
    lbl.setStyleSheet(f"color: {color}; font-size: {size}px; font-weight: {weight};")
    return lbl

def make_output(min_height=120):
    te = QTextEdit()
    te.setReadOnly(True)
    te.setMinimumHeight(min_height)
    te.setFont(QFont("Consolas, Courier New, monospace", 12))
    te.setStyleSheet(f"""
        QTextEdit {{
            background-color: {CLR_BG};
            color: #a8d8a8;
            border: 1px solid {CLR_BORDER};
            border-radius: 8px;
            padding: 8px;
        }}
    """)
    return te

def hline():
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color: {CLR_BORDER};")
    return line

def make_copy_btn(text_edit: QTextEdit):
    """Returns a small 'Copy' button that copies the content of a QTextEdit."""
    btn = make_btn("📋 Copy", "#2d3748")
    btn.setFixedHeight(26)
    btn.clicked.connect(lambda: QApplication.clipboard().setText(text_edit.toPlainText()))
    return btn

def make_output_with_copy(min_height=120):
    """Returns (container_widget, text_edit) — output box with a copy button."""
    container = QWidget()
    container.setStyleSheet("background: transparent;")
    vl = QVBoxLayout(container)
    vl.setContentsMargins(0, 0, 0, 0)
    vl.setSpacing(4)
    te = make_output(min_height)
    copy_row = QHBoxLayout()
    copy_row.addStretch()
    copy_row.addWidget(make_copy_btn(te))
    vl.addLayout(copy_row)
    vl.addWidget(te)
    return container, te

# ─────────────────────────────────────────────
# Block history helpers
# ─────────────────────────────────────────────
def _load_block_history():
    if os.path.exists(BLOCK_HISTORY_FILE):
        try:
            with open(BLOCK_HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []

def _save_block_history(entries):
    try:
        with open(BLOCK_HISTORY_FILE, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception:
        pass

def _add_block_history(ip, action, reason=""):
    entries = _load_block_history()
    entries.insert(0, {
        "ip": ip,
        "action": action,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reason": reason,
    })
    _save_block_history(entries[:500])   # cap at 500 entries

# ─────────────────────────────────────────────
# Dashboard worker
# ─────────────────────────────────────────────
class DashboardWorker(QThread):
    finished = pyqtSignal(dict)

    def run(self):
        data = {}
        # Hostname
        try:
            data["hostname"] = socket.gethostname()
        except Exception:
            data["hostname"] = "unknown"
        # OS
        data["os"] = f"{platform.system()} {platform.release()}"
        # Uptime
        if IS_WINDOWS:
            rc, out, _ = run_cmd(
                ["powershell", "-Command",
                 "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | "
                 "Select-Object -ExpandProperty TotalHours"], timeout=8)
            try:
                hours = float(out.strip())
                data["uptime"] = f"{int(hours)}h {int((hours % 1)*60)}m"
            except Exception:
                data["uptime"] = "unknown"
        else:
            rc, out, _ = run_cmd(["uptime", "-p"], timeout=5)
            data["uptime"] = out.strip() if rc == 0 else "unknown"
        # Active connections count
        if IS_WINDOWS:
            rc, out, _ = run_cmd(["netstat", "-ano"], timeout=8)
        else:
            rc, out, _ = run_cmd(["ss", "-tunap"], timeout=8)
        data["conn_count"] = str(len([l for l in out.splitlines() if l.strip()]))
        # Firewall rules count
        rc2, out2, _ = fw_list_rules()
        data["rule_count"] = str(len([l for l in out2.splitlines() if l.strip() and not l.startswith("Chain")]))
        # Services running
        running = [s for s in SERVICES if svc_status(s) == "active"]
        data["services_up"] = str(len(running))
        data["services_total"] = str(len(SERVICES))
        # Block history count
        data["blocked_ips"] = str(len(_load_block_history()))
        self.finished.emit(data)


# ─────────────────────────────────────────────
# Firewall page
# ─────────────────────────────────────────────
class FirewallPage(QWidget):
    def __init__(self, log_fn):
        super().__init__()
        self.log = log_fn
        self._nmap_worker = None
        self._build_ui()
        QTimer.singleShot(300, self.load_rules)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        # ── Title row
        title_row = QHBoxLayout()
        title = make_label("🔒  Firewall Manager", bold=True, size=18)
        backend = make_label(
            f"Backend: {'Windows Firewall (netsh)' if IS_WINDOWS else 'iptables (Linux)'}",
            muted=True, size=12
        )
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(backend)
        root.addLayout(title_row)
        root.addWidget(hline())

        # ── Top row: Add Rule  |  Block / Unblock IP
        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        # Add Rule card
        add_card = make_card("➕  Add Firewall Rule")
        add_layout = QGridLayout()
        add_layout.setSpacing(8)

        add_layout.addWidget(make_label("Protocol"), 0, 0)
        self.proto_box = make_combo(["tcp", "udp"])
        add_layout.addWidget(self.proto_box, 0, 1)

        add_layout.addWidget(make_label("Port"), 1, 0)
        self.port_input = make_input("e.g. 8080")
        add_layout.addWidget(self.port_input, 1, 1)

        add_layout.addWidget(make_label("Action"), 2, 0)
        self.action_box = make_combo(["ACCEPT", "DROP", "REJECT"])
        add_layout.addWidget(self.action_box, 2, 1)

        add_layout.addWidget(make_label("Source IP"), 3, 0)
        self.ip_filter_input = make_input("optional, e.g. 192.168.1.5")
        add_layout.addWidget(self.ip_filter_input, 3, 1)

        self.add_btn = make_btn("＋  Add Rule", CLR_ACCENT)
        self.add_btn.clicked.connect(self.add_rule)
        add_layout.addWidget(self.add_btn, 4, 0, 1, 2)
        add_card.setLayout(add_layout)

        # Block / Unblock card
        block_card = make_card("🚫  Block / Unblock IP")
        block_layout = QVBoxLayout()
        block_layout.setSpacing(8)
        self.block_ip_input = make_input("Enter IP address")
        block_btn  = make_btn("⛔  Block IP",   CLR_DANGER)
        unblock_btn = make_btn("✅  Unblock IP", CLR_SUCCESS)
        block_btn.clicked.connect(self.block_ip)
        unblock_btn.clicked.connect(self.unblock_ip)
        block_layout.addWidget(make_label("Target IP Address"))
        block_layout.addWidget(self.block_ip_input)
        block_layout.addWidget(block_btn)
        block_layout.addWidget(unblock_btn)
        block_layout.addStretch()
        block_card.setLayout(block_layout)

        top_row.addWidget(add_card, 3)
        top_row.addWidget(block_card, 2)
        root.addLayout(top_row)

        # ── Quick Templates card
        tpl_card = make_card("⚡  Quick Rule Templates")
        tpl_layout = QHBoxLayout()
        tpl_layout.setContentsMargins(10, 6, 10, 10)
        tpl_layout.setSpacing(6)
        templates = [
            ("Allow HTTP",   "tcp", "80",   "ACCEPT"),
            ("Allow HTTPS",  "tcp", "443",  "ACCEPT"),
            ("Allow SSH",    "tcp", "22",   "ACCEPT"),
            ("Block Telnet", "tcp", "23",   "DROP"),
            ("Block FTP",    "tcp", "21",   "DROP"),
            ("Block RDP",    "tcp", "3389", "DROP"),
        ]
        for label, proto, port, action in templates:
            clr = CLR_SUCCESS if action == "ACCEPT" else CLR_DANGER
            b = make_btn(label, clr)
            b.setFixedHeight(30)
            b.clicked.connect(lambda _, p=proto, pt=port, a=action, l=label:
                              self._apply_template(p, pt, a, l))
            tpl_layout.addWidget(b)
        tpl_layout.addStretch()
        tpl_card.setLayout(tpl_layout)
        root.addWidget(tpl_card)

        # ── Controls row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(8)
        self.refresh_btn = make_btn("🔄  Refresh Rules", "#2d3748")
        self.flush_btn   = make_btn("🗑️  Flush All Rules", CLR_DANGER)
        self.export_btn  = make_btn("💾  Export Rules", "#2d5a3d")
        self.auto_chk    = QCheckBox("Auto-refresh (10s)")
        self.auto_chk.setStyleSheet(f"color: {CLR_MUTED}; font-size: 12px;")
        self.refresh_btn.clicked.connect(self.load_rules)
        self.flush_btn.clicked.connect(self.flush_rules)
        self.export_btn.clicked.connect(self.export_rules)
        self.auto_chk.stateChanged.connect(self._toggle_auto_refresh)
        ctrl_row.addWidget(self.refresh_btn)
        ctrl_row.addWidget(self.flush_btn)
        ctrl_row.addWidget(self.export_btn)
        ctrl_row.addStretch()
        ctrl_row.addWidget(self.auto_chk)
        root.addLayout(ctrl_row)

        self._timer = QTimer()
        self._timer.timeout.connect(self.load_rules)

        # ── Rules display with copy button
        rules_hdr = QHBoxLayout()
        rules_hdr.addWidget(make_label("Current Firewall Rules", bold=True))
        rules_hdr.addStretch()
        rules_copy_btn_placeholder = QLabel("")   # filled after rules_display exists
        root.addLayout(rules_hdr)
        rules_wrap, self.rules_display = make_output_with_copy(180)
        root.addWidget(rules_wrap)

        # ── Delete rule by line number (Linux only)
        if not IS_WINDOWS:
            del_card = make_card("🗑️  Delete Rule by Line Number")
            del_layout = QHBoxLayout()
            del_layout.setContentsMargins(10, 6, 10, 10)
            del_layout.setSpacing(8)
            self._del_line_input = make_input("Line number (see rules above)")
            self._del_line_input.setFixedWidth(220)
            del_btn = make_btn("Delete Rule", CLR_DANGER)
            del_btn.clicked.connect(self._delete_rule_by_line)
            hint = make_label("Line numbers shown in 'Current Firewall Rules'", muted=True, size=12)
            del_layout.addWidget(make_label("Line:"))
            del_layout.addWidget(self._del_line_input)
            del_layout.addWidget(del_btn)
            del_layout.addWidget(hint)
            del_layout.addStretch()
            del_card.setLayout(del_layout)
            root.addWidget(del_card)

        # ── Nmap card
        nmap_card = make_card("🔍  Port Scanner (nmap)")
        nmap_layout = QVBoxLayout()
        nmap_layout.setSpacing(8)

        nmap_top = QHBoxLayout()
        self.nmap_ip_input   = make_input("Target IP address")
        self.nmap_type_combo = make_combo(["-Pn  (basic)", "-sV  (version detect)", "-O  (OS detect)", "-A  (aggressive)"])
        self.nmap_btn        = make_btn("▶  Scan", CLR_ACCENT2)
        self.nmap_btn.clicked.connect(self.run_nmap)
        nmap_top.addWidget(make_label("Target IP:"))
        nmap_top.addWidget(self.nmap_ip_input, 2)
        nmap_top.addWidget(make_label("Scan type:"))
        nmap_top.addWidget(self.nmap_type_combo, 2)
        nmap_top.addWidget(self.nmap_btn)

        self.nmap_progress = QProgressBar()
        self.nmap_progress.setRange(0, 100)
        self.nmap_progress.setValue(0)
        self.nmap_progress.setVisible(False)
        self.nmap_progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {CLR_SURFACE};
                border: 1px solid {CLR_BORDER};
                border-radius: 4px;
                height: 8px;
                text-align: center;
            }}
            QProgressBar::chunk {{ background-color: {CLR_ACCENT2}; border-radius: 4px; }}
        """)

        self.nmap_result = make_output(140)
        nmap_layout.addLayout(nmap_top)
        nmap_layout.addWidget(self.nmap_progress)
        nmap_layout.addWidget(self.nmap_result)
        nmap_card.setLayout(nmap_layout)
        root.addWidget(nmap_card)

    def _toggle_auto_refresh(self, state):
        if state == Qt.CheckState.Checked.value:
            self._timer.start(10000)
        else:
            self._timer.stop()

    def load_rules(self):
        rc, out, err = fw_list_rules()
        if rc == 0:
            self.rules_display.setText(out or "(no rules)")
        else:
            tip = "Tip: run as Administrator." if IS_WINDOWS else "Tip: run with sudo."
            self.rules_display.setText(f"[Could not load rules]\n{err}\n\n{tip}")
        self.log(f"Rules refreshed ({datetime.datetime.now().strftime('%H:%M:%S')})", "info")

    def add_rule(self):
        proto  = self.proto_box.currentText()
        port   = self.port_input.text().strip()
        action = self.action_box.currentText()
        src_ip = self.ip_filter_input.text().strip()
        if not validate_port(port):
            QMessageBox.warning(self, "Input Error", "Invalid port (must be 1–65535).")
            return
        if src_ip and not validate_ip(src_ip):
            QMessageBox.warning(self, "Input Error", "Invalid source IP address.")
            return
        rc, out, err = fw_add_rule(proto, port, action, src_ip or None)
        if rc == 0:
            self.log(f"Rule added: {action} {proto}/{port}" + (f" from {src_ip}" if src_ip else ""), "success")
            self.port_input.clear()
            self.ip_filter_input.clear()
            self.load_rules()
        else:
            self.log(f"Add rule failed: {err or out}", "error")
            QMessageBox.critical(self, "Command Failed", err or out)

    def flush_rules(self):
        if QMessageBox.question(
            self, "Confirm Flush",
            "Delete ALL inbound firewall rules?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        rc, out, err = fw_flush_rules()
        if rc == 0:
            self.log("All inbound rules flushed.", "warn")
        else:
            self.log(f"Flush failed: {err or out}", "error")
            QMessageBox.critical(self, "Error", err or out)
        self.load_rules()

    def export_rules(self):
        if IS_WINDOWS:
            path, _ = QFileDialog.getSaveFileName(self, "Export Rules", "firewall_backup.wfw", "WFW Files (*.wfw)")
            if not path:
                return
            rc, out, err = run_cmd(["netsh", "advfirewall", "export", path])
            if rc == 0:
                self.log(f"Rules exported to {path}", "success")
                QMessageBox.information(self, "Saved", f"Exported to:\n{path}")
            else:
                self.log(f"Export failed: {err}", "error")
                QMessageBox.critical(self, "Error", err or out)
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Export Rules", "firewall_backup.rules", "Rules Files (*.rules *.txt)")
            if not path:
                return
            rc, out, err = run_cmd(["sudo", "iptables-save"])
            if rc == 0:
                with open(path, "w") as f:
                    f.write(out)
                self.log(f"Rules exported to {path}", "success")
                QMessageBox.information(self, "Saved", f"Exported to:\n{path}")
            else:
                self.log(f"Export failed: {err}", "error")
                QMessageBox.critical(self, "Error", err)

    def _apply_template(self, proto, port, action, label):
        rc, out, err = fw_add_rule(proto, port, action)
        if rc == 0:
            self.log(f"Template applied: {label} ({action} {proto}/{port})", "success")
            self.load_rules()
        else:
            self.log(f"Template failed: {err or out}", "error")
            QMessageBox.critical(self, "Template Failed", err or out)

    def _delete_rule_by_line(self):
        line_widget = getattr(self, "_del_line_input", None)
        if not line_widget:
            return
        num = line_widget.text().strip()
        if not num.isdigit():
            QMessageBox.warning(self, "Input Error", "Enter a valid line number.")
            return
        rc, out, err = run_cmd(["sudo", "iptables", "-D", "INPUT", num])
        if rc == 0:
            self.log(f"Rule line {num} deleted.", "warn")
            line_widget.clear()
            self.load_rules()
        else:
            self.log(f"Delete rule failed: {err or out}", "error")
            QMessageBox.critical(self, "Error", err or out)

    def block_ip(self):
        ip = self.block_ip_input.text().strip()
        if not validate_ip(ip):
            QMessageBox.warning(self, "Input Error", "Enter a valid IPv4 address.")
            return
        rc, out, err = fw_block_ip(ip)
        if rc == 0:
            self.log(f"Blocked IP: {ip}", "warn")
            _add_block_history(ip, "blocked")
            self.block_ip_input.clear()
        else:
            self.log(f"Block failed: {err or out}", "error")
            QMessageBox.critical(self, "Error", err or out)
        self.load_rules()

    def unblock_ip(self):
        ip = self.block_ip_input.text().strip()
        if not validate_ip(ip):
            QMessageBox.warning(self, "Input Error", "Enter a valid IPv4 address.")
            return
        rc, out, err = fw_unblock_ip(ip)
        if rc == 0:
            self.log(f"Unblocked IP: {ip}", "success")
            _add_block_history(ip, "unblocked")
            self.block_ip_input.clear()
        else:
            self.log(f"Unblock failed: {err or out}", "error")
            QMessageBox.critical(self, "Error", err or out)
        self.load_rules()

    def run_nmap(self):
        ip = self.nmap_ip_input.text().strip()
        if not validate_ip(ip):
            QMessageBox.warning(self, "Error", "Enter a valid IP address.")
            return
        if self._nmap_worker and self._nmap_worker.isRunning():
            QMessageBox.information(self, "Busy", "A scan is already running.")
            return

        raw_type = self.nmap_type_combo.currentText().split()[0]
        self.nmap_btn.setEnabled(False)
        self.nmap_btn.setText("Scanning…")
        self.nmap_result.setText("Running nmap, please wait…")
        self.nmap_progress.setValue(0)
        self.nmap_progress.setVisible(True)
        self.log(f"Nmap scan started → {ip} ({raw_type})", "info")

        self._nmap_worker = NmapWorker(ip, raw_type)
        self._nmap_worker.finished.connect(self._on_nmap_done)
        self._nmap_worker.progress.connect(self.nmap_progress.setValue)
        self._nmap_worker.start()

    def _on_nmap_done(self, output):
        self.nmap_result.setText(output)
        self.nmap_btn.setEnabled(True)
        self.nmap_btn.setText("▶  Scan")
        self.nmap_progress.setVisible(False)
        self.log("Nmap scan complete.", "success")

# ─────────────────────────────────────────────
# Services page
# ─────────────────────────────────────────────
class ServicesPage(QWidget):
    def __init__(self, log_fn):
        super().__init__()
        self.log = log_fn
        self.status_labels = {}
        self._build_ui()
        QTimer.singleShot(250, self._refresh_all)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        # Title
        title_row = QHBoxLayout()
        title = make_label("🛠️  Service Manager", bold=True, size=18)
        refresh_all_btn = make_btn("🔄  Refresh All", "#2d3748")
        refresh_all_btn.clicked.connect(self._refresh_all)
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(refresh_all_btn)
        root.addLayout(title_row)

        if IS_WINDOWS:
            note = make_label(
                "ℹ  Windows mode — mapped to: sshd · W3SVC · FTPSVC · TermService  (requires Admin)",
                muted=True, size=12
            )
            root.addWidget(note)

        root.addWidget(hline())

        # Service cards grid
        grid_widget = QWidget()
        grid = QGridLayout(grid_widget)
        grid.setSpacing(14)

        SERVICE_ICONS = {"ssh": "🔐", "apache2": "🌐", "vsftpd": "📁", "xrdp": "🖥️"}

        for col, header in enumerate(["Service", "Port", "Status", "Actions"]):
            lbl = make_label(header, bold=True, size=12, muted=True)
            grid.addWidget(lbl, 0, col)

        for row, (svc, port) in enumerate(SERVICES.items(), start=1):
            icon = SERVICE_ICONS.get(svc, "⚙️")

            name_lbl = make_label(f"{icon}  {svc}", bold=True)
            port_lbl = make_label(f":{port}", muted=True)
            status_lbl = make_label("…")
            status_lbl.setMinimumWidth(90)

            btn_row = QHBoxLayout()
            btn_row.setSpacing(6)
            start_btn   = make_btn("▶ Start",   CLR_SUCCESS)
            stop_btn    = make_btn("■ Stop",    CLR_DANGER)
            refresh_btn = make_btn("↻", "#2d3748")
            refresh_btn.setFixedWidth(36)
            start_btn.clicked.connect(lambda _, s=svc: self._toggle(s, "start"))
            stop_btn.clicked.connect(lambda _, s=svc: self._toggle(s, "stop"))
            refresh_btn.clicked.connect(lambda _, s=svc: self._refresh_one(s))
            btn_row.addWidget(start_btn)
            btn_row.addWidget(stop_btn)
            btn_row.addWidget(refresh_btn)

            btn_container = QWidget()
            btn_container.setLayout(btn_row)

            grid.addWidget(name_lbl,      row, 0)
            grid.addWidget(port_lbl,      row, 1)
            grid.addWidget(status_lbl,    row, 2)
            grid.addWidget(btn_container, row, 3)
            self.status_labels[svc] = status_lbl

            # Separator line after each row
            if row < len(SERVICES):
                sep = hline()
                grid.addWidget(sep, row * 2, 0, 1, 4)

        root.addWidget(grid_widget)
        root.addStretch()

    def _set_status(self, svc, status):
        lbl = self.status_labels[svc]
        lbl.setText(f"● {status}")
        if status == "active":
            lbl.setStyleSheet(f"color: {CLR_SUCCESS}; font-size: 13px; font-weight: 700;")
        elif status in ("inactive", "stopped"):
            lbl.setStyleSheet(f"color: {CLR_DANGER}; font-size: 13px; font-weight: 700;")
        elif status == "not found":
            lbl.setStyleSheet(f"color: {CLR_BORDER}; font-size: 13px;")
        else:
            lbl.setStyleSheet(f"color: {CLR_WARN}; font-size: 13px;")

    def _refresh_one(self, svc):
        self._set_status(svc, svc_status(svc))

    def _refresh_all(self):
        for svc in SERVICES:
            self._refresh_one(svc)
        self.log("Service statuses refreshed.", "info")

    def _toggle(self, svc, action):
        fn = svc_start if action == "start" else svc_stop
        rc, out, err = fn(svc)
        if rc == -1:
            self.log(f"Service '{svc}' {action} failed: {err}", "error")
            QMessageBox.warning(self, "Service Error", err)
        else:
            self.log(f"Service '{svc}': {action} executed.", "info")
        self._refresh_one(svc)

# ─────────────────────────────────────────────
# Activity Log panel
# ─────────────────────────────────────────────
class LogPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        hdr = QHBoxLayout()
        hdr.addWidget(make_label("📋  Activity Log", bold=True, size=13))
        export_btn = make_btn("💾 Export", "#2d5a3d")
        export_btn.setFixedHeight(26)
        export_btn.clicked.connect(self._export_log)
        clear_btn = make_btn("Clear", "#2d3748")
        clear_btn.setFixedHeight(26)
        clear_btn.clicked.connect(lambda: self.log_view.clear())
        hdr.addStretch()
        hdr.addWidget(export_btn)
        hdr.addWidget(clear_btn)
        layout.addLayout(hdr)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas, Courier New", 11))
        self.log_view.setStyleSheet(f"""
            QTextEdit {{
                background-color: {CLR_BG};
                color: {CLR_MUTED};
                border: 1px solid {CLR_BORDER};
                border-radius: 8px;
                padding: 6px;
            }}
        """)
        layout.addWidget(self.log_view)

    COLORS = {
        "info":    "#8892a4",
        "success": "#22c55e",
        "warn":    "#f59e0b",
        "error":   "#ef4444",
    }

    def append(self, message, level="info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = self.COLORS.get(level, self.COLORS["info"])
        icons = {"info": "ℹ", "success": "✔", "warn": "⚠", "error": "✖"}
        icon = icons.get(level, "·")
        self.log_view.append(
            f'<span style="color:{CLR_MUTED};">[{ts}]</span> '
            f'<span style="color:{color};">{icon}  {message}</span>'
        )
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum()
        )

    def _export_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Activity Log",
            f"netcommander_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.log_view.toPlainText())
            self.append(f"Log exported to {path}", "success")
        except Exception as e:
            self.append(f"Export failed: {e}", "error")

# ─────────────────────────────────────────────
# Network Monitor workers
# ─────────────────────────────────────────────
class InterfaceWorker(QThread):
    finished = pyqtSignal(str)

    def run(self):
        if IS_WINDOWS:
            rc, out, err = run_cmd(["ipconfig", "/all"], timeout=10)
        else:
            rc, out, err = run_cmd(["ip", "addr"], timeout=10)
            if rc != 0:
                rc, out, err = run_cmd(["ifconfig", "-a"], timeout=10)
        self.finished.emit(out if rc == 0 else f"[Error]\n{err}")


class ConnectionsWorker(QThread):
    finished = pyqtSignal(str)

    def run(self):
        if IS_WINDOWS:
            rc, out, err = run_cmd(["netstat", "-ano"], timeout=10)
        else:
            rc, out, err = run_cmd(["ss", "-tunap"], timeout=10)
            if rc != 0:
                rc, out, err = run_cmd(["netstat", "-tunap"], timeout=10)
        self.finished.emit(out if rc == 0 else f"[Error]\n{err}")


# ─────────────────────────────────────────────
# Network Monitor page
# ─────────────────────────────────────────────
class NetworkMonitorPage(QWidget):
    def __init__(self, log_fn):
        super().__init__()
        self.log = log_fn
        self._iface_worker = None
        self._conn_worker  = None
        self._build_ui()
        QTimer.singleShot(400, self._refresh_all)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        # Title row
        title_row = QHBoxLayout()
        title_row.addWidget(make_label("🌐  Network Monitor", bold=True, size=18))
        title_row.addStretch()
        refresh_btn = make_btn("🔄  Refresh All", "#2d3748")
        refresh_btn.clicked.connect(self._refresh_all)
        self.auto_chk = QCheckBox("Auto-refresh (15s)")
        self.auto_chk.setStyleSheet(f"color: {CLR_MUTED}; font-size: 12px;")
        self.auto_chk.stateChanged.connect(self._toggle_auto)
        title_row.addWidget(refresh_btn)
        title_row.addWidget(self.auto_chk)
        root.addLayout(title_row)
        root.addWidget(hline())

        self._timer = QTimer()
        self._timer.timeout.connect(self._refresh_all)

        # ── Interfaces card
        iface_card = make_card("🔌  Network Interfaces")
        iface_layout = QVBoxLayout()
        iface_layout.setContentsMargins(10, 6, 10, 10)

        iface_ctrl = QHBoxLayout()
        self._iface_btn = make_btn("↻  Refresh Interfaces", "#2d3748")
        self._iface_btn.clicked.connect(self._refresh_ifaces)
        self._iface_status = make_label("", muted=True, size=11)
        iface_ctrl.addWidget(self._iface_btn)
        iface_ctrl.addStretch()
        iface_ctrl.addWidget(self._iface_status)
        iface_layout.addLayout(iface_ctrl)

        self._iface_out = make_output(200)
        iface_layout.addWidget(self._iface_out)
        iface_card.setLayout(iface_layout)
        root.addWidget(iface_card)

        # ── Connections card
        conn_card = make_card("🔗  Active Connections")
        conn_layout = QVBoxLayout()
        conn_layout.setContentsMargins(10, 6, 10, 10)

        conn_ctrl = QHBoxLayout()
        self._conn_btn = make_btn("↻  Refresh Connections", "#2d3748")
        self._conn_btn.clicked.connect(self._refresh_conns)
        self._conn_filter = make_input("Filter (e.g. ESTABLISHED, :80, an IP…)")
        self._conn_filter.textChanged.connect(self._apply_filter)
        self._conn_status = make_label("", muted=True, size=11)
        conn_ctrl.addWidget(self._conn_btn)
        conn_ctrl.addWidget(self._conn_filter, 2)
        conn_ctrl.addStretch()
        conn_ctrl.addWidget(self._conn_status)
        conn_layout.addLayout(conn_ctrl)

        self._conn_out = make_output(220)
        self._raw_conn_text = ""          # store unfiltered text
        conn_layout.addWidget(self._conn_out)
        conn_card.setLayout(conn_layout)
        root.addWidget(conn_card)

        # Suspicious connection alert banner (hidden until triggered)
        self._alert_lbl = QLabel("")
        self._alert_lbl.setWordWrap(True)
        self._alert_lbl.setStyleSheet(
            f"background-color: #3a1010; color: {CLR_DANGER}; border: 1px solid {CLR_DANGER};"
            f" border-radius: 6px; padding: 8px; font-size: 12px;"
        )
        self._alert_lbl.setVisible(False)
        root.addWidget(self._alert_lbl)

    def _toggle_auto(self, state):
        if state == Qt.CheckState.Checked.value:
            self._timer.start(15000)
        else:
            self._timer.stop()

    def _refresh_all(self):
        self._refresh_ifaces()
        self._refresh_conns()

    def _refresh_ifaces(self):
        if self._iface_worker and self._iface_worker.isRunning():
            return
        self._iface_btn.setEnabled(False)
        self._iface_status.setText("loading…")
        self._iface_worker = InterfaceWorker()
        self._iface_worker.finished.connect(self._on_ifaces_done)
        self._iface_worker.start()

    def _on_ifaces_done(self, text):
        self._iface_out.setText(text)
        self._iface_btn.setEnabled(True)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._iface_status.setText(f"Updated {ts}")
        self.log("Network interfaces refreshed.", "info")

    def _refresh_conns(self):
        if self._conn_worker and self._conn_worker.isRunning():
            return
        self._conn_btn.setEnabled(False)
        self._conn_status.setText("loading…")
        self._conn_worker = ConnectionsWorker()
        self._conn_worker.finished.connect(self._on_conns_done)
        self._conn_worker.start()

    def _on_conns_done(self, text):
        self._raw_conn_text = text
        self._apply_filter()
        self._conn_btn.setEnabled(True)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._conn_status.setText(f"Updated {ts}")
        self.log("Active connections refreshed.", "info")
        # Suspicious port scan
        alerts = []
        for line in text.splitlines():
            for port, reason in SUSPICIOUS_PORTS.items():
                if f":{port} " in line or f":{port}\t" in line or line.endswith(f":{port}"):
                    alerts.append(f"  ⚠ Port {port} ({reason})  →  {line.strip()}")
        if alerts:
            self._alert_lbl.setText(
                "🚨  Suspicious port(s) detected:\n" + "\n".join(alerts[:8])
            )
            self._alert_lbl.setVisible(True)
            self.log(f"Suspicious connections detected: {len(alerts)} hit(s)!", "error")
        else:
            self._alert_lbl.setVisible(False)

    def _apply_filter(self):
        filt = self._conn_filter.text().strip().lower()
        if not filt:
            self._conn_out.setText(self._raw_conn_text)
            return
        lines = self._raw_conn_text.splitlines()
        matched = [l for l in lines if filt in l.lower()]
        self._conn_out.setText(
            "\n".join(matched) if matched else f"(no matches for '{filt}')"
        )


# ─────────────────────────────────────────────
# Ping / DNS workers
# ─────────────────────────────────────────────
class PingWorker(QThread):
    finished  = pyqtSignal(str)
    progress  = pyqtSignal(int)

    def __init__(self, host, count=4):
        super().__init__()
        self.host  = host
        self.count = count

    def run(self):
        self.progress.emit(15)
        if IS_WINDOWS:
            cmd = ["ping", "-n", str(self.count), self.host]
        else:
            cmd = ["ping", "-c", str(self.count), self.host]
        rc, out, err = run_cmd(cmd, timeout=30)
        self.progress.emit(100)
        self.finished.emit(out if rc == 0 else f"[Error / Host unreachable]\n{err or out}")


class TracerouteWorker(QThread):
    finished = pyqtSignal(str)
    progress = pyqtSignal(int)

    def __init__(self, host):
        super().__init__()
        self.host = host

    def run(self):
        self.progress.emit(10)
        cmd = ["tracert", "-d", self.host] if IS_WINDOWS else ["traceroute", "-n", self.host]
        rc, out, err = run_cmd(cmd, timeout=60)
        self.progress.emit(100)
        self.finished.emit(out if rc == 0 else f"[Error]\n{err or out}")


class DNSWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, query, lookup_type="forward"):
        super().__init__()
        self.query       = query
        self.lookup_type = lookup_type   # "forward" or "reverse"

    def run(self):
        if IS_WINDOWS:
            cmd = ["nslookup", self.query]
        else:
            if self.lookup_type == "reverse":
                cmd = ["dig", "-x", self.query, "+short"]
            else:
                cmd = ["dig", self.query, "+short"]
            # fallback: nslookup also exists on most Linux distros
        rc, out, err = run_cmd(cmd, timeout=15)
        if rc != 0 and not IS_WINDOWS:
            rc, out, err = run_cmd(["nslookup", self.query], timeout=15)
        self.finished.emit(out.strip() if rc == 0 else f"[Error]\n{err or out}")


# ─────────────────────────────────────────────
# Ping / DNS Tools page
# ─────────────────────────────────────────────
class PingDNSPage(QWidget):
    def __init__(self, log_fn):
        super().__init__()
        self.log = log_fn
        self._ping_worker  = None
        self._trace_worker = None
        self._dns_worker   = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        root.addWidget(make_label("📡  Ping & DNS Tools", bold=True, size=18))
        root.addWidget(hline())

        # ── Ping card
        ping_card = make_card("🏓  Ping")
        ping_layout = QVBoxLayout()
        ping_layout.setContentsMargins(12, 8, 12, 12)
        ping_layout.setSpacing(8)

        ping_row = QHBoxLayout()
        self._ping_host  = make_input("Hostname or IP  (e.g. 8.8.8.8)")
        self._ping_count = make_combo(["4 packets", "8 packets", "16 packets", "Continuous (10)"])
        self._ping_btn   = make_btn("▶  Ping", CLR_ACCENT)
        self._ping_btn.clicked.connect(self._run_ping)
        ping_row.addWidget(make_label("Host:"))
        ping_row.addWidget(self._ping_host, 3)
        ping_row.addWidget(make_label("Count:"))
        ping_row.addWidget(self._ping_count, 1)
        ping_row.addWidget(self._ping_btn)

        self._ping_progress = QProgressBar()
        self._ping_progress.setRange(0, 100)
        self._ping_progress.setValue(0)
        self._ping_progress.setVisible(False)
        self._ping_progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {CLR_SURFACE};
                border: 1px solid {CLR_BORDER};
                border-radius: 4px; height: 8px;
            }}
            QProgressBar::chunk {{ background-color: {CLR_ACCENT}; border-radius: 4px; }}
        """)

        self._ping_out = make_output(130)
        ping_layout.addLayout(ping_row)
        ping_layout.addWidget(self._ping_progress)
        ping_layout.addWidget(self._ping_out)
        ping_card.setLayout(ping_layout)
        root.addWidget(ping_card)

        # ── Traceroute card
        trace_card = make_card("🗺️  Traceroute")
        trace_layout = QVBoxLayout()
        trace_layout.setContentsMargins(12, 8, 12, 12)
        trace_layout.setSpacing(8)

        trace_row = QHBoxLayout()
        self._trace_host = make_input("Hostname or IP  (e.g. google.com)")
        self._trace_btn  = make_btn("▶  Trace", CLR_ACCENT2)
        self._trace_btn.clicked.connect(self._run_trace)
        trace_row.addWidget(make_label("Host:"))
        trace_row.addWidget(self._trace_host, 4)
        trace_row.addWidget(self._trace_btn)

        self._trace_progress = QProgressBar()
        self._trace_progress.setRange(0, 100)
        self._trace_progress.setValue(0)
        self._trace_progress.setVisible(False)
        self._trace_progress.setStyleSheet(f"""
            QProgressBar {{
                background-color: {CLR_SURFACE};
                border: 1px solid {CLR_BORDER};
                border-radius: 4px; height: 8px;
            }}
            QProgressBar::chunk {{ background-color: {CLR_ACCENT2}; border-radius: 4px; }}
        """)

        self._trace_out = make_output(130)
        trace_layout.addLayout(trace_row)
        trace_layout.addWidget(self._trace_progress)
        trace_layout.addWidget(self._trace_out)
        trace_card.setLayout(trace_layout)
        root.addWidget(trace_card)

        # ── DNS card
        dns_card = make_card("🔎  DNS Lookup")
        dns_layout = QVBoxLayout()
        dns_layout.setContentsMargins(12, 8, 12, 12)
        dns_layout.setSpacing(8)

        dns_row = QHBoxLayout()
        self._dns_input = make_input("Domain or IP  (e.g. github.com  or  1.1.1.1)")
        self._dns_type  = make_combo(["Forward (domain → IP)", "Reverse (IP → domain)"])
        self._dns_btn   = make_btn("🔍  Lookup", CLR_SUCCESS)
        self._dns_btn.clicked.connect(self._run_dns)
        dns_row.addWidget(make_label("Query:"))
        dns_row.addWidget(self._dns_input, 3)
        dns_row.addWidget(make_label("Type:"))
        dns_row.addWidget(self._dns_type, 2)
        dns_row.addWidget(self._dns_btn)

        self._dns_out = make_output(120)
        dns_layout.addLayout(dns_row)
        dns_layout.addWidget(self._dns_out)
        dns_card.setLayout(dns_layout)
        root.addWidget(dns_card)

    # ── Ping logic
    def _run_ping(self):
        host = self._ping_host.text().strip()
        if not host:
            QMessageBox.warning(self, "Input", "Enter a hostname or IP.")
            return
        if self._ping_worker and self._ping_worker.isRunning():
            QMessageBox.information(self, "Busy", "Ping already running.")
            return
        count_map = {"4 packets": 4, "8 packets": 8,
                     "16 packets": 16, "Continuous (10)": 10}
        count = count_map.get(self._ping_count.currentText(), 4)
        self._ping_btn.setEnabled(False)
        self._ping_btn.setText("Pinging…")
        self._ping_out.setText(f"Pinging {host}…")
        self._ping_progress.setValue(0)
        self._ping_progress.setVisible(True)
        self.log(f"Ping started → {host} ({count} packets)", "info")
        self._ping_worker = PingWorker(host, count)
        self._ping_worker.finished.connect(self._on_ping_done)
        self._ping_worker.progress.connect(self._ping_progress.setValue)
        self._ping_worker.start()

    def _on_ping_done(self, output):
        self._ping_out.setText(output)
        self._ping_btn.setEnabled(True)
        self._ping_btn.setText("▶  Ping")
        self._ping_progress.setVisible(False)
        ok = "unreachable" not in output.lower() and "error" not in output.lower()
        self.log("Ping complete — " + ("host reachable." if ok else "host unreachable."),
                 "success" if ok else "warn")

    # ── Traceroute logic
    def _run_trace(self):
        host = self._trace_host.text().strip()
        if not host:
            QMessageBox.warning(self, "Input", "Enter a hostname or IP.")
            return
        if self._trace_worker and self._trace_worker.isRunning():
            QMessageBox.information(self, "Busy", "Traceroute already running.")
            return
        self._trace_btn.setEnabled(False)
        self._trace_btn.setText("Tracing…")
        self._trace_out.setText(f"Tracing route to {host}…")
        self._trace_progress.setValue(0)
        self._trace_progress.setVisible(True)
        self.log(f"Traceroute started → {host}", "info")
        self._trace_worker = TracerouteWorker(host)
        self._trace_worker.finished.connect(self._on_trace_done)
        self._trace_worker.progress.connect(self._trace_progress.setValue)
        self._trace_worker.start()

    def _on_trace_done(self, output):
        self._trace_out.setText(output)
        self._trace_btn.setEnabled(True)
        self._trace_btn.setText("▶  Trace")
        self._trace_progress.setVisible(False)
        self.log("Traceroute complete.", "success")

    # ── DNS logic
    def _run_dns(self):
        query = self._dns_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Input", "Enter a domain or IP.")
            return
        if self._dns_worker and self._dns_worker.isRunning():
            QMessageBox.information(self, "Busy", "Lookup already running.")
            return
        ltype = "reverse" if "Reverse" in self._dns_type.currentText() else "forward"
        self._dns_btn.setEnabled(False)
        self._dns_btn.setText("Looking up…")
        self._dns_out.setText(f"Resolving {query}…")
        self.log(f"DNS {ltype} lookup → {query}", "info")
        self._dns_worker = DNSWorker(query, ltype)
        self._dns_worker.finished.connect(self._on_dns_done)
        self._dns_worker.start()

    def _on_dns_done(self, output):
        self._dns_out.setText(output)
        self._dns_btn.setEnabled(True)
        self._dns_btn.setText("🔍  Lookup")
        self.log("DNS lookup complete.", "success")


# ─────────────────────────────────────────────
# Dashboard page
# ─────────────────────────────────────────────
class DashboardPage(QWidget):
    def __init__(self, log_fn):
        super().__init__()
        self.log = log_fn
        self._worker = None
        self._build_ui()
        QTimer.singleShot(500, self._refresh)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(18, 18, 18, 18)

        title_row = QHBoxLayout()
        title_row.addWidget(make_label("🏠  Dashboard", bold=True, size=18))
        title_row.addStretch()
        self._refresh_btn = make_btn("🔄  Refresh", "#2d3748")
        self._refresh_btn.clicked.connect(self._refresh)
        title_row.addWidget(self._refresh_btn)
        root.addLayout(title_row)
        root.addWidget(hline())

        # Stat cards row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self._stats = {}
        stat_defs = [
            ("hostname",      "🖥️  Hostname",          CLR_ACCENT),
            ("os",            "💿  OS",                 CLR_ACCENT2),
            ("uptime",        "⏱️  Uptime",             "#2d5a3d"),
            ("conn_count",    "🔗  Connections",        "#2d3748"),
            ("rule_count",    "🔒  FW Rules",           "#2d3748"),
            ("services_up",   "🛠️  Services Up",        CLR_SUCCESS),
            ("blocked_ips",   "🚫  Blocked IPs",        CLR_DANGER),
        ]
        for key, label, color in stat_defs:
            card = QFrame()
            card.setStyleSheet(
                f"background-color: {CLR_CARD}; border: 1px solid {color}50;"
                f" border-radius: 10px; padding: 4px;"
            )
            vl = QVBoxLayout(card)
            vl.setContentsMargins(14, 10, 14, 10)
            lbl = make_label(label, muted=True, size=11)
            val = make_label("…", bold=True, size=20)
            val.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: 800;")
            vl.addWidget(lbl)
            vl.addWidget(val)
            stats_row.addWidget(card, 1)
            self._stats[key] = val
        root.addLayout(stats_row)

        # System info card
        info_card = make_card("🔍  System Details")
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(12, 8, 12, 12)
        self._info_out = make_output(140)
        info_layout.addWidget(self._info_out)
        info_card.setLayout(info_layout)
        root.addWidget(info_card)

        root.addStretch()

    def _refresh(self):
        if self._worker and self._worker.isRunning():
            return
        self._refresh_btn.setEnabled(False)
        self._worker = DashboardWorker()
        self._worker.finished.connect(self._on_done)
        self._worker.start()

    def _on_done(self, data):
        self._refresh_btn.setEnabled(True)
        for key, lbl in self._stats.items():
            v = data.get(key, "—")
            if key == "services_up":
                v = f"{data.get('services_up','?')} / {data.get('services_total','?')}"
            lbl.setText(v)
        details = (
            f"Hostname : {data.get('hostname','?')}\n"
            f"OS       : {data.get('os','?')}\n"
            f"Uptime   : {data.get('uptime','?')}\n"
            f"Firewall : {'netsh (Windows)' if IS_WINDOWS else 'iptables (Linux)'}\n"
            f"FW Rules : {data.get('rule_count','?')}\n"
            f"Conns    : {data.get('conn_count','?')} active sockets\n"
            f"Services : {data.get('services_up','?')}/{data.get('services_total','?')} running\n"
            f"Blocked  : {data.get('blocked_ips','?')} IPs in history\n"
        )
        self._info_out.setText(details)
        self.log("Dashboard refreshed.", "info")


# ─────────────────────────────────────────────
# IP History / Watchlist page
# ─────────────────────────────────────────────
class IPHistoryPage(QWidget):
    def __init__(self, log_fn):
        super().__init__()
        self.log = log_fn
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(12)
        root.setContentsMargins(18, 18, 18, 18)

        title_row = QHBoxLayout()
        title_row.addWidget(make_label("🗂️  Blocked IP History", bold=True, size=18))
        title_row.addStretch()
        refresh_btn = make_btn("🔄  Refresh", "#2d3748")
        refresh_btn.clicked.connect(self._refresh)
        clear_btn = make_btn("🗑️  Clear History", CLR_DANGER)
        clear_btn.clicked.connect(self._clear_history)
        title_row.addWidget(refresh_btn)
        title_row.addWidget(clear_btn)
        root.addLayout(title_row)

        note = make_label(
            "All IPs you have blocked or unblocked are logged here with timestamps.",
            muted=True, size=12
        )
        root.addWidget(note)
        root.addWidget(hline())

        # Re-block from history row
        reblock_row = QHBoxLayout()
        reblock_row.setSpacing(8)
        self._reblock_input = make_input("Enter IP to re-block from history")
        reblock_btn = make_btn("⛔  Re-block IP", CLR_DANGER)
        reblock_btn.clicked.connect(self._reblock_ip)
        reblock_row.addWidget(make_label("Quick re-block:"))
        reblock_row.addWidget(self._reblock_input, 2)
        reblock_row.addWidget(reblock_btn)
        reblock_row.addStretch()
        root.addLayout(reblock_row)

        # Table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["IP Address", "Action", "Time", "Reason"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {CLR_SURFACE};
                color: {CLR_TEXT};
                border: 1px solid {CLR_BORDER};
                border-radius: 8px;
                gridline-color: {CLR_BORDER};
                font-size: 13px;
            }}
            QHeaderView::section {{
                background-color: {CLR_CARD};
                color: {CLR_MUTED};
                border: none;
                padding: 6px;
                font-weight: bold;
            }}
            QTableWidget::item:selected {{
                background-color: {CLR_ACCENT}44;
            }}
        """)
        root.addWidget(self._table)

        self._count_lbl = make_label("", muted=True, size=11)
        root.addWidget(self._count_lbl)

    def _refresh(self):
        entries = _load_block_history()
        self._table.setRowCount(0)
        for e in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            ip_item = QTableWidgetItem(e.get("ip", ""))
            action  = e.get("action", "")
            action_item = QTableWidgetItem(action)
            if action == "blocked":
                action_item.setForeground(QColor(CLR_DANGER))
            elif action == "unblocked":
                action_item.setForeground(QColor(CLR_SUCCESS))
            self._table.setItem(row, 0, ip_item)
            self._table.setItem(row, 1, action_item)
            self._table.setItem(row, 2, QTableWidgetItem(e.get("time", "")))
            self._table.setItem(row, 3, QTableWidgetItem(e.get("reason", "")))
        self._count_lbl.setText(f"{len(entries)} entries  ·  saved in block_history.json")

    def _clear_history(self):
        if QMessageBox.question(
            self, "Clear History", "Delete all block history entries?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return
        _save_block_history([])
        self._refresh()
        self.log("Block history cleared.", "warn")

    def _reblock_ip(self):
        ip = self._reblock_input.text().strip()
        if not validate_ip(ip):
            QMessageBox.warning(self, "Input Error", "Enter a valid IPv4 address.")
            return
        rc, out, err = fw_block_ip(ip)
        if rc == 0:
            _add_block_history(ip, "blocked", "re-blocked from history")
            self.log(f"Re-blocked IP: {ip}", "warn")
            self._reblock_input.clear()
            self._refresh()
        else:
            self.log(f"Re-block failed: {err or out}", "error")
            QMessageBox.critical(self, "Error", err or out)


# ─────────────────────────────────────────────
# Help page
# ─────────────────────────────────────────────
class HelpPage(QWidget):
    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(24, 24, 24, 24)

        root.addWidget(make_label("❓  Help & User Guide", bold=True, size=18))
        root.addWidget(hline())

        intro = make_label(
            "Welcome to NetCommander! This guide explains every feature so you can use the tool "
            "confidently — even if you have never touched a firewall before.",
            muted=True, size=13
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        sections = [
            ("🔒  Firewall Tab — What is it?",
             "A firewall controls which network traffic is allowed into or out of your computer. "
             "NetCommander lets you create, view, and delete firewall rules without typing any commands."),

            ("➕  Add Firewall Rule",
             "• Protocol — Choose TCP (most apps: web, SSH, FTP) or UDP (DNS, games, VoIP).\n"
             "• Port — The port number the rule applies to (e.g. 80 = web, 22 = SSH, 443 = HTTPS).\n"
             "• Action — ACCEPT lets traffic through. DROP silently ignores it. REJECT sends an error back.\n"
             "• Source IP — Optional. Fill this in to target only a specific sender's IP address.\n\n"
             "Click  ＋ Add Rule  to apply. The rule list below will refresh automatically."),

            ("🚫  Block / Unblock IP",
             "Enter any IPv4 address (e.g. 192.168.1.100) and press Block to instantly drop all "
             "inbound traffic from that address. Press Unblock to remove the block.\n\n"
             "Useful for banning a suspicious device on your network."),

            ("🔄  Refresh / 🗑️ Flush / 💾 Export",
             "• Refresh — Reloads the live rule list from the system firewall.\n"
             "• Flush All Rules — DANGER: deletes every inbound rule. You will be asked to confirm.\n"
             "• Export Rules — Saves a backup of all current rules to a file you choose.\n"
             "• Auto-refresh (10s) — Tick this box to keep the rule list updated automatically."),

            ("🔍  Port Scanner (nmap)",
             "Nmap scans a target IP address to discover which ports are open.\n\n"
             "• Basic (-Pn) — Simple scan, no host-alive check. Good default.\n"
             "• Version detect (-sV) — Also identifies what software is running on each port.\n"
             "• OS detect (-O) — Tries to guess the target's operating system. Needs admin/root.\n"
             "• Aggressive (-A) — Combines OS, version, scripts, and traceroute. Slow but thorough.\n\n"
             "⚠  Only scan IP addresses you own or have written permission to scan."),

            ("🛠️  Services Tab",
             "Start or stop common network services running on this machine:\n\n"
             "• ssh (port 22) — Secure Shell remote login.\n"
             "• apache2 (port 80) — Apache web server.\n"
             "• vsftpd (port 21) — FTP file transfer server.\n"
             "• xrdp (port 3389) — Remote Desktop (RDP) server.\n\n"
             "The coloured dot next to each service shows its current status:\n"
             "  ● Green = running (active)\n"
             "  ● Red = stopped (inactive)\n"
             "  ● Grey = not installed / not found"),

            ("📋  Activity Log",
             "The log panel at the bottom records every action you perform with a timestamp and "
             "colour-coded result:\n"
             "  ✔ Green = success\n"
             "  ⚠ Amber = warning (e.g. flush)\n"
             "  ✖ Red   = error\n"
             "  ℹ Grey  = informational\n\n"
             "Press Clear to wipe the log. Drag the divider up or down to resize it."),

            ("🔐  Permissions",
             "Firewall and service commands require elevated privileges:\n\n"
             "• Windows — Run NetCommander as Administrator (right-click → Run as administrator).\n"
             "• Linux / Kali / Ubuntu — Run with  sudo python codefile.py  or grant your user "
             "passwordless sudo for iptables.\n\n"
             "Without the right permissions, commands will fail and an error will appear in the log."),
        ]

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border: none; background: transparent;")
        content = QWidget()
        content.setStyleSheet(f"background-color: {CLR_BG};")
        cl = QVBoxLayout(content)
        cl.setSpacing(12)
        cl.setContentsMargins(0, 0, 12, 12)

        for heading, body in sections:
            card = make_card(heading)
            card_layout = QVBoxLayout()
            card_layout.setContentsMargins(10, 6, 10, 10)
            body_lbl = QLabel(body)
            body_lbl.setWordWrap(True)
            body_lbl.setStyleSheet(f"color: {CLR_TEXT}; font-size: 13px; line-height: 1.6;")
            card_layout.addWidget(body_lbl)
            card.setLayout(card_layout)
            cl.addWidget(card)

        cl.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll)


# ─────────────────────────────────────────────
# About page
# ─────────────────────────────────────────────
class AboutPage(QWidget):
    def __init__(self):
        super().__init__()
        root = QVBoxLayout(self)
        root.setSpacing(16)
        root.setContentsMargins(24, 24, 24, 24)

        root.addWidget(make_label("👤  About NetCommander", bold=True, size=18))
        root.addWidget(hline())

        # Hero card
        hero = make_card("")
        hero_layout = QVBoxLayout()
        hero_layout.setContentsMargins(20, 16, 20, 20)
        hero_layout.setSpacing(6)

        name_lbl = QLabel("NetCommander")
        name_lbl.setStyleSheet(f"color: {CLR_ACCENT}; font-size: 26px; font-weight: 800; letter-spacing: 2px;")
        name_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        tagline = make_label("Cross-Platform Firewall & Service Manager", muted=True, size=13)
        tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)

        version = make_label("Version 1.0", muted=True, size=12)
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)

        hero_layout.addWidget(name_lbl)
        hero_layout.addWidget(tagline)
        hero_layout.addWidget(version)
        hero.setLayout(hero_layout)
        root.addWidget(hero)

        # Author card
        author_card = make_card("✍️  Author")
        author_layout = QGridLayout()
        author_layout.setContentsMargins(14, 8, 14, 14)
        author_layout.setSpacing(10)

        def row(label, value, row_idx):
            author_layout.addWidget(make_label(label, muted=True, size=12), row_idx, 0)
            v = make_label(value, bold=True, size=13)
            author_layout.addWidget(v, row_idx, 1)

        row("Name",    "Bhavya Sehgal",                          0)
        row("Project", "NetCommander",                              1)
        row("Version", "1.0",                                     2)
        row("License", "MIT — free to use and modify",            3)

        author_card.setLayout(author_layout)
        root.addWidget(author_card)

        # Description card
        desc_card = make_card("📄  Description")
        desc_layout = QVBoxLayout()
        desc_layout.setContentsMargins(14, 8, 14, 14)
        desc_text = QLabel(
            "NetCommander is a graphical firewall and service management tool built with Python and PyQt6. "
            "It provides a clean, beginner-friendly interface to manage inbound firewall rules, "
            "block/unblock IP addresses, scan open ports via nmap, and control common system services — "
            "all without needing to remember command-line syntax.\n\n"
            "It runs natively on Windows (using netsh / Windows Firewall) and all major Linux "
            "distributions including Kali Linux and Ubuntu (using iptables / systemctl)."
        )
        desc_text.setWordWrap(True)
        desc_text.setStyleSheet(f"color: {CLR_TEXT}; font-size: 13px; line-height: 1.6;")
        desc_layout.addWidget(desc_text)
        desc_card.setLayout(desc_layout)
        root.addWidget(desc_card)

        # Tech stack card
        tech_card = make_card("🧰  Built With")
        tech_layout = QVBoxLayout()
        tech_layout.setContentsMargins(14, 8, 14, 14)
        tech_layout.setSpacing(4)
        stack = [
            ("Python 3.8+",  "Core language"),
            ("PyQt6",        "GUI framework"),
            ("iptables",     "Firewall backend on Linux"),
            ("netsh",        "Firewall backend on Windows"),
            ("nmap",         "Port scanning (must be installed separately)"),
            ("systemctl",    "Service management on Linux"),
            ("sc.exe",       "Service management on Windows"),
        ]
        for tech, desc in stack:
            row_w = QHBoxLayout()
            row_w.setSpacing(8)
            t = make_label(f"• {tech}", bold=True, size=13)
            t.setFixedWidth(170)
            d = make_label(desc, muted=True, size=12)
            row_w.addWidget(t)
            row_w.addWidget(d)
            row_w.addStretch()
            tech_layout.addLayout(row_w)
        tech_card.setLayout(tech_layout)
        root.addWidget(tech_card)

        root.addStretch()


# ─────────────────────────────────────────────
# Sidebar navigation
# ─────────────────────────────────────────────
class Sidebar(QWidget):
    page_changed = pyqtSignal(int)

    NAV_ITEMS = [
        ("🏠", "Dashboard"),
        ("🔒", "Firewall"),
        ("🛠️", "Services"),
        ("🌐", "Network"),
        ("📡", "Ping/DNS"),
        ("🗂️", "IP History"),
        ("❓", "Help"),
        ("👤", "About"),
    ]

    def __init__(self):
        super().__init__()
        self.setFixedWidth(160)
        self.setStyleSheet(f"background-color: {CLR_SIDEBAR};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo area
        logo = QLabel("NetCommander")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet(f"""
            color: {CLR_ACCENT};
            font-size: 16px;
            font-weight: 800;
            padding: 22px 10px 10px 10px;
            letter-spacing: 1px;
        """)
        layout.addWidget(logo)

        sub = QLabel("v1.0  ·  " + ("Windows" if IS_WINDOWS else platform.system()))
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub.setStyleSheet(f"color: {CLR_MUTED}; font-size: 10px; padding-bottom: 14px;")
        layout.addWidget(sub)

        sep = hline()
        sep.setStyleSheet(f"color: {CLR_BORDER}; margin: 0 12px;")
        layout.addWidget(sep)

        self._buttons = []
        for idx, (icon, label) in enumerate(self.NAV_ITEMS):
            btn = QPushButton(f"  {icon}  {label}")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(self._btn_style(False))
            btn.clicked.connect(lambda _, i=idx: self._select(i))
            layout.addWidget(btn)
            self._buttons.append(btn)

        layout.addStretch()

        # OS info at bottom
        os_info = make_label(platform.system() + " " + platform.release(), muted=True, size=10)
        os_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        os_info.setWordWrap(True)
        os_info.setStyleSheet(f"color: {CLR_BORDER}; font-size: 10px; padding: 8px;")
        layout.addWidget(os_info)

        self._select(0)

    def _btn_style(self, active):
        bg   = CLR_ACCENT if active else "transparent"
        color = "#ffffff" if active else CLR_MUTED
        return f"""
            QPushButton {{
                background-color: {bg};
                color: {color};
                border: none;
                border-radius: 0;
                padding: 12px 16px;
                text-align: left;
                font-size: 13px;
                font-weight: {'700' if active else '400'};
            }}
            QPushButton:hover {{ background-color: {'#3a4fc4' if active else CLR_SURFACE}; }}
        """

    def _select(self, idx):
        for i, btn in enumerate(self._buttons):
            btn.setChecked(i == idx)
            btn.setStyleSheet(self._btn_style(i == idx))
        self.page_changed.emit(idx)

# ─────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────
class NetCommanderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetCommander — Firewall & Service Manager")
        self.setMinimumSize(1100, 750)
        self.resize(1200, 820)

        # Global palette
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(CLR_BG))
        pal.setColor(QPalette.ColorRole.WindowText, QColor(CLR_TEXT))
        self.setPalette(pal)

        central = QWidget()
        central.setStyleSheet(f"background-color: {CLR_BG};")
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = Sidebar()
        main_layout.addWidget(self.sidebar)

        # Right side: pages + log
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Pages stack
        self.pages = QStackedWidget()
        self.pages.setStyleSheet(f"background-color: {CLR_BG};")

        self.log_panel = LogPanel()

        self.dash_page    = DashboardPage(self.log_panel.append)
        self.fw_page      = FirewallPage(self.log_panel.append)
        self.svc_page     = ServicesPage(self.log_panel.append)
        self.net_page     = NetworkMonitorPage(self.log_panel.append)
        self.pingdns_page = PingDNSPage(self.log_panel.append)
        self.hist_page    = IPHistoryPage(self.log_panel.append)
        self.help_page    = HelpPage()
        self.about_page   = AboutPage()

        def _scroll(widget):
            sa = QScrollArea()
            sa.setWidgetResizable(True)
            sa.setStyleSheet("border: none; background: transparent;")
            sa.setWidget(widget)
            return sa

        self.pages.addWidget(_scroll(self.dash_page))     # 0 Dashboard
        self.pages.addWidget(_scroll(self.fw_page))       # 1 Firewall
        self.pages.addWidget(_scroll(self.svc_page))      # 2 Services
        self.pages.addWidget(_scroll(self.net_page))      # 3 Network
        self.pages.addWidget(_scroll(self.pingdns_page))  # 4 Ping/DNS
        self.pages.addWidget(_scroll(self.hist_page))     # 5 IP History
        self.pages.addWidget(_scroll(self.help_page))     # 6 Help
        self.pages.addWidget(_scroll(self.about_page))    # 7 About

        # Splitter: pages on top, log on bottom
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{ background-color: {CLR_BORDER}; height: 2px; }}
        """)
        pages_wrap = QWidget()
        pages_wrap.setLayout(QVBoxLayout())
        pages_wrap.layout().setContentsMargins(0, 0, 0, 0)
        pages_wrap.layout().addWidget(self.pages)

        splitter.addWidget(pages_wrap)
        splitter.addWidget(self.log_panel)
        splitter.setSizes([580, 160])

        right_layout.addWidget(splitter)
        main_layout.addWidget(right)

        self.sidebar.page_changed.connect(self.pages.setCurrentIndex)

        # Status bar
        self.statusBar().setStyleSheet(f"""
            QStatusBar {{
                background-color: {CLR_SIDEBAR};
                color: {CLR_MUTED};
                font-size: 11px;
                border-top: 1px solid {CLR_BORDER};
                padding: 2px 8px;
            }}
        """)
        self.statusBar().showMessage(
            f"NetCommander ready  ·  {platform.system()} {platform.release()}  "
            f"·  Backend: {'netsh' if IS_WINDOWS else 'iptables'}"
        )

        self.log_panel.append("NetCommander started.", "info")
        self.log_panel.append(
            f"Platform: {platform.system()} {platform.release()} — "
            f"backend: {'netsh (Windows Firewall)' if IS_WINDOWS else 'iptables'}",
            "info"
        )

# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    gui = NetCommanderGUI()
    gui.show()
    sys.exit(app.exec())
