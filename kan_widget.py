from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import psutil
import requests
from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QScrollArea,
    QStackedWidget, QVBoxLayout, QWidget, QInputDialog, QTextEdit, QCheckBox,
)

APP_NAME = "Kan Widget"
APP_VERSION = "0.1.1"
APP_DIR = Path(os.getenv("APPDATA", str(Path.home()))) / "KanWidget"
SETTINGS_FILE = APP_DIR / "settings.json"
VPN_CONFIG_FILE = APP_DIR / "sing-box.json"
PROXY_SNAPSHOT_FILE = APP_DIR / "proxy_snapshot.json"
ENGINE_DIR = APP_DIR / "engine"
ENGINE_LOG_FILE = ENGINE_DIR / "sing-box.log"
MIXED_PORT = 20808
GITHUB_API = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"

DEFAULT_SETTINGS: dict[str, Any] = {
    "apps": [],
    "subscription_url": "",
    "nodes": [],
    "selected_node": "",
    "notes": "",
    "tasks": [],
    "theme": "dark",
    "always_on_top": False,
    "proxy_snapshot": None,
}


def load_settings() -> dict[str, Any]:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if SETTINGS_FILE.exists():
        try:
            loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            # Keep a recoverable copy instead of silently overwriting damaged data.
            try:
                backup = SETTINGS_FILE.with_suffix(".corrupt.json")
                if not backup.exists():
                    shutil.copy2(SETTINGS_FILE, backup)
            except OSError:
                pass
    settings = {**DEFAULT_SETTINGS, **data}
    for key in ("apps", "nodes", "tasks"):
        if not isinstance(settings.get(key), list):
            settings[key] = []
    for key in ("subscription_url", "selected_node", "notes"):
        if not isinstance(settings.get(key), str):
            settings[key] = ""
    if settings.get("theme") not in ("dark", "light"):
        settings["theme"] = "dark"
    if not isinstance(settings.get("always_on_top"), bool):
        settings["always_on_top"] = False
    return settings


def save_settings(settings: dict[str, Any]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temp_path = SETTINGS_FILE.with_suffix(".tmp")
    payload = json.dumps(settings, ensure_ascii=False, indent=2)
    temp_path.write_text(payload, encoding="utf-8")
    os.replace(temp_path, SETTINGS_FILE)


def decode_subscription(raw: str) -> str:
    raw = raw.strip().lstrip("\ufeff")
    if re.search(r"(?im)^(vless|vmess|trojan|ss|hysteria2|hy2|tuic|wireguard)://", raw):
        return raw
    compact = re.sub(r"\s+", "", raw)
    try:
        padded = compact + "=" * ((4 - len(compact) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode()).decode("utf-8", errors="replace")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return raw


def b64_text(value: str) -> str:
    value = value.strip()
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value.encode()).decode("utf-8", errors="replace")


def query_first(query: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        values = query.get(name)
        if values:
            return values[0]
    return default


def transport_from_query(q: dict[str, list[str]]) -> dict[str, Any] | None:
    net = query_first(q, "type", "network", default="tcp").lower()
    header_type = query_first(q, "headerType")
    if header_type and header_type.lower() not in ("none",):
        raise ValueError(f"هدر TCP از نوع {header_type} هنوز پشتیبانی نمی‌شود")
    if net in ("tcp", "none", ""):
        return None
    if net == "ws":
        result: dict[str, Any] = {"type": "ws"}
        path = query_first(q, "path")
        host = query_first(q, "host")
        if path:
            result["path"] = urllib.parse.unquote(path)
        if host:
            result["headers"] = {"Host": host}
        return result
    if net == "grpc":
        result = {"type": "grpc"}
        service = query_first(q, "serviceName", "service_name", "path")
        if service:
            result["service_name"] = urllib.parse.unquote(service).strip("/")
        return result
    if net == "httpupgrade":
        result = {"type": "httpupgrade"}
        path = query_first(q, "path")
        host = query_first(q, "host")
        if path:
            result["path"] = path
        if host:
            result["host"] = host
        return result
    raise ValueError(f"انتقال شبکه {net} هنوز پشتیبانی نمی‌شود")


def tls_from_query(q: dict[str, list[str]], server: str) -> dict[str, Any] | None:
    security = query_first(q, "security").lower()
    if security not in ("tls", "reality"):
        return None
    sni = query_first(q, "sni", "servername", "peer", default=server)
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": sni,
        "insecure": query_first(q, "allowInsecure", "insecure", default="0") in ("1", "true", "yes"),
    }
    fp = query_first(q, "fp", "fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    alpn = query_first(q, "alpn")
    if alpn:
        tls["alpn"] = [item.strip() for item in alpn.split(",") if item.strip()]
    if security == "reality":
        public_key = query_first(q, "pbk", "publicKey")
        short_id = query_first(q, "sid", "shortId")
        if not public_key:
            raise ValueError("پارامتر public key (pbk) برای Reality پیدا نشد")
        # sing-box expects short_id even when the server uses an empty short ID.
        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": short_id,
        }
    return tls


def parse_vmess(uri: str) -> dict[str, Any]:
    payload = uri[len("vmess://"):].split("#", 1)[0]
    obj = json.loads(b64_text(payload))
    server = str(obj.get("add", "")).strip()
    port = int(obj.get("port", 0))
    uuid = str(obj.get("id", ""))
    if not server or not port or not uuid:
        raise ValueError("اطلاعات VMess ناقص است")
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else str(obj.get("ps", "VMess"))
    outbound: dict[str, Any] = {
        "type": "vmess", "tag": name or "VMess", "server": server,
        "server_port": port, "uuid": uuid,
        "security": str(obj.get("scy", "auto") or "auto"),
        "alter_id": int(obj.get("aid", 0) or 0),
    }
    net = str(obj.get("net", "tcp")).lower()
    if net == "ws":
        transport = {"type": "ws"}
        path = str(obj.get("path", ""))
        host = str(obj.get("host", ""))
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": str(obj.get("path", "")).strip("/")}
    elif net not in ("tcp", "none", ""):
        raise ValueError(f"انتقال VMess با نوع {net} هنوز پشتیبانی نمی‌شود")
    if str(obj.get("tls", "")).lower() in ("tls", "true", "1"):
        tls = {"enabled": True, "server_name": str(obj.get("sni") or obj.get("host") or server)}
        if obj.get("allowInsecure") in ("1", 1, True, "true"):
            tls["insecure"] = True
        fp = obj.get("fp")
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": str(fp)}
        outbound["tls"] = tls
    return {"name": name or "VMess", "outbound": outbound}


def parse_uri(uri: str) -> dict[str, Any]:
    uri = uri.strip()
    if uri.lower().startswith("vmess://"):
        return parse_vmess(uri)
    parsed = urllib.parse.urlsplit(uri)
    scheme = parsed.scheme.lower()
    if scheme not in ("vless", "trojan", "ss"):
        raise ValueError(f"پروتکل {scheme or 'نامشخص'} در این نسخه پشتیبانی نمی‌شود")
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else scheme.upper()
    q = urllib.parse.parse_qs(parsed.query)
    if scheme == "ss":
        # Supports SIP002: ss://method:password@host:port
        # and the common base64-userinfo form.
        netloc = parsed.netloc.rsplit("@", 1)
        if len(netloc) == 2:
            userinfo, hostport = netloc
            userinfo = urllib.parse.unquote(userinfo)
            if ":" not in userinfo:
                userinfo = b64_text(userinfo)
            if ":" not in userinfo:
                raise ValueError("اطلاعات احراز هویت Shadowsocks نامعتبر است")
            method, password = userinfo.split(":", 1)
            host_parsed = urllib.parse.urlsplit("//" + hostport)
            server, port = host_parsed.hostname, host_parsed.port
        else:
            decoded = b64_text(parsed.netloc)
            host_parsed = urllib.parse.urlsplit("//" + decoded.split("@", 1)[1])
            method, password = decoded.split("@", 1)[0].split(":", 1)
            server, port = host_parsed.hostname, host_parsed.port
        if not server or not port or not (1 <= int(port) <= 65535):
            raise ValueError("آدرس Shadowsocks نامعتبر است")
        outbound = {
            "type": "shadowsocks", "tag": name,
            "server": server, "server_port": int(port),
            "method": method, "password": password,
        }
        plugin = query_first(q, "plugin")
        if plugin:
            plugin_name, separator, plugin_opts = plugin.partition(";")
            if plugin_name not in ("obfs-local", "v2ray-plugin"):
                raise ValueError(f"افزونه Shadowsocks با نام {plugin_name} پشتیبانی نمی‌شود")
            outbound["plugin"] = plugin_name
            if separator and plugin_opts:
                outbound["plugin_opts"] = plugin_opts
        return {"name": name, "outbound": outbound}

    server = parsed.hostname
    port = parsed.port
    if not server or not port or not (1 <= int(port) <= 65535):
        raise ValueError("آدرس سرور یا پورت نامعتبر است")
    outbound: dict[str, Any] = {"type": scheme, "tag": name, "server": server, "server_port": int(port)}
    if scheme == "vless":
        outbound["uuid"] = urllib.parse.unquote(parsed.username or "")
        outbound["flow"] = query_first(q, "flow")
        if not outbound["uuid"]:
            raise ValueError("UUID در لینک VLESS پیدا نشد")
        if not outbound["flow"]:
            outbound.pop("flow")
    elif scheme == "trojan":
        outbound["password"] = urllib.parse.unquote(parsed.username or "")
        if not outbound["password"]:
            raise ValueError("رمز Trojan پیدا نشد")
    tls = tls_from_query(q, server)
    if tls:
        outbound["tls"] = tls
    transport = transport_from_query(q)
    if transport:
        outbound["transport"] = transport
    return {"name": name, "outbound": outbound}


def parse_subscription(content: str) -> list[dict[str, Any]]:
    text_content = decode_subscription(content)
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"(?i)^(vless|vmess|trojan|ss)://", line):
            continue
        try:
            node = parse_uri(line)
            outbound_signature = dict(node["outbound"])
            outbound_signature.pop("tag", None)
            signature = json.dumps(outbound_signature, sort_keys=True, ensure_ascii=False)
            if signature not in seen:
                seen.add(signature)
                nodes.append(node)
        except Exception:
            continue
    return nodes


def fetch_subscription_text(url: str, max_bytes: int = 8 * 1024 * 1024) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("آدرس اشتراک باید با http:// یا https:// شروع شود")
    if parsed.username or parsed.password:
        raise ValueError("نام کاربری و رمز را داخل آدرس اشتراک قرار نده")

    chunks: list[bytes] = []
    total = 0
    headers = {"User-Agent": f"KanWidget/{APP_VERSION}"}
    with requests.get(url, stream=True, timeout=(10, 30), headers=headers) as response:
        response.raise_for_status()
        declared_size = response.headers.get("Content-Length")
        if declared_size and declared_size.isdigit() and int(declared_size) > max_bytes:
            raise ValueError("حجم فایل اشتراک بیش از ۸ مگابایت است")
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("حجم فایل اشتراک بیش از ۸ مگابایت است")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8-sig", errors="replace")


def format_bytes(value: float) -> str:
    units = ["B/s", "KB/s", "MB/s", "GB/s"]
    n = max(0.0, float(value))
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB/s"


class Worker(QObject):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn, *args):
        super().__init__()
        self.fn = fn
        self.args = args

    def run(self):
        try:
            self.done.emit(self.fn(*self.args))
        except Exception as exc:
            self.failed.emit(str(exc))


class MetricCard(QFrame):
    def __init__(self, title: str, icon: str, value: str = "--", subtitle: str = ""):
        super().__init__()
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        top = QHBoxLayout()
        title_label = QLabel(f"{icon}  {title}")
        title_label.setObjectName("muted")
        top.addWidget(title_label)
        top.addStretch()
        layout.addLayout(top)
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        layout.addWidget(self.value_label)
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("mutedSmall")
        layout.addWidget(self.subtitle_label)

    def set_values(self, value: str, subtitle: str = ""):
        self.value_label.setText(value)
        self.subtitle_label.setText(subtitle)


class KanWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.engine_process: subprocess.Popen | None = None
        self.active_thread: QThread | None = None
        self.active_worker: Worker | None = None
        self.operation_busy = False
        self.active_done_callback = None
        self.gpu_name_cache: str | None = None
        self.last_net = psutil.net_io_counters()
        self.last_net_time = time.time()
        self.current_theme = self.settings.get("theme", "dark")
        self.setWindowTitle(APP_NAME)
        self.resize(1120, 760)
        self.setMinimumSize(900, 640)
        self._recover_stale_proxy()
        self._build_ui()
        self._apply_theme()
        self._load_apps()
        self._load_nodes()
        self._apply_window_flags()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_metrics)
        self.timer.start(1000)
        self.update_metrics()
        atexit.register(self._shutdown_cleanup)

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        main = QHBoxLayout(root)
        main.setContentsMargins(0, 0, 0, 0)
        main.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(18, 24, 18, 18)
        side.setSpacing(12)
        brand = QLabel("KAN<span style='color:#48D9C2'>.</span>")
        brand.setObjectName("brand")
        side.addWidget(brand)
        tagline = QLabel("DESKTOP CONTROL CENTER")
        tagline.setObjectName("mutedSmall")
        side.addWidget(tagline)
        side.addSpacing(26)
        self.nav_buttons: list[QPushButton] = []
        for index, (label, icon) in enumerate((("داشبورد", "◈"), ("فیلترشکن", "⇄"), ("برنامه‌های من", "▦"), ("تنظیمات", "⚙"))):
            button = QPushButton(f"  {icon}   {label}")
            button.setObjectName("navButton")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self.show_page(i))
            side.addWidget(button)
            self.nav_buttons.append(button)
        side.addStretch()
        self.connection_badge = QLabel("●  VPN قطع است")
        self.connection_badge.setObjectName("connectionBadge")
        side.addWidget(self.connection_badge)
        version = QLabel(f"KAN WIDGET  •  v{APP_VERSION}")
        version.setObjectName("mutedSmall")
        side.addWidget(version)
        main.addWidget(sidebar)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(28, 22, 28, 24)
        content_layout.setSpacing(18)
        header = QHBoxLayout()
        self.page_title = QLabel("داشبورد")
        self.page_title.setObjectName("pageTitle")
        header.addWidget(self.page_title)
        header.addStretch()
        self.theme_button = QPushButton("☼  تغییر تم")
        self.theme_button.setObjectName("ghostButton")
        self.theme_button.clicked.connect(self.toggle_theme)
        header.addWidget(self.theme_button)
        content_layout.addLayout(header)

        self.pages = QStackedWidget()
        dashboard_scroll = QScrollArea()
        dashboard_scroll.setWidgetResizable(True)
        dashboard_scroll.setFrameShape(QFrame.NoFrame)
        dashboard_scroll.setWidget(self._dashboard_page())
        self.pages.addWidget(dashboard_scroll)
        self.pages.addWidget(self._vpn_page())
        self.pages.addWidget(self._apps_page())
        self.pages.addWidget(self._settings_page())
        content_layout.addWidget(self.pages)
        main.addWidget(content, 1)
        self.show_page(0)

    def _dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        hero = QFrame()
        hero.setObjectName("hero")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(24, 22, 24, 22)
        left = QVBoxLayout()
        greeting = QLabel("سلام! آماده‌ای؟")
        greeting.setObjectName("heroTitle")
        left.addWidget(greeting)
        desc = QLabel("وضعیت سیستم و ابزارهای موردنیازت همیشه یک‌جا هستند.")
        desc.setObjectName("heroSub")
        left.addWidget(desc)
        hero_layout.addLayout(left)
        hero_layout.addStretch()
        self.clock_label = QLabel("--:--")
        self.clock_label.setObjectName("clock")
        clock_col = QVBoxLayout()
        clock_col.addWidget(self.clock_label)
        self.date_label = QLabel("---")
        self.date_label.setObjectName("heroSub")
        self.date_label.setAlignment(Qt.AlignRight)
        clock_col.addWidget(self.date_label)
        hero_layout.addLayout(clock_col)
        layout.addWidget(hero)

        metrics = QGridLayout()
        metrics.setHorizontalSpacing(14)
        metrics.setVerticalSpacing(14)
        self.cpu_card = MetricCard("پردازنده", "◉", "--%", "CPU usage")
        self.ram_card = MetricCard("حافظه RAM", "▤", "--%", "Memory usage")
        self.disk_card = MetricCard("فضای دیسک", "▣", "--%", "System drive")
        self.net_card = MetricCard("شبکه", "⇅", "--", "↓ دریافت  •  ↑ ارسال")
        self.gpu_card = MetricCard("کارت گرافیک", "▥", "نامشخص", "در صورت پشتیبانی NVIDIA")
        self.uptime_card = MetricCard("زمان روشن بودن", "◷", "--", "System uptime")
        cards = [self.cpu_card, self.ram_card, self.disk_card, self.net_card, self.gpu_card, self.uptime_card]
        for i, card in enumerate(cards):
            metrics.addWidget(card, i // 3, i % 3)
        layout.addLayout(metrics)

        section_header = QHBoxLayout()
        section_title = QLabel("دسترسی سریع")
        section_title.setObjectName("sectionTitle")
        section_header.addWidget(section_title)
        section_header.addStretch()
        add = QPushButton("＋ افزودن برنامه")
        add.setObjectName("smallButton")
        add.clicked.connect(self.add_app)
        section_header.addWidget(add)
        layout.addLayout(section_header)
        self.quick_apps = QGridLayout()
        self.quick_apps.setHorizontalSpacing(12)
        self.quick_apps.setVerticalSpacing(12)
        self.quick_apps_host = QWidget()
        self.quick_apps_host.setLayout(self.quick_apps)
        layout.addWidget(self.quick_apps_host)

        productivity = QGridLayout()
        productivity.setHorizontalSpacing(14)
        productivity.setVerticalSpacing(12)
        notes_panel = QFrame()
        notes_panel.setObjectName("panel")
        notes_layout = QVBoxLayout(notes_panel)
        notes_layout.setContentsMargins(16, 14, 16, 14)
        notes_title = QLabel("یادداشت سریع")
        notes_title.setObjectName("sectionTitle")
        notes_layout.addWidget(notes_title)
        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("اینجا یادداشت‌های روزانه‌ات را بنویس...")
        self.notes_edit.setMaximumHeight(105)
        self.notes_edit.setPlainText(self.settings.get("notes", ""))
        self.notes_edit.textChanged.connect(self.save_notes)
        notes_layout.addWidget(self.notes_edit)
        tasks_panel = QFrame()
        tasks_panel.setObjectName("panel")
        tasks_layout = QVBoxLayout(tasks_panel)
        tasks_layout.setContentsMargins(16, 14, 16, 14)
        tasks_title = QLabel("چک‌لیست")
        tasks_title.setObjectName("sectionTitle")
        tasks_layout.addWidget(tasks_title)
        task_entry_row = QHBoxLayout()
        self.task_input = QLineEdit()
        self.task_input.setPlaceholderText("یک کار جدید...")
        self.task_input.returnPressed.connect(self.add_task)
        task_entry_row.addWidget(self.task_input, 1)
        task_add = QPushButton("＋")
        task_add.setObjectName("smallButton")
        task_add.clicked.connect(self.add_task)
        task_entry_row.addWidget(task_add)
        tasks_layout.addLayout(task_entry_row)
        self.tasks_container = QWidget()
        self.tasks_layout = QVBoxLayout(self.tasks_container)
        self.tasks_layout.setContentsMargins(0, 0, 0, 0)
        self.tasks_layout.setSpacing(4)
        tasks_layout.addWidget(self.tasks_container)
        productivity.addWidget(notes_panel, 0, 0)
        productivity.addWidget(tasks_panel, 0, 1)
        layout.addLayout(productivity)
        self._render_tasks()
        layout.addStretch()
        return page

    def _vpn_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        intro = QLabel("اتصال امن، انتخاب سرور و به‌روزرسانی اشتراک")
        intro.setObjectName("muted")
        layout.addWidget(intro)

        sub_card = QFrame()
        sub_card.setObjectName("panel")
        sub_layout = QVBoxLayout(sub_card)
        sub_layout.setContentsMargins(20, 18, 20, 18)
        label = QLabel("آدرس اشتراک (Subscription URL)")
        label.setObjectName("fieldLabel")
        sub_layout.addWidget(label)
        row = QHBoxLayout()
        self.subscription_input = QLineEdit(self.settings.get("subscription_url", ""))
        self.subscription_input.setPlaceholderText("https://example.com/subscription/...")
        row.addWidget(self.subscription_input, 1)
        self.update_sub_button = QPushButton("⟳  بروزرسانی")
        self.update_sub_button.setObjectName("primaryButton")
        self.update_sub_button.clicked.connect(self.update_subscription)
        row.addWidget(self.update_sub_button)
        sub_layout.addLayout(row)
        layout.addWidget(sub_card)

        node_card = QFrame()
        node_card.setObjectName("panel")
        node_layout = QVBoxLayout(node_card)
        node_layout.setContentsMargins(20, 18, 20, 18)
        node_header = QHBoxLayout()
        node_title = QLabel("انتخاب سرور")
        node_title.setObjectName("sectionTitle")
        node_header.addWidget(node_title)
        node_header.addStretch()
        self.node_count_label = QLabel("۰ سرور")
        self.node_count_label.setObjectName("mutedSmall")
        node_header.addWidget(self.node_count_label)
        node_layout.addLayout(node_header)
        self.node_combo = QComboBox()
        self.node_combo.setMinimumHeight(44)
        self.node_combo.currentIndexChanged.connect(self._on_node_changed)
        node_layout.addWidget(self.node_combo)
        button_row = QHBoxLayout()
        self.add_link_button = QPushButton("＋ افزودن لینک تکی")
        self.add_link_button.setObjectName("ghostButton")
        self.add_link_button.clicked.connect(self.add_single_link)
        button_row.addWidget(self.add_link_button)
        self.remove_nodes_button = QPushButton("پاک‌کردن لیست")
        self.remove_nodes_button.setObjectName("ghostButton")
        self.remove_nodes_button.clicked.connect(self.clear_nodes)
        button_row.addWidget(self.remove_nodes_button)
        button_row.addStretch()
        node_layout.addLayout(button_row)
        layout.addWidget(node_card)

        connect_card = QFrame()
        connect_card.setObjectName("connectPanel")
        connect_layout = QVBoxLayout(connect_card)
        connect_layout.setContentsMargins(20, 20, 20, 20)
        self.vpn_status = QLabel("●  اتصال برقرار نیست")
        self.vpn_status.setObjectName("sectionTitle")
        connect_layout.addWidget(self.vpn_status)
        self.vpn_detail = QLabel("برای شروع، اشتراک را وارد و سرور موردنظر را انتخاب کن.")
        self.vpn_detail.setObjectName("muted")
        connect_layout.addWidget(self.vpn_detail)
        action_row = QHBoxLayout()
        self.connect_button = QPushButton("اتصال")
        self.connect_button.setObjectName("primaryButton")
        self.connect_button.setMinimumHeight(46)
        self.connect_button.clicked.connect(self.connect_vpn)
        action_row.addWidget(self.connect_button)
        self.disconnect_button = QPushButton("قطع اتصال")
        self.disconnect_button.setObjectName("dangerButton")
        self.disconnect_button.setMinimumHeight(46)
        self.disconnect_button.setEnabled(False)
        self.disconnect_button.clicked.connect(self.disconnect_vpn)
        action_row.addWidget(self.disconnect_button)
        connect_layout.addLayout(action_row)
        layout.addWidget(connect_card)
        note = QLabel("پشتیبانی این نسخه: VLESS، VMess، Trojan و Shadowsocks. اتصال از طریق پراکسی ویندوز انجام می‌شود؛ برنامه‌هایی که پراکسی سیستم را نادیده می‌گیرند ممکن است از VPN عبور نکنند.")
        note.setObjectName("mutedSmall")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch()
        return page

    def _apps_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        intro = QLabel("برنامه‌ها و پوشه‌هایی که بیشتر استفاده می‌کنی")
        intro.setObjectName("muted")
        row.addWidget(intro)
        row.addStretch()
        button = QPushButton("＋ افزودن برنامه")
        button.setObjectName("primaryButton")
        button.clicked.connect(self.add_app)
        row.addWidget(button)
        layout.addLayout(row)
        self.apps_grid = QGridLayout()
        self.apps_grid.setHorizontalSpacing(12)
        self.apps_grid.setVerticalSpacing(12)
        self.apps_grid_host = QWidget()
        self.apps_grid_host.setLayout(self.apps_grid)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(self.apps_grid_host)
        layout.addWidget(scroll)
        return page

    def _settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        card = QFrame()
        card.setObjectName("panel")
        c = QVBoxLayout(card)
        c.setContentsMargins(22, 22, 22, 22)
        title = QLabel("تنظیمات برنامه")
        title.setObjectName("sectionTitle")
        c.addWidget(title)
        self.topmost_button = QPushButton("◻  همیشه روی پنجره‌های دیگر باشد")
        self.topmost_button.setObjectName("ghostButton")
        self.topmost_button.setCheckable(True)
        self.topmost_button.setChecked(bool(self.settings.get("always_on_top", False)))
        self.topmost_button.clicked.connect(self.toggle_topmost)
        c.addWidget(self.topmost_button)
        folder_row = QHBoxLayout()
        folder_row.addWidget(QLabel("محل ذخیره تنظیمات و هسته VPN:"))
        folder_row.addStretch()
        open_folder = QPushButton("بازکردن پوشه داده‌ها")
        open_folder.setObjectName("ghostButton")
        open_folder.clicked.connect(lambda: os.startfile(str(APP_DIR)) if os.name == "nt" else None)
        folder_row.addWidget(open_folder)
        c.addLayout(folder_row)
        tip = QLabel("هسته sing-box هنگام اولین اتصال از مخزن رسمی GitHub دریافت می‌شود. آدرس اشتراک و فهرست سرورها فقط روی همین دستگاه ذخیره می‌شوند.")
        tip.setObjectName("muted")
        tip.setWordWrap(True)
        c.addWidget(tip)
        layout.addWidget(card)
        layout.addStretch()
        return page

    def show_page(self, index: int):
        self.pages.setCurrentIndex(index)
        titles = ["داشبورد", "مدیریت فیلترشکن", "برنامه‌های من", "تنظیمات"]
        self.page_title.setText(titles[index])
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)

    def _apply_theme(self):
        if self.current_theme == "light":
            bg, panel, sidebar, text, muted = "#F3F6FA", "#FFFFFF", "#E9EEF5", "#172033", "#738096"
            border = "#E1E7EF"
        else:
            bg, panel, sidebar, text, muted = "#0D1220", "#151D2E", "#101827", "#EDF3FC", "#91A0B7"
            border = "#263247"
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{ background: {bg}; color: {text}; font-family: 'Segoe UI', 'Tahoma'; font-size: 10pt; }}
            #sidebar {{ background: {sidebar}; border-right: 1px solid {border}; }}
            #brand {{ font-size: 25pt; font-weight: 900; letter-spacing: 2px; }}
            #pageTitle {{ font-size: 21pt; font-weight: 800; }}
            #hero {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #192B42, stop:1 #183B48); border: 1px solid #285366; border-radius: 18px; }}
            #heroTitle {{ color: #FFFFFF; font-size: 19pt; font-weight: 800; }}
            #heroSub {{ color: #B7CAD9; font-size: 10pt; }}
            #clock {{ color: #6FE5D1; font-size: 31pt; font-weight: 800; }}
            QTextEdit {{ background: {bg}; border: 1px solid {border}; border-radius: 8px; padding: 7px; color: {text}; }}
            #metricCard, #panel, #connectPanel {{ background: {panel}; border: 1px solid {border}; border-radius: 15px; }}
            #metricValue {{ font-size: 23pt; font-weight: 800; }}
            #muted, #mutedSmall {{ color: {muted}; }}
            #mutedSmall {{ font-size: 8.5pt; }}
            #sectionTitle {{ font-size: 14pt; font-weight: 750; }}
            #fieldLabel {{ font-weight: 700; }}
            QPushButton {{ border: 1px solid {border}; border-radius: 10px; padding: 10px 14px; background: {panel}; color: {text}; }}
            QPushButton:hover {{ border-color: #48D9C2; }}
            QPushButton:checked, #navButton:checked {{ background: #1B3D4A; border-color: #286A70; color: #73E7D4; }}
            #navButton {{ text-align: left; border: none; background: transparent; padding: 13px 12px; font-size: 10.5pt; }}
            #primaryButton {{ background: #36CDB5; color: #071A1B; border: none; font-weight: 800; }}
            #primaryButton:hover {{ background: #61E0CB; }}
            #dangerButton {{ background: #4A2634; color: #FFB9C6; border-color: #6A3547; font-weight: 700; }}
            #ghostButton, #smallButton {{ background: transparent; }}
            #connectionBadge {{ background: {panel}; border: 1px solid {border}; border-radius: 10px; padding: 9px; color: {muted}; }}
            QLineEdit, QComboBox {{ background: {bg}; border: 1px solid {border}; border-radius: 9px; padding: 11px; color: {text}; selection-background-color: #2A8F83; }}
            QComboBox QAbstractItemView {{ background: {panel}; color: {text}; selection-background-color: #285B62; }}
            QScrollArea {{ border: none; background: transparent; }}
        """)

    def toggle_theme(self):
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.settings["theme"] = self.current_theme
        save_settings(self.settings)
        self._apply_theme()

    def _apply_window_flags(self):
        # Keep normal Windows window behavior while optionally staying on top.
        self.setWindowFlag(Qt.WindowStaysOnTopHint, bool(self.settings.get("always_on_top", False)))
        self.show()

    def toggle_topmost(self):
        self.settings["always_on_top"] = self.topmost_button.isChecked()
        save_settings(self.settings)
        self._apply_window_flags()

    def update_metrics(self):
        if self.engine_process and self.engine_process.poll() is not None:
            if self._restore_windows_proxy():
                self.engine_process = None
                self.connect_button.setEnabled(True)
                self.connect_button.setText("اتصال")
                self.disconnect_button.setEnabled(False)
                self.vpn_status.setText("●  اتصال برقرار نیست")
                self.vpn_detail.setText("هسته VPN متوقف شد و پراکسی قبلی ویندوز بازیابی شد.")
                self.connection_badge.setText("●  VPN قطع است")
                self.connection_badge.setStyleSheet("")
                self._set_vpn_controls_enabled(True)
            else:
                self.vpn_status.setText("●  بازیابی پراکسی ناموفق")
                self.vpn_detail.setText("هسته VPN متوقف شده، اما پراکسی ویندوز هنوز بازیابی نشده است. برای تلاش مجدد روی قطع اتصال بزن.")
                self.disconnect_button.setEnabled(True)
                self._set_vpn_controls_enabled(False)
        now = time.strftime("%H:%M")
        self.clock_label.setText(now)
        self.date_label.setText(time.strftime("%A  •  %d %B %Y"))
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        root = Path(os.getenv("SystemDrive", "C:") + "\\") if os.name == "nt" else Path("/")
        try:
            disk = psutil.disk_usage(str(root))
            self.disk_card.set_values(f"{disk.percent:.0f}%", f"{disk.used / (1024**3):.0f} / {disk.total / (1024**3):.0f} GB")
        except Exception:
            self.disk_card.set_values("--", "فضای دیسک")
        self.cpu_card.set_values(f"{cpu:.0f}%", f"{psutil.cpu_count(logical=True)} هسته منطقی")
        self.ram_card.set_values(f"{mem.percent:.0f}%", f"{mem.used / (1024**3):.1f} / {mem.total / (1024**3):.1f} GB")
        current = psutil.net_io_counters()
        t = time.time()
        dt = max(0.001, t - self.last_net_time)
        down = (current.bytes_recv - self.last_net.bytes_recv) / dt
        up = (current.bytes_sent - self.last_net.bytes_sent) / dt
        self.net_card.set_values(format_bytes(down), f"↑ {format_bytes(up)} ارسال")
        self.last_net, self.last_net_time = current, t
        self.uptime_card.set_values(self._uptime_text(), "از آخرین روشن‌شدن سیستم")
        if self.gpu_name_cache is None:
            self.gpu_name_cache = self._gpu_name()
        gpu = self.gpu_name_cache
        self.gpu_card.set_values(gpu, "NVIDIA / nvidia-smi" if gpu != "در دسترس نیست" else "درایور یا ابزار NVIDIA پیدا نشد")

    def _uptime_text(self) -> str:
        seconds = int(time.time() - psutil.boot_time())
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        return f"{days} روز {hours:02d}:{minutes:02d}"

    def _gpu_name(self) -> str:
        try:
            result = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                                    capture_output=True, text=True, timeout=1, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[0][:24]
        except Exception:
            pass
        return "در دسترس نیست"

    def _load_apps(self):
        for grid in (self.quick_apps, self.apps_grid):
            while grid.count():
                item = grid.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
        apps = self.settings.get("apps", [])
        for i, app in enumerate(apps):
            tile = self._app_tile(app, i)
            self.apps_grid.addWidget(tile, i // 3, i % 3)
            if i < 6:
                self.quick_apps.addWidget(self._app_tile(app, i, compact=True), i // 3, i % 3)
        if not apps:
            empty = QLabel("هنوز برنامه‌ای اضافه نکردی. از دکمه «افزودن برنامه» شروع کن.")
            empty.setObjectName("muted")
            self.apps_grid.addWidget(empty, 0, 0)
            self.quick_apps.addWidget(QLabel("برای دسترسی سریع، برنامه دلخواهت را اضافه کن."), 0, 0)

    def _app_tile(self, app: dict[str, str], index: int, compact: bool = False) -> QFrame:
        tile = QFrame()
        tile.setObjectName("metricCard")
        tile.setMinimumHeight(74 if compact else 96)
        row = QHBoxLayout(tile)
        row.setContentsMargins(14, 12, 14, 12)
        icon = QLabel(app.get("icon", "▣"))
        icon.setStyleSheet("font-size: 20pt; color: #55DCC5;")
        row.addWidget(icon)
        names = QVBoxLayout()
        name = QLabel(app.get("name", "برنامه"))
        name.setStyleSheet("font-weight: 750;")
        names.addWidget(name)
        path = QLabel(Path(app.get("path", "")).name or app.get("path", ""))
        path.setObjectName("mutedSmall")
        path.setToolTip(app.get("path", ""))
        names.addWidget(path)
        row.addLayout(names, 1)
        open_button = QPushButton("بازکردن")
        open_button.setObjectName("smallButton")
        open_button.clicked.connect(lambda checked=False, p=app.get("path", ""): self.launch_app(p))
        row.addWidget(open_button)
        if not compact:
            remove = QPushButton("×")
            remove.setFixedWidth(34)
            remove.clicked.connect(lambda checked=False, i=index: self.remove_app(i))
            row.addWidget(remove)
        return tile

    def add_app(self):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب برنامه", str(Path.home()), "Programs (*.exe);;All files (*.*)")
        if not path:
            path = QFileDialog.getExistingDirectory(self, "انتخاب پوشه", str(Path.home()))
        if not path:
            return
        name = Path(path).stem if Path(path).is_file() else Path(path).name
        self.settings.setdefault("apps", []).append({"name": name, "path": path, "icon": "▣"})
        save_settings(self.settings)
        self._load_apps()

    def remove_app(self, index: int):
        apps = self.settings.get("apps", [])
        if 0 <= index < len(apps):
            apps.pop(index)
            save_settings(self.settings)
            self._load_apps()

    def launch_app(self, path: str):
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                subprocess.Popen([path])
        except Exception as exc:
            QMessageBox.warning(self, "خطا در اجرای برنامه", str(exc))

    def save_notes(self):
        if hasattr(self, "notes_edit"):
            self.settings["notes"] = self.notes_edit.toPlainText()
            save_settings(self.settings)

    def add_task(self):
        text = self.task_input.text().strip()
        if not text:
            return
        self.settings.setdefault("tasks", []).append({"text": text, "done": False})
        self.task_input.clear()
        save_settings(self.settings)
        self._render_tasks()

    def _render_tasks(self):
        if not hasattr(self, "tasks_layout"):
            return
        while self.tasks_layout.count():
            item = self.tasks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        tasks = self.settings.get("tasks", [])
        for i, task in enumerate(tasks[-5:]):
            actual_index = len(tasks[-5:]) - 1 - i
            check = QCheckBox(task.get("text", ""))
            check.setChecked(bool(task.get("done", False)))
            check.stateChanged.connect(lambda state, idx=len(tasks) - len(tasks[-5:]) + i: self._set_task_done(idx, state))
            self.tasks_layout.addWidget(check)
        if not tasks:
            hint = QLabel("هنوز کاری ثبت نشده.")
            hint.setObjectName("mutedSmall")
            self.tasks_layout.addWidget(hint)

    def _set_task_done(self, index: int, state: int):
        tasks = self.settings.get("tasks", [])
        if 0 <= index < len(tasks):
            tasks[index]["done"] = state == Qt.Checked
            save_settings(self.settings)

    def _load_nodes(self):
        if not hasattr(self, "node_combo"):
            return
        self.node_combo.blockSignals(True)
        self.node_combo.clear()
        nodes = self.settings.get("nodes", [])
        for node in nodes:
            self.node_combo.addItem(node.get("name", "Server"))
        selected = self.settings.get("selected_node", "")
        if selected:
            idx = next((i for i, n in enumerate(nodes) if n.get("name") == selected), -1)
            if idx >= 0:
                self.node_combo.setCurrentIndex(idx)
        self.node_count_label.setText(f"{len(nodes)} سرور")
        self.node_combo.blockSignals(False)
        self._on_node_changed(self.node_combo.currentIndex())

    def _on_node_changed(self, index: int):
        nodes = self.settings.get("nodes", [])
        if 0 <= index < len(nodes):
            self.settings["selected_node"] = nodes[index].get("name", "")
            save_settings(self.settings)

    def _set_vpn_controls_enabled(self, enabled: bool):
        for control_name in ("node_combo", "update_sub_button", "add_link_button", "remove_nodes_button"):
            control = getattr(self, control_name, None)
            if control is not None:
                control.setEnabled(enabled)

    def _run_worker(self, fn, on_done):
        if self.operation_busy or (self.active_thread and self.active_thread.isRunning()):
            QMessageBox.information(self, "در حال انجام", "یک عملیات دیگر هنوز در حال اجراست.")
            return False
        self.operation_busy = True
        self._set_vpn_controls_enabled(False)
        self.connect_button.setEnabled(False)
        thread = QThread(self)
        worker = Worker(fn)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        self.active_done_callback = on_done
        worker.done.connect(self._worker_succeeded)
        worker.failed.connect(self._worker_failed)
        worker.done.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(self._worker_thread_finished)
        self.active_thread, self.active_worker = thread, worker
        thread.start()
        return True

    def _worker_thread_finished(self):
        finished_thread = self.sender()
        if finished_thread is self.active_thread:
            self.active_thread = None
            self.active_worker = None
        if finished_thread:
            finished_thread.deleteLater()

    def _worker_succeeded(self, result):
        callback = self.active_done_callback
        self.active_done_callback = None
        self.operation_busy = False
        self.update_sub_button.setEnabled(True)
        if self.engine_process is None or self.engine_process.poll() is not None:
            self.connect_button.setEnabled(True)
            self.connect_button.setText("اتصال")
            self._set_vpn_controls_enabled(True)
        else:
            self._set_vpn_controls_enabled(False)
        if callback:
            callback(result)

    def _worker_failed(self, message: str):
        self.active_done_callback = None
        self.operation_busy = False
        self.update_sub_button.setEnabled(True)
        self.update_sub_button.setText("⟳  بروزرسانی")
        if self.engine_process is None or self.engine_process.poll() is not None:
            self.connect_button.setEnabled(True)
            self.connect_button.setText("اتصال")
            self._set_vpn_controls_enabled(True)
        else:
            self._set_vpn_controls_enabled(False)
        QMessageBox.warning(self, "عملیات ناموفق", message)

    def update_subscription(self):
        url = self.subscription_input.text().strip()
        if not url:
            QMessageBox.information(self, "آدرس اشتراک", "ابتدا آدرس اشتراک را وارد کن.")
            return

        def fetch():
            content = fetch_subscription_text(url)
            nodes = parse_subscription(content)
            if not nodes:
                raise ValueError("هیچ لینک سازگاری پیدا نشد. اشتراک باید شامل لینک‌های VLESS، VMess، Trojan یا SS باشد.")
            return (url, nodes)

        if self._run_worker(fetch, self._subscription_loaded):
            self.update_sub_button.setText("در حال دریافت...")

    def _subscription_loaded(self, result):
        url, nodes = result
        previous_selection = self.settings.get("selected_node", "")
        self.settings["subscription_url"] = url
        self.subscription_input.setText(url)
        self.settings["nodes"] = nodes
        selected = next((node["name"] for node in nodes if node["name"] == previous_selection), nodes[0]["name"])
        self.settings["selected_node"] = selected
        save_settings(self.settings)
        self._load_nodes()
        QMessageBox.information(self, "اشتراک بروزرسانی شد", f"{len(nodes)} سرور با موفقیت دریافت شد.")

    def add_single_link(self):
        link, ok = QInputDialog.getMultiLineText(self, "افزودن لینک سرور", "لینک VLESS / VMess / Trojan / SS:")
        if not ok or not link.strip():
            return
        try:
            node = parse_uri(link.strip())
            self.settings.setdefault("nodes", []).append(node)
            save_settings(self.settings)
            self._load_nodes()
            self.node_combo.setCurrentIndex(len(self.settings["nodes"]) - 1)
        except Exception as exc:
            QMessageBox.warning(self, "لینک نامعتبر", str(exc))

    def clear_nodes(self):
        answer = QMessageBox.question(self, "پاک‌کردن سرورها", "تمام سرورهای ذخیره‌شده پاک شوند؟")
        if answer == QMessageBox.Yes:
            self.settings["nodes"] = []
            self.settings["selected_node"] = ""
            save_settings(self.settings)
            self._load_nodes()

    def _singbox_binary(self) -> Path:
        ENGINE_DIR.mkdir(parents=True, exist_ok=True)
        candidates = list(ENGINE_DIR.glob("sing-box*.exe"))
        for candidate in candidates:
            try:
                result = subprocess.run(
                    [str(candidate), "version"],
                    capture_output=True, text=True, timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0:
                    return candidate
            except Exception:
                pass
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass

        response = requests.get(
            GITHUB_API, timeout=(10, 20),
            headers={"Accept": "application/vnd.github+json", "User-Agent": f"KanWidget/{APP_VERSION}"},
        )
        response.raise_for_status()
        release = response.json()
        machine = platform.machine().lower()
        if "arm" in machine or "aarch64" in machine:
            arch = "arm64"
        elif sys.maxsize > 2**32:
            arch = "amd64"
        else:
            arch = "386"
        asset = next((
            item for item in release.get("assets", [])
            if item.get("name", "").lower().endswith(f"windows-{arch}.zip")
        ), None)
        if not asset:
            raise RuntimeError(f"نسخه ویندوز sing-box برای معماری {arch} در انتشار رسمی پیدا نشد.")

        digest_text = str(asset.get("digest") or "")
        match = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", digest_text)
        if not match:
            raise RuntimeError("GitHub برای فایل هسته VPN مقدار SHA-256 معتبر ارائه نکرد؛ دانلود لغو شد.")
        expected_digest = match.group(1).lower()
        archive_path = ENGINE_DIR / "sing-box.zip"
        partial_path = ENGINE_DIR / "sing-box.zip.part"
        target = ENGINE_DIR / "sing-box.exe"
        target_partial = ENGINE_DIR / "sing-box.exe.part"
        hasher = hashlib.sha256()
        downloaded = 0
        try:
            with requests.get(asset["browser_download_url"], stream=True, timeout=(10, 60)) as download:
                download.raise_for_status()
                with partial_path.open("wb") as stream:
                    for chunk in download.iter_content(1024 * 128):
                        if chunk:
                            downloaded += len(chunk)
                            hasher.update(chunk)
                            stream.write(chunk)
            expected_size = int(asset.get("size") or 0)
            if expected_size and downloaded != expected_size:
                raise RuntimeError("حجم فایل دانلودشده با اطلاعات GitHub مطابقت ندارد.")
            if hasher.hexdigest().lower() != expected_digest:
                raise RuntimeError("بررسی SHA-256 هسته VPN ناموفق بود؛ فایل اجرا نخواهد شد.")
            os.replace(partial_path, archive_path)

            with zipfile.ZipFile(archive_path) as archive:
                exe_member = next((
                    name for name in archive.namelist()
                    if PurePosixPath(name).name.lower() == "sing-box.exe"
                ), None)
                if not exe_member:
                    raise RuntimeError("فایل sing-box.exe داخل بسته رسمی پیدا نشد.")
                # Copy only the executable; do not extract arbitrary archive paths.
                with archive.open(exe_member) as source, target_partial.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
            os.replace(target_partial, target)
        finally:
            partial_path.unlink(missing_ok=True)
            archive_path.unlink(missing_ok=True)
            target_partial.unlink(missing_ok=True)
        return target

    def _make_config(self, node: dict[str, Any]) -> dict[str, Any]:
        outbound = dict(node["outbound"])
        outbound["tag"] = "selected-proxy"
        return {
            "log": {"level": "warn", "timestamp": True},
            "inbounds": [{
                "type": "mixed", "tag": "mixed-in",
                "listen": "127.0.0.1", "listen_port": MIXED_PORT,
            }],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"auto_detect_interface": True, "final": "selected-proxy"},
        }

    def _read_engine_log_tail(self) -> str:
        try:
            lines = ENGINE_LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(lines[-16:])[-1800:]
        except OSError:
            return ""

    def connect_vpn(self):
        if os.name != "nt":
            QMessageBox.warning(self, "سیستم‌عامل پشتیبانی‌نشده", "اتصال پراکسی ویندوز فقط روی Windows 10/11 فعال است.")
            return
        if self.engine_process and self.engine_process.poll() is None:
            return
        nodes = self.settings.get("nodes", [])
        index = self.node_combo.currentIndex()
        if not nodes or index < 0:
            QMessageBox.information(self, "انتخاب سرور", "ابتدا یک اشتراک وارد یا یک لینک سرور اضافه کن.")
            return
        node = nodes[index]

        def start():
            binary = self._singbox_binary()
            config = self._make_config(node)
            temporary_config = VPN_CONFIG_FILE.with_suffix(".tmp")
            temporary_config.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temporary_config, VPN_CONFIG_FILE)

            check = subprocess.run(
                [str(binary), "check", "-c", str(VPN_CONFIG_FILE)],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if check.returncode != 0:
                detail = (check.stderr or check.stdout or "خطای نامشخص در پیکربندی").strip()
                raise RuntimeError(f"پیکربندی سرور توسط sing-box تأیید نشد:\n{detail[-1400:]}")

            try:
                with socket.create_connection(("127.0.0.1", MIXED_PORT), timeout=0.25):
                    raise RuntimeError(f"پورت محلی {MIXED_PORT} قبلاً توسط برنامه دیگری اشغال شده است.")
            except OSError:
                pass

            ENGINE_DIR.mkdir(parents=True, exist_ok=True)
            process = None
            try:
                with ENGINE_LOG_FILE.open("w", encoding="utf-8") as log_stream:
                    process = subprocess.Popen(
                        [str(binary), "run", "-c", str(VPN_CONFIG_FILE)],
                        stdout=log_stream, stderr=subprocess.STDOUT,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                deadline = time.time() + 12
                ready = False
                while time.time() < deadline:
                    if process.poll() is not None:
                        detail = self._read_engine_log_tail()
                        message = "هسته VPN متوقف شد."
                        if detail:
                            message += f"\n\nگزارش sing-box:\n{detail}"
                        raise RuntimeError(message)
                    try:
                        with socket.create_connection(("127.0.0.1", MIXED_PORT), timeout=0.3):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.25)
                if not ready:
                    detail = self._read_engine_log_tail()
                    message = "پورت پراکسی محلی در زمان مقرر آماده نشد."
                    if detail:
                        message += f"\n\nگزارش sing-box:\n{detail}"
                    raise RuntimeError(message)
                return process, node.get("name", "Server")
            except Exception:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                raise

        if self._run_worker(start, self._start_engine):
            self.connect_button.setText("در حال آماده‌سازی...")

    def _start_engine(self, data):
        process, name = data
        self.engine_process = process
        try:
            self._enable_windows_proxy()
            self.connect_button.setEnabled(False)
            self.connect_button.setText("پراکسی فعال")
            self.disconnect_button.setEnabled(True)
            self.vpn_status.setText("●  پراکسی محلی فعال است")
            self.vpn_detail.setText(
                f"سرور انتخابی: {name}  •  پراکسی محلی: 127.0.0.1:{MIXED_PORT}  •  اتصال مقصد با درخواست واقعی برنامه‌ها مشخص می‌شود."
            )
            self.connection_badge.setText("●  VPN فعال است")
            self.connection_badge.setStyleSheet("color:#5CE0BE;")
            self._set_vpn_controls_enabled(False)
        except Exception as exc:
            restored = self._restore_windows_proxy()
            if restored:
                self._stop_engine()
                self.connect_button.setEnabled(True)
                self.connect_button.setText("اتصال")
                self.disconnect_button.setEnabled(False)
                self._set_vpn_controls_enabled(True)
            else:
                # Keep sing-box alive if Windows may still point at it; allow retrying restore.
                self.connect_button.setEnabled(False)
                self.disconnect_button.setEnabled(True)
                self._set_vpn_controls_enabled(False)
                self.vpn_status.setText("●  نیاز به بازیابی پراکسی ویندوز")
                self.vpn_detail.setText("تنظیمات پراکسی کامل بازیابی نشد. قطع اتصال را دوباره امتحان کن.")
            QMessageBox.warning(self, "تنظیم پراکسی ویندوز ناموفق", str(exc))

    def _enable_windows_proxy(self):
        if os.name != "nt":
            return
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            try:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                enabled = 0
            try:
                server = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                server = ""
        snapshot = {"enabled": int(enabled), "server": str(server)}
        snapshot_tmp = PROXY_SNAPSHOT_FILE.with_suffix(".tmp")
        snapshot_tmp.write_text(json.dumps(snapshot), encoding="utf-8")
        os.replace(snapshot_tmp, PROXY_SNAPSHOT_FILE)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"http=127.0.0.1:{MIXED_PORT};https=127.0.0.1:{MIXED_PORT};socks=127.0.0.1:{MIXED_PORT}")
        self._notify_windows_proxy_change()
        self.settings["proxy_snapshot"] = snapshot
        save_settings(self.settings)

    def _restore_windows_proxy(self) -> bool:
        if os.name != "nt":
            return True
        snapshot = None
        if PROXY_SNAPSHOT_FILE.exists():
            try:
                snapshot = json.loads(PROXY_SNAPSHOT_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return False
        else:
            snapshot = self.settings.get("proxy_snapshot")
        if not snapshot:
            return True
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(snapshot.get("enabled", 0)))
                if snapshot.get("server"):
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(snapshot["server"]))
                else:
                    try:
                        winreg.DeleteValue(key, "ProxyServer")
                    except FileNotFoundError:
                        pass
        except Exception:
            # Keep the backup file so restoration can be retried.
            return False
        self._notify_windows_proxy_change()
        PROXY_SNAPSHOT_FILE.unlink(missing_ok=True)
        self.settings["proxy_snapshot"] = None
        save_settings(self.settings)
        return True

    def _notify_windows_proxy_change(self):
        if os.name != "nt":
            return
        try:
            import ctypes
            internet = ctypes.windll.Wininet
            internet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
            internet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
        except Exception:
            pass

    def _stop_engine(self):
        if self.engine_process and self.engine_process.poll() is None:
            self.engine_process.terminate()
            try:
                self.engine_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.engine_process.kill()
        self.engine_process = None

    def disconnect_vpn(self):
        if not self._restore_windows_proxy():
            QMessageBox.critical(
                self, "بازیابی پراکسی ناموفق",
                "تنظیمات قبلی پراکسی ویندوز بازیابی نشد. اتصال را فعال نگه داشتم تا اینترنتت قطع نشود؛ دوباره تلاش کن.",
            )
            return
        self._stop_engine()
        self.connect_button.setEnabled(True)
        self.connect_button.setText("اتصال")
        self._set_vpn_controls_enabled(True)
        self.disconnect_button.setEnabled(False)
        self.vpn_status.setText("●  اتصال برقرار نیست")
        self.vpn_detail.setText("اتصال قطع شد و تنظیمات پراکسی قبلی ویندوز بازیابی شد.")
        self.connection_badge.setText("●  VPN قطع است")
        self.connection_badge.setStyleSheet("")

    def _recover_stale_proxy(self):
        # If the app or Windows was closed unexpectedly, restore the previous system proxy.
        if PROXY_SNAPSHOT_FILE.exists():
            self._restore_proxy_without_ui()

    def _restore_proxy_without_ui(self):
        if os.name != "nt" or not PROXY_SNAPSHOT_FILE.exists():
            return
        try:
            snapshot = json.loads(PROXY_SNAPSHOT_FILE.read_text(encoding="utf-8"))
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(snapshot.get("enabled", 0)))
                if snapshot.get("server"):
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(snapshot["server"]))
                else:
                    try:
                        winreg.DeleteValue(key, "ProxyServer")
                    except FileNotFoundError:
                        pass
            self._notify_windows_proxy_change()
            PROXY_SNAPSHOT_FILE.unlink(missing_ok=True)
        except Exception:
            # Leave the snapshot in place so the next launch can retry.
            pass

    def _shutdown_cleanup(self):
        try:
            if self._restore_windows_proxy():
                self._stop_engine()
        except Exception:
            pass

    def closeEvent(self, event):
        if self.operation_busy or (self.active_thread and self.active_thread.isRunning()):
            QMessageBox.information(
                self, "عملیات در حال اجرا",
                "تا پایان دریافت اشتراک یا آماده‌سازی اتصال، برنامه را نبند.",
            )
            event.ignore()
            return
        if self.engine_process and self.engine_process.poll() is None:
            answer = QMessageBox.question(self, "خروج از Kan Widget", "VPN متصل است. هنگام خروج اتصال قطع شود؟")
            if answer != QMessageBox.Yes:
                event.ignore()
                return
        if not self._restore_windows_proxy():
            QMessageBox.critical(
                self, "بازیابی پراکسی ناموفق",
                "تنظیمات قبلی پراکسی ویندوز بازیابی نشد. برنامه باز می‌ماند تا بتوانی دوباره قطع اتصال را امتحان کنی.",
            )
            event.ignore()
            return
        self._stop_engine()
        event.accept()


def main():
    if os.name != "nt":
        print("Kan Widget currently targets Windows 10/11.")
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setFont(QFont("Segoe UI", 10))
    window = KanWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
