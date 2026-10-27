"""Kalıcı durum: yollar, config.toml, arayüzden değişen ayarlar, düzenlemeler, ajanlar.

config.toml   -> kullanıcının elle yazdığı temel ayarlar (salt okunur kullanılır)
settings.json -> arayüzden değişen tarama ayarları
overrides.json-> arayüzden yapılan cihaz/uygulama düzenlemeleri (config.toml'u ezer)
agents.json   -> kayıtlı ajanlar ve anahtarları
"""

import copy
import hmac
import os
import re
import secrets
import threading
import tomllib

from . import util

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_SETTINGS = {
    "auto": True,             # otomatik tarama
    "interval_min": 5,        # tarama sıklığı (dakika)
    "online_window_min": 15,  # pasif dinlemede bu kadar dakikadır ses veren cihaz çevrimiçi sayılır
    "agent_auto_update": True,  # ajanlar (router dahil) yeni sürümü Pi'den kendileri alsın
    "sources": {
        "tailscale": True,    # tailscale status
        "arp": True,          # Ev 1 aktif ARP taraması (arp-scan)
        "passive": True,      # Ev 1 pasif dinleme (ARP/DHCP/mDNS/SSDP)
        "neigh": True,        # Pi'nin komşu tablosu
        "docker": True,       # Pi'deki Docker container'ları
        "host_ports": True,   # Pi'de Docker dışı dinleyen servisler
        "router": True,       # router ajanının raporu
        "agents": True,       # diğer sunucuların ajan raporları
        "health": True,       # Pi servislerinin kendi portları yanıt veriyor mu (127.0.0.1)
    },
}
INTERVALS = (1, 2, 5, 10, 15, 30, 60)
DEVICE_TYPES = ("modem", "router", "ap", "server", "cloud-vm", "pc", "laptop", "phone",
                "tablet", "tv", "console", "iot", "lamp", "vacuum", "camera", "printer",
                "speaker", "nas", "device")
AGENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class Paths:
    def __init__(self, home):
        self.home = home
        self.config = os.environ.get("NODESK_CONFIG") or os.path.join(home, "config.toml")
        self.data = os.path.join(home, "data")
        self.www = os.path.join(home, "www")
        self.keys = os.path.join(home, "keys")
        self.agents_dir = os.path.join(self.data, "agents")
        self.settings = os.path.join(self.data, "settings.json")
        self.overrides = os.path.join(self.data, "overrides.json")
        self.agents = os.path.join(self.data, "agents.json")
        self.state = os.path.join(self.data, "state.json")
        self.passive = os.path.join(self.data, "passive.json")
        self.update = os.path.join(self.data, "update.json")
        self.data_json = os.path.join(self.www, "data.json")


def load_config(paths):
    path = paths.config
    if not os.path.exists(path):
        path = os.path.join(APP_DIR, "config.example.toml")
    with open(path, "rb") as f:
        return tomllib.load(f)


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Store:
    """Arayüzden değişen her şey; iş parçacıkları arasında kilitli."""

    def __init__(self, paths):
        self.p = paths
        self.lock = threading.RLock()

    # ------------------------------------------------ ayarlar
    def settings(self):
        with self.lock:
            return _merge(DEFAULT_SETTINGS, util.read_json(self.p.settings, {}))

    def set_settings(self, patch):
        with self.lock:
            cur = self.settings()
            if "auto" in patch:
                cur["auto"] = bool(patch["auto"])
            if "agent_auto_update" in patch:
                cur["agent_auto_update"] = bool(patch["agent_auto_update"])
            if "interval_min" in patch:
                v = int(patch["interval_min"])
                if v not in INTERVALS:
                    raise ValueError(f"sıklık şunlardan biri olmalı: {INTERVALS}")
                cur["interval_min"] = v
            if "online_window_min" in patch:
                cur["online_window_min"] = max(2, min(240, int(patch["online_window_min"])))
            for k, v in (patch.get("sources") or {}).items():
                if k in DEFAULT_SETTINGS["sources"]:
                    cur["sources"][k] = bool(v)
            util.write_json(self.p.settings, cur)
            return cur

    # ------------------------------------------------ cihaz/uygulama düzenlemeleri
    def overrides(self):
        with self.lock:
            o = util.read_json(self.p.overrides, {}) or {}
            o.setdefault("devices", {})
            o.setdefault("apps", {})
            o.setdefault("sites", {})
            return o

    def set_device(self, node_id, patch):
        clean = {}
        if patch.get("name"):
            clean["name"] = str(patch["name"]).strip()[:60]
        if patch.get("type"):
            if patch["type"] not in DEVICE_TYPES:
                raise ValueError("bilinmeyen tür")
            clean["type"] = patch["type"]
        if patch.get("parent"):
            clean["parent"] = str(patch["parent"])[:80]
        tags = patch.get("tags") or []
        if isinstance(tags, str):
            tags = tags.split(",")
        tags = sorted({t.strip()[:24] for t in tags if t and t.strip()})
        if tags:
            clean["tags"] = tags[:12]
        if patch.get("note"):
            clean["note"] = str(patch["note"]).strip()[:500]
        if patch.get("icon"):
            icon = str(patch["icon"]).strip()[:300]
            if not icon.startswith("https://"):
                raise ValueError("ikon adresi https:// ile başlamalı")
            clean["icon"] = icon
        if patch.get("hidden"):
            clean["hidden"] = True
        services = []
        for s in patch.get("services") or []:
            name = str(s.get("name") or "").strip()[:40]
            port = str(s.get("port") or "").strip()
            url = str(s.get("url") or "").strip()[:200]
            if not name:
                continue
            if port and not (port.isdigit() and 0 < int(port) < 65536):
                raise ValueError(f"geçersiz port: {port}")
            if url and not re.match(r"^https?://", url):
                raise ValueError("bağlantı http:// ya da https:// ile başlamalı")
            services.append({k: v for k, v in (("name", name), ("port", port), ("url", url)) if v})
        if services:
            clean["services"] = services[:20]
        with self.lock:
            o = self.overrides()
            if clean:
                o["devices"][node_id] = clean
            else:
                o["devices"].pop(node_id, None)
            util.write_json(self.p.overrides, o)
            return clean

    def set_site(self, site_id, patch):
        if site_id not in ("ev1", "ev2", "oracle", "mobile"):
            raise ValueError("bilinmeyen grup")
        with self.lock:
            o = self.overrides()
            name = str(patch.get("name") or "").strip()[:40]
            if name:
                o["sites"][site_id] = {"name": name}
            else:
                o["sites"].pop(site_id, None)
            util.write_json(self.p.overrides, o)
            return o["sites"].get(site_id, {})

    def set_app(self, app_id, patch):
        with self.lock:
            o = self.overrides()
            clean = {}
            if patch.get("name"):
                clean["name"] = str(patch["name"]).strip()[:40]
            if patch.get("hidden"):
                clean["hidden"] = True
            if clean:
                o["apps"][app_id] = clean
            else:
                o["apps"].pop(app_id, None)
            util.write_json(self.p.overrides, o)
            return clean

    # ------------------------------------------------ ajanlar
    def agents(self):
        with self.lock:
            a = util.read_json(self.p.agents, {}) or {}
            a.setdefault("agents", {})
            return a

    def add_agent(self, name, kind):
        name = (name or "").strip().lower()
        if not AGENT_NAME_RE.match(name):
            raise ValueError("ad küçük harf, rakam ve tire içermeli (en fazla 32 karakter)")
        if kind not in ("router", "linux"):
            raise ValueError("tür router ya da linux olmalı")
        with self.lock:
            a = self.agents()
            cur = a["agents"].get(name)
            if cur:
                return cur
            cur = {"kind": kind, "token": secrets.token_urlsafe(24),
                   "created": util.iso(util.utcnow())}
            a["agents"][name] = cur
            util.write_json(self.p.agents, a, mode=0o600)
            return cur

    def remove_agent(self, name):
        with self.lock:
            a = self.agents()
            if a["agents"].pop(name, None) is None:
                return False
            util.write_json(self.p.agents, a, mode=0o600)
        for ext in (".txt", ".json"):
            try:
                os.unlink(os.path.join(self.p.agents_dir, name + ext))
            except OSError:
                pass
        return True

    def check_token(self, name, token):
        ag = self.agents()["agents"].get(name)
        return bool(ag and token and hmac.compare_digest(ag["token"], token))

    def save_report(self, name, text, remote):
        os.makedirs(self.p.agents_dir, exist_ok=True)
        with open(os.path.join(self.p.agents_dir, name + ".txt"), "w", encoding="utf-8") as f:
            f.write(text)
        util.write_json(os.path.join(self.p.agents_dir, name + ".json"),
                        {"received": util.iso(util.utcnow()), "from": remote, "bytes": len(text)})

    def reports(self):
        """{ad: {kind, received, sections}}"""
        out = {}
        for name, meta in self.agents()["agents"].items():
            info = util.read_json(os.path.join(self.p.agents_dir, name + ".json"), {}) or {}
            text = util.read_text(os.path.join(self.p.agents_dir, name + ".txt"), "")
            out[name] = {"kind": meta["kind"], "received": info.get("received"),
                         "from": info.get("from"),
                         "sections": util.parse_sections(text) if text else None}
        return out
