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

from . import sites as sitesmod, util

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
        "probe": True,        # Ev 1 ad sorgusu: her IP'ye günde bir kez NetBIOS/mDNS/SSDP
    },
}
# Kart renkleri (arayüzden değişir). "" = renksiz (nötr kart).
COLOR_CATEGORIES = ("net", "srv", "pc", "mobile", "media", "home", "other", "app", "sys")
DEFAULT_SETTINGS["colors"] = {"net": "#3b82d6", "srv": "#c2508a", "pc": "#8e66d0", "mobile": "#e07b53",
                              "media": "#d6a03a", "home": "#4f9d69", "other": "", "app": "#1e9ab0",
                              "sys": "#8c9440"}
HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")
# Kim düzenler / kim görür (auth.py). edit: tailnet | password | everyone; view: everyone | login
DEFAULT_SETTINGS["access"] = {"edit": "tailnet", "view": "everyone", "ts_users": []}
# Bildirimler (history.py): ntfy ya da Telegram; boşsa kapalı. Gizli: herkese açık veriye yazılmaz.
DEFAULT_SETTINGS["alerts"] = {"ntfy_url": "", "telegram_token": "", "telegram_chat": "",
                              "events": {"new_device": True, "service_down": True,
                                         "agent_silent": True, "exit_change": True}}
SECRET_SETTINGS = ("alerts", "access")   # yalnızca düzenleyebilenler görür
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
        self.data_json = os.path.join(self.www, "data.json")              # herkese açık harita
        self.data_private = os.path.join(self.data, "data.json")          # /api/data (giriş gerekirse)
        self.auth = os.path.join(self.data, "auth.json")
        self.teardown_req = os.path.join(self.data, "teardown-request")   # sudo nodesk uninstall
        self.teardown_state = os.path.join(self.data, "teardown.json")    # kaldırma sürüyor (yeniden başlatmada devam)


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
            acc = patch.get("access") or {}
            if "edit" in acc:
                if acc["edit"] not in ("tailnet", "password", "everyone"):
                    raise ValueError("edit: tailnet | password | everyone")
                cur["access"]["edit"] = acc["edit"]
            if "view" in acc:
                if acc["view"] not in ("everyone", "login"):
                    raise ValueError("view: everyone | login")
                cur["access"]["view"] = acc["view"]
            if "ts_users" in acc:
                users = acc["ts_users"] if isinstance(acc["ts_users"], list) else str(acc["ts_users"]).split(",")
                cur["access"]["ts_users"] = sorted({str(u).strip().lower()[:100] for u in users if str(u).strip()})[:20]
            if "sites" in patch:
                cur["sites"] = sitesmod.validate(patch["sites"])
            for k, v in (patch.get("ts_site") or {}).items():   # Tailscale cihazı -> grup ("" = varsayılan)
                k = str(k).lower()[:60]
                if v:
                    cur.setdefault("ts_site", {})[k] = str(v)[:24]
                else:
                    cur.setdefault("ts_site", {}).pop(k, None)
            al = patch.get("alerts") or {}
            if "ntfy_url" in al:
                v = str(al["ntfy_url"]).strip()[:300]
                if v and not re.match(r"^https?://[^\s]+$", v):
                    raise ValueError("ntfy adresi http(s):// ile başlamalı (örn. https://ntfy.sh/konu)")
                cur["alerts"]["ntfy_url"] = v
            if "telegram_token" in al:
                v = str(al["telegram_token"]).strip()
                if v and not re.match(r"^[0-9]{5,}:[A-Za-z0-9_-]{20,}$", v):
                    raise ValueError("Telegram bot anahtarı 123456:ABC... biçiminde olmalı")
                cur["alerts"]["telegram_token"] = v
            if "telegram_chat" in al:
                v = str(al["telegram_chat"]).strip()[:40]
                if v and not re.match(r"^(-?[0-9]+|@[A-Za-z0-9_]{4,})$", v):
                    raise ValueError("Telegram sohbet kimliği sayı ya da @kanal olmalı")
                cur["alerts"]["telegram_chat"] = v
            for k, v in (al.get("events") or {}).items():
                if k in DEFAULT_SETTINGS["alerts"]["events"]:
                    cur["alerts"]["events"][k] = bool(v)
            if "setup_done" in patch:
                cur["setup_done"] = bool(patch["setup_done"])
            for k, v in (patch.get("colors") or {}).items():
                if k not in COLOR_CATEGORIES or not (v == "" or HEX_COLOR.match(str(v))):
                    raise ValueError(f"geçersiz renk: {k}={v}")
                cur["colors"][k] = str(v).lower()
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
        for k in ("same_as", "not_same"):   # aynı cihazın başka MAC'i / öneriyi reddet
            v = str(patch.get(k) or "")
            if v and (not v.startswith("mac:") or len(v) > 30 or v == node_id):
                raise ValueError(f"geçersiz {k}")
            if v:
                clean[k] = v
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

    def sites(self):
        """Ayarlardaki gruplar + kayıtlı router ajanları (sites.resolve)."""
        routers = [n for n, a in self.agents()["agents"].items() if a["kind"] == "router"]
        return sitesmod.resolve(self.settings().get("sites"), routers)

    def migrate_sites(self, cfg, fresh):
        """Grup yapısı ayarlarda yoksa eski config.toml'dan bir kez oluştur."""
        with self.lock:
            saved = util.read_json(self.p.settings, {}) or {}
            if "sites" in saved:
                return False
            saved["sites"], saved["ts_site"] = sitesmod.from_config(cfg)
            saved.setdefault("setup_done", not fresh)   # yeni kurulumda arayüz sihirbazı açar
            util.write_json(self.p.settings, saved)
            return True

    def set_site(self, site_id, patch):
        if site_id not in {s["id"] for s in self.sites()}:
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
        """Silme isteği: ajan bir sonraki raporunda kendini cihazdan kaldırır ("ok uninstall"),
        sonra "#UNINSTALLED" gönderir ve kayıt o zaman silinir (purge_agent)."""
        with self.lock:
            a = self.agents()
            if name not in a["agents"]:
                return False
            a["agents"][name]["removing"] = util.iso(util.utcnow())
            util.write_json(self.p.agents, a, mode=0o600)
            return True

    def cancel_removal(self, name):
        with self.lock:
            a = self.agents()
            if a["agents"].get(name, {}).pop("removing", None):
                util.write_json(self.p.agents, a, mode=0o600)

    def purge_agent(self, name):
        """Kaydı ve raporlarını tamamen sil (cihaz kendini kaldırdı ya da kullanıcı zorladı)."""
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
