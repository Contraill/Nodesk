"""Nodesk sunucusu: zamanlayıcı + toplayıcı + pasif dinleyici + HTTP API.

Pi'de root olarak systemd ile çalışır (nodesk.service). API sadece 127.0.0.1'i dinler;
dışarıya nginx (nodesk-web container'ı, 8088) üzerinden /api/ olarak açılır.
"""

import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import agents, model, passive, probe, sources, store, util

API_HOST = "127.0.0.1"
API_PORT = int(os.environ.get("NODESK_API_PORT", "8089"))
UPDATE_CHECK_HOURS_DEFAULT = 6


def log(msg):
    print(f"[nodesk] {msg}", flush=True)


class App:
    def __init__(self, home, fixtures=None):
        self.paths = store.Paths(home)
        self.store = store.Store(self.paths)
        self.fixtures = fixtures
        self.cfg = store.load_config(self.paths)
        oui_path = os.environ.get("NODESK_OUI") or self.cfg.get("general", {}).get(
            "oui_file", "/usr/share/arp-scan/ieee-oui.txt")
        self.oui = util.load_oui(oui_path)
        self.raw = None
        self.status = {"running": False, "last_start": None, "last_end": None,
                       "last_ok": None, "last_error": None, "sources": {}}
        self.scan_lock = threading.Lock()
        self.build_lock = threading.Lock()
        self.wake = threading.Event()
        self.scan_requested = False
        self.stop = threading.Event()
        ev1 = self.cfg.get("ev1", {})
        self.passive = passive.Passive(self.paths.passive, ev1.get("interface", "eth0"),
                                       ev1.get("subnet"),
                                       self.cfg.get("general", {}).get("forget_after_days", 14))
        if fixtures and os.path.exists(os.path.join(fixtures, "passive.json")):
            self.passive.data = util.read_json(os.path.join(fixtures, "passive.json"), {})
            self.passive.ipinfo = util.read_json(os.path.join(fixtures, "passive_ip.json"), {}) or {}
        # Ev 2: router'ın duyduğu ve sorduğu adlar (router raporlarından, kalıcı)
        self.heard = passive.Passive(os.path.join(self.paths.data, "passive_ev2.json"), None, None,
                                     self.cfg.get("general", {}).get("forget_after_days", 14))
        self.import_router_names()
        self.update_info = util.read_json(self.paths.update, {}) or {}
        self.updating = False
        self.icons_path = os.path.join(self.paths.data, "icons.json")
        self.icon_files = {}     # uzak adres -> "live/icons/x.png"
        for url, v in (util.read_json(self.icons_path, {}) or {}).items():
            if v.get("file") and os.path.exists(os.path.join(self.paths.www, "icons", v["file"])):
                self.icon_files[url] = "live/icons/" + v["file"]
        self.icon_thread = None
        self.probed = {}         # IP -> son ad sorgusu (time.monotonic)

    # ------------------------------------------------------------ sürüm
    def version(self):
        return util.read_text(os.path.join(store.APP_DIR, "VERSION"), "?")

    def git(self, *args, timeout=40):
        try:
            p = subprocess.run(["git", "-C", store.APP_DIR, *args], capture_output=True,
                               text=True, timeout=timeout)
            return p.stdout.strip() if p.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    def check_update(self, force=False):
        if self.fixtures:
            return self.update_info
        hours = self.cfg.get("general", {}).get("update_check_hours", UPDATE_CHECK_HOURS_DEFAULT)
        last = util.parse_iso(self.update_info.get("checked"))
        if not force and (not hours or (last and (util.utcnow() - last).total_seconds() < hours * 3600)):
            return self.update_info
        branch = self.cfg.get("general", {}).get("branch", "main")
        info = {"checked": util.iso(util.utcnow())}
        if self.git("fetch", "--quiet", "origin", branch) is None:
            info["error"] = "depoya ulaşılamadı"
        else:
            info["behind"] = int(self.git("rev-list", "--count", f"HEAD..origin/{branch}") or 0)
            info["latest"] = self.git("show", f"origin/{branch}:VERSION") or "?"
            info["latest_rev"] = self.git("rev-parse", "--short", f"origin/{branch}")
            log_lines = self.git("log", "--format=%s", f"HEAD..origin/{branch}") or ""
            info["changes"] = log_lines.splitlines()[:20]
        self.update_info = info
        util.write_json(self.paths.update, info)
        return info

    def app_info(self):
        rev = None if self.fixtures else self.git("rev-parse", "--short", "HEAD", timeout=5)
        u = self.update_info
        upd = None
        if u.get("behind") and u.get("latest_rev") != rev:
            upd = {"latest": u.get("latest"), "behind": u["behind"], "changes": u.get("changes", [])}
        return {"version": self.version(), "rev": rev, "update": upd,
                "update_checked": u.get("checked"), "updating": self.updating}

    def public_url(self):
        base = self.cfg.get("general", {}).get("public_url")
        if base:
            return base
        ts = (self.raw or {}).get("ts") or {}
        ips = (ts.get("Self") or {}).get("TailscaleIPs") or []
        ip = next((i for i in ips if ":" not in i), None)
        if not ip and not self.fixtures:
            try:
                ip = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True,
                                    timeout=5).stdout.split()[0]
            except (OSError, subprocess.SubprocessError, IndexError):
                ip = None
        return f"http://{ip or '100.64.0.1'}:8088"

    # ------------------------------------------------------------ toplama
    def gather(self, settings):
        src = settings["sources"]
        r = sources.Runner(self.fixtures)
        raw = {"time": util.iso(util.utcnow())}
        ev1 = self.cfg.get("ev1", {})
        iface = ev1.get("interface", "eth0")
        raw["ts"] = sources.tailscale(r) if src["tailscale"] else None
        raw["ifaces"] = sources.self_ifaces(r)
        if not ev1.get("subnet"):
            for i in raw["ifaces"]:
                if i["ifname"] == iface:
                    self.passive.set_subnet(f"{i['ip']}/{i['prefix']}")
        raw["arp"] = sources.arpscan(r, iface) if src["arp"] else None
        raw["neigh"] = sources.neigh(r) if src["neigh"] else None
        raw["exit_clients"] = sources.exit_clients(r) if src["tailscale"] else None
        if src.get("probe", True) and raw["arp"] and not self.fixtures:
            self.probe_names(r, raw, iface)
        raw["docker"] = sources.docker_containers(r) if src["docker"] else None
        projects = {c["project"] for c in raw["docker"] or [] if c.get("project")}
        raw["casaos"] = sources.casaos_titles(r, projects)
        skip = {p for c in raw["docker"] or [] if c["host_network"] for p in c["ports"]}
        raw["host_ports"] = sources.host_ports(r, skip) if src["host_ports"] else None
        ports = {p for c in raw["docker"] or [] if c["state"] == "running" for p in c["ports"]}
        # SSH/Samba/VNC'ye bağlanmak her seferinde sistem günlüğüne satır düşürür; onları atla
        ports |= {p for s in raw["host_ports"] or [] if s["proc"] in ("casaos-gateway", "casaos")
                  for p in s["ports"]}
        hosts = ["127.0.0.1"] + [i["ip"] for i in raw["ifaces"] if i["ifname"] == iface]
        raw["health"] = sources.check_ports(r, ports, hosts) if src.get("health", True) else {}
        raw["status"] = r.status
        return raw

    def probe_names(self, r, raw, iface):
        """Ev 1'de ARP'ye yanıt veren her IP'ye günde en fazla bir kez ad sorgusu (probe.py)."""
        local = next((i["ip"] for i in raw["ifaces"] if i["ifname"] == iface), None)
        mine = {i["ip"] for i in raw["ifaces"]}
        now = time.monotonic()
        targets = {e["ip"]: e["mac"] for e in raw["arp"]
                   if e["ip"] not in mine and now - self.probed.get(e["ip"], -1e9) > 86400}
        if not local or not targets:
            return
        self.probed.update((ip, now) for ip in targets)
        try:
            found = probe.run(targets, local)
        except OSError as e:
            r.mark("probe", False, error=str(e)[:200])
            return
        for obs in found:
            self.passive.observe(obs)
        r.mark("probe", True, count=len(found))

    def import_router_names(self):
        rep = self.store.reports().get("router")
        if not rep or not rep.get("sections"):
            return
        for obs in model.router_name_obs(rep["sections"]):
            self.heard.observe(obs)
        if not self.fixtures:
            self.heard.prune_and_save()

    def attach_live(self, raw, settings):
        """Her yeniden hesaplamada güncel olan kaynaklar: pasif dinleme ve ajan raporları."""
        raw = dict(raw)
        src = settings["sources"]
        raw["passive"] = self.passive.snapshot() if src["passive"] else None
        raw["passive_ip"] = self.passive.snapshot_ip() if src["passive"] else {}
        raw["passive_ev2"] = self.heard.snapshot()
        reports = self.store.reports()
        if not src["router"]:
            reports.pop("router", None)
        raw["reports"] = reports
        return raw

    # ------------------------------------------------------------ ikonlar
    ICON_TYPES = {"image/png": ".png", "image/svg+xml": ".svg", "image/jpeg": ".jpg",
                  "image/webp": ".webp", "image/x-icon": ".ico", "image/vnd.microsoft.icon": ".ico"}

    def fetch_icons(self, urls):
        """Servis ikonlarını Pi'ye indirip /live/icons altından sunar (tarayıcının internete
        çıkması gerekmez). Arka planda; bittiğinde haritayı yeniden hesaplar."""
        if self.icon_thread and self.icon_thread.is_alive():
            return
        self.icon_thread = threading.Thread(target=self._fetch_icons, args=(list(urls),),
                                            name="icons", daemon=True)
        self.icon_thread.start()

    def _fetch_icons(self, urls):
        index = util.read_json(self.icons_path, {}) or {}
        now = util.utcnow()
        got = False
        os.makedirs(os.path.join(self.paths.www, "icons"), exist_ok=True)
        for url in urls[:40]:
            prev = index.get(url) or {}
            last = util.parse_iso(prev.get("failed"))
            if not url.startswith("https://") or (last and (now - last).total_seconds() < 86400):
                continue
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "nodesk"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                    body = r.read(300 * 1024 + 1)
                ext = self.ICON_TYPES.get(ctype)
                if not ext or len(body) > 300 * 1024 or not body:
                    raise ValueError(f"uygun değil ({ctype}, {len(body)} bayt)")
                name = hashlib.sha1(url.encode()).hexdigest()[:16] + ext
                tmp = os.path.join(self.paths.www, "icons", "." + name)
                with open(tmp, "wb") as f:
                    f.write(body)
                os.chmod(tmp, 0o644)
                os.replace(tmp, os.path.join(self.paths.www, "icons", name))
                index[url] = {"file": name, "fetched": util.iso(now)}
                self.icon_files[url] = "live/icons/" + name
                got = True
            except Exception as e:   # ikon yoksa yerleşik simge kullanılır
                index[url] = {"failed": util.iso(now), "error": str(e)[:120]}
                log(f"ikon indirilemedi: {url} ({e})")
        util.write_json(self.icons_path, index)
        if got:
            self.rebuild()

    def rebuild(self):
        if self.raw is None:
            return None
        with self.build_lock:
            settings = self.store.settings()
            raw = self.attach_live(self.raw, settings)
            state = util.read_json(self.paths.state, {}) or {}
            now = util.utcnow()
            data, state = model.build(raw, self.cfg, settings, self.store.overrides(), state,
                                      self.oui, now, {"topo_expected": agents.topo_version(),
                                                      "icon_files": dict(self.icon_files)})
            wanted = data.pop("icon_wanted", [])
            if wanted and (not self.fixtures or os.environ.get("NODESK_FETCH_ICONS")):
                self.fetch_icons(wanted)
            pstatus = {"ok": self.passive.running or bool(self.fixtures),
                       "count": len(raw["passive"] or {}), "error": self.passive.error}
            if not settings["sources"]["passive"]:
                pstatus = {"ok": None, "disabled": True}
            data["sources"] = {**raw.get("status", {}), "passive": pstatus}
            data["scan"] = {"last_start": self.status["last_start"], "last_end": self.status["last_end"]}
            data["settings"] = settings
            data["app"] = self.app_info()
            data["apps"] = {k: v for k, v in self.store.overrides().get("apps", {}).items()}
            util.write_json(self.paths.state, state)
            util.write_json(self.paths.data_json, data)
            return data

    def collect(self):
        if not self.scan_lock.acquire(blocking=False):
            return False
        try:
            self.status.update(running=True, last_start=util.iso(util.utcnow()))
            try:
                self.cfg = store.load_config(self.paths)   # config.toml değişikliklerini al
            except (OSError, ValueError) as e:
                log(f"config.toml okunamadı, önceki ayarlar kullanılıyor: {e}")
            settings = self.store.settings()
            self.raw = self.gather(settings)
            self.status["sources"] = self.raw.get("status", {})
            data = self.rebuild()
            self.status.update(last_ok=True, last_error=None)
            n = [x for x in data["nodes"] if not x.get("placeholder") and x["kind"] not in ("internet", "service")]
            sv = [x for x in data["nodes"] if x["kind"] == "service"]
            log(f"{len(n)} cihaz ({sum(1 for x in n if x['online'])} çevrimiçi), {len(sv)} servis "
                f"({sum(1 for x in sv if x['online'])} çalışıyor), {len(data['errors'])} uyarı")
            for e in data["errors"]:
                log(f"  ! {e}")
            return True
        except Exception as e:  # tarama hiçbir durumda sunucuyu düşürmesin
            self.status.update(last_ok=False, last_error=str(e))
            log("toplama hatası: " + "".join(traceback.format_exception(e))[-800:])
            return False
        finally:
            self.status.update(running=False, last_end=util.iso(util.utcnow()))
            self.scan_lock.release()

    def request_scan(self):
        if self.status["running"]:
            return False
        self.scan_requested = True
        self.wake.set()
        return True

    def scheduler(self):
        last_scan = None
        last_rebuild = time.monotonic()
        last_update_check = 0.0
        while not self.stop.is_set():
            settings = self.store.settings()
            now = time.monotonic()
            next_due = 0.0 if last_scan is None else last_scan + settings["interval_min"] * 60
            if self.scan_requested or (settings["auto"] and now >= next_due):
                self.scan_requested = False
                self.collect()
                last_scan = time.monotonic()
                next_due = last_scan + settings["interval_min"] * 60
                last_rebuild = time.monotonic()
            elif now - last_rebuild > 60:
                # Pasif dinleme ve ajan raporları tarama beklemeden haritaya yansısın
                try:
                    self.rebuild()
                except Exception as e:
                    log(f"yeniden hesaplama hatası: {e}")
                last_rebuild = time.monotonic()
            if now - last_update_check > 1800:
                threading.Thread(target=self.check_update, daemon=True).start()
                last_update_check = now
            self.status["next"] = (util.iso(util.utcnow() + dt.timedelta(
                seconds=max(0, next_due - time.monotonic()))) if settings["auto"] else None)
            self.wake.wait(5)
            self.wake.clear()

    # ------------------------------------------------------------ güncelleme
    def start_update(self):
        if self.fixtures:
            return False, "test modunda güncelleme yok"
        if self.updating:
            return False, "güncelleme zaten sürüyor"
        cli = shutil.which("nodesk") or os.path.join(store.APP_DIR, "bin", "nodesk")
        unit = f"nodesk-update-{int(time.time())}"
        try:
            subprocess.run(["systemd-run", f"--unit={unit}", "--collect", "--quiet",
                            "--description=Nodesk güncellemesi", cli, "update"],
                           check=True, capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError) as e:
            return False, f"güncelleme başlatılamadı: {e}"
        self.updating = True
        return True, unit


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    app: App = None
    server_version = "nodesk"

    def log_message(self, fmt, *args):  # erişim günlüğünü kirletme
        pass

    # yardımcılar
    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, status=200, ctype="text/plain; charset=utf-8"):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def fail(self, msg, status=400):
        self.send_json({"error": msg}, status)

    def body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("istek çok büyük")
        return self.rfile.read(n) if n else b""

    def json_body(self):
        # Sadece application/json: başka sitelerin form ile istek atmasını (CSRF) engeller
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise PermissionError("Content-Type application/json olmalı")
        raw = self.body(64 * 1024)
        return json.loads(raw or b"{}")

    def route(self):
        u = urllib.parse.urlsplit(self.path)
        return u.path.rstrip("/") or "/", dict(urllib.parse.parse_qsl(u.query))

    def remote(self):
        return (self.headers.get("X-Real-IP") or self.client_address[0])

    # yöntemler
    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def do_PUT(self):
        self.dispatch("PUT")

    def do_DELETE(self):
        self.dispatch("DELETE")

    def dispatch(self, method):
        path, q = self.route()
        app = self.app
        try:
            if method == "GET" and path == "/api/state":
                return self.send_json(self.state())
            if method == "POST" and path == "/api/scan":
                self.json_body()
                return self.send_json({"started": app.request_scan(), "status": app.status})
            if method == "PUT" and path == "/api/settings":
                s = app.store.set_settings(self.json_body())
                if not app.fixtures:
                    if s["sources"]["passive"]:
                        app.passive.start()
                    else:
                        app.passive.stop()
                app.wake.set()
                app.rebuild()
                return self.send_json(s)
            if method == "PUT" and path == "/api/device":
                nid = q.get("id") or ""
                if not nid or len(nid) > 80:
                    return self.fail("id gerekli")
                res = app.store.set_device(nid, self.json_body())
                app.rebuild()
                return self.send_json({"id": nid, "override": res})
            if method == "PUT" and path == "/api/site":
                res = app.store.set_site(q.get("id", ""), self.json_body())
                app.rebuild()
                return self.send_json({"id": q.get("id"), "override": res})
            if method == "PUT" and path == "/api/app":
                aid = q.get("id") or ""
                if not aid or len(aid) > 80:
                    return self.fail("id gerekli")
                res = app.store.set_app(aid, self.json_body())
                app.rebuild()
                return self.send_json({"id": aid, "override": res})
            if method == "GET" and path == "/api/agents":
                return self.send_json(self.agent_list())
            if method == "POST" and path == "/api/agents":
                b = self.json_body()
                ag = app.store.add_agent(b.get("name"), b.get("kind", "linux"))
                return self.send_json(self.agent_list())
            if method == "DELETE" and path == "/api/agent":
                self.json_body()
                ok = app.store.remove_agent(q.get("name", ""))
                app.rebuild()
                return self.send_json({"removed": ok})
            if method == "GET" and path == "/api/agent/install":
                name, token = q.get("name", ""), q.get("token", "")
                if not app.store.check_token(name, token):
                    return self.send_text("echo 'Nodesk: geçersiz ajan anahtarı'; exit 1\n", 403)
                kind = app.store.agents()["agents"][name]["kind"]
                return self.send_text(agents.installer(kind, app.public_url(), name, token),
                                      ctype="text/x-shellscript; charset=utf-8")
            if method == "POST" and path == "/api/ingest":
                name, token = q.get("agent", ""), q.get("token", "")
                if not app.store.check_token(name, token):
                    return self.fail("geçersiz ajan anahtarı", 403)
                text = self.body(1024 * 1024).decode("utf-8", "replace")
                if "#END" not in text:
                    return self.fail("rapor eksik (#END yok)")
                app.store.save_report(name, text, self.remote())
                if app.store.agents()["agents"][name]["kind"] == "router":
                    app.import_router_names()
                threading.Thread(target=app.rebuild, daemon=True).start()
                kind = app.store.agents()["agents"][name]["kind"]
                want = agents.expected_version(kind)
                have = agents.reported_version(kind, util.parse_sections(text))
                if app.store.settings().get("agent_auto_update", True) and have != want:
                    log(f"ajan {name}: sürüm {have} -> {want}, kendini güncelleyecek")
                    return self.send_text("ok update\n")
                return self.send_text("ok\n")
            if method == "POST" and path == "/api/update/check":
                self.json_body()
                info = app.check_update(force=True)
                app.rebuild()
                return self.send_json(info)
            if method == "POST" and path == "/api/update":
                self.json_body()
                ok, msg = app.start_update()
                return self.send_json({"started": ok, "message": msg}, 200 if ok else 409)
            return self.fail("bulunamadı", 404)
        except PermissionError as e:
            return self.fail(str(e), 415)
        except (ValueError, json.JSONDecodeError) as e:
            return self.fail(str(e), 400)
        except Exception as e:
            log("API hatası: " + "".join(traceback.format_exception(e))[-800:])
            return self.fail("sunucu hatası", 500)

    def agent_list(self):
        app = self.app
        reports = app.store.reports()
        out = []
        for name, a in sorted(app.store.agents()["agents"].items()):
            r = reports.get(name, {})
            out.append({"name": name, "kind": a["kind"], "received": r.get("received"),
                        "from": r.get("from"),
                        "commands": agents.install_commands(a["kind"], app.public_url(), name,
                                                            a["token"])})
        return out

    def state(self):
        app = self.app
        return {
            "app": app.app_info(),
            "settings": app.store.settings(),
            "scan": {k: app.status.get(k) for k in
                     ("running", "last_start", "last_end", "last_ok", "last_error", "next")},
            "sources": {**app.status.get("sources", {}),
                        "passive": {"ok": app.passive.running or bool(app.fixtures),
                                    "count": len(app.passive.data), "error": app.passive.error}},
            "types": list(store.DEVICE_TYPES),
            "intervals": list(store.INTERVALS),
            "public_url": app.public_url(),
        }


def serve(home, fixtures=None):
    app = App(home, fixtures)
    log(f"Nodesk {app.version()} başlıyor ({home})")
    settings = app.store.settings()
    if settings["sources"]["passive"] and not fixtures:
        app.passive.start()
    Handler.app = app
    httpd = ThreadingHTTPServer((os.environ.get("NODESK_API_HOST", API_HOST), API_PORT), Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, name="http", daemon=True).start()
    log(f"API: http://{API_HOST}:{API_PORT}/api/")
    try:
        app.scheduler()
    except KeyboardInterrupt:
        pass
    finally:
        app.stop.set()
        app.passive.stop()
        app.passive.prune_and_save()
        httpd.shutdown()


def collect_once(home, fixtures=None):
    app = App(home, fixtures)
    ok = app.collect()
    return 0 if ok else 1
