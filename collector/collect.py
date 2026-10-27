#!/usr/bin/env python3
"""nodesk veri toplayıcı.

Ağı port taramasıyla değil, bilgiyi zaten tutan kaynaklardan okur:
  - Tailscale:  `tailscale status --json`
  - Ev 1 LAN:   Pi'den `arp-scan` (L2, ~256 ARP paketi)
  - Ev 2:       router'daki kısıtlı `topo-collect` scripti (SSH ile)
                -> DHCP kiraları, ARP komşuları, WAN tarafında arp-scan
  - Pi servisleri: `docker ps`

Sonucu <NODESK_HOME>/www/data.json'a yazar. Sadece Python standart kütüphanesi
kullanır. Test için NODESK_FIXTURES=<klasör> verilirse komutlar yerine o
klasördeki dosyalar okunur.

Klasör düzeni (NODESK_HOME, varsayılan /DATA/AppData/nodesk):
  app/          git deposu (bu dosya app/collector/collect.py)
  config.toml   kullanıcı ayarları (güncellemede dokunulmaz)
  data/         state.json, known_hosts, update.json
  keys/         router_ed25519, deploy_ed25519
  www/          data.json (nginx /live/ altında yayınlar)
"""

import datetime as dt
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = os.environ.get("NODESK_HOME", "/DATA/AppData/nodesk")
CONFIG_PATH = os.environ.get("NODESK_CONFIG", os.path.join(HOME, "config.toml"))
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = os.path.join(APP, "config.example.toml")
DATA_DIR = os.path.join(HOME, "data")
FIXTURES = os.environ.get("NODESK_FIXTURES")
NOW = dt.datetime.now(dt.timezone.utc)
if os.environ.get("NODESK_NOW"):  # testler için sabit zaman
    NOW = dt.datetime.fromisoformat(os.environ["NODESK_NOW"])

errors = []


def log(msg):
    print(f"[nodesk] {msg}", file=sys.stderr)


# ---------------------------------------------------------------- komutlar

def run(key, cmd, timeout=30):
    """Komutu çalıştır; test modunda fixture dosyasını oku. Hata -> None."""
    if FIXTURES:
        path = os.path.join(FIXTURES, key)
        if not os.path.exists(path):
            errors.append(f"{key}: fixture yok")
            return None
        with open(path, encoding="utf-8") as f:
            return f.read()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        errors.append(f"{key}: {e}")
        return None
    if out.returncode != 0:
        errors.append(f"{key}: çıkış kodu {out.returncode}: {out.stderr.strip()[:200]}")
        return None
    return out.stdout


# ---------------------------------------------------------------- yardımcılar

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


def is_local_mac(mac):
    """Yerel yönetimli (çoğu zaman telefonların rastgele) MAC adresi mi?"""
    return bool(mac) and (int(mac.split(":")[0], 16) & 0x02) != 0


def load_oui(path):
    table = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.rstrip("\n").split("\t", 1)
                if len(parts) != 2:
                    continue
                key = parts[0].replace(":", "").replace("-", "").upper()
                if len(key) >= 6:
                    table[key[:6]] = parts[1].strip()
    except OSError:
        pass
    return table


def vendor_for(mac, oui):
    if not mac:
        return None
    return oui.get(mac.replace(":", "")[:6].upper())


def guess_type(vendor, mac):
    v = (vendor or "").lower()
    rules = [
        ("roborock", "iot"), ("yeelink", "iot"), ("xiaomi", "iot"),
        ("espressif", "iot"), ("tuya", "iot"), ("shelly", "iot"),
        ("keenetic", "ap"), ("zyxel", "ap"), ("tp-link", "ap"),
        ("raspberry", "server"),
        ("apple", "phone"), ("oneplus", "phone"),
    ]
    for key, kind in rules:
        if key in v:
            return kind
    if not vendor and is_local_mac(mac):
        return "phone"  # rastgele MAC: büyük ihtimalle telefon/tablet
    return "device"


VENDOR_NOISE = {"beijing", "shanghai", "shenzhen", "guangzhou", "hangzhou", "xiamen",
                "co", "co.", "ltd", "ltd.", "inc", "inc.", "corp", "corporation",
                "limited", "technology", "technologies", "electronics", "electronic",
                "mobile", "software", "communication", "communications", "network",
                "networks", "international", "san", "ve", "tic", "a.s.", "gmbh", "llc"}


def short_vendor(vendor):
    """'Beijing Roborock Technology Co., Ltd.' -> 'Roborock'"""
    if not vendor:
        return None
    vendor = re.sub(r"\bco\.?,?\s*ltd\.?", " ", vendor, flags=re.I)
    words = [w.strip(",.()") for w in vendor.split()]
    keep = [w for w in words if w and w.lower().strip(".") not in VENDOR_NOISE
            and w.lower() not in VENDOR_NOISE]
    return " ".join(keep[:2]) or words[0]


def fallback_label(vendor, mac, ip):
    tail = f" (.{ip.rsplit('.', 1)[-1]})" if ip and "." in ip else ""
    sv = short_vendor(vendor)
    if sv:
        return sv + tail
    if is_local_mac(mac):
        return "Telefon/tablet?" + tail
    return "Bilinmeyen" + tail


def ip_sort_key(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------- toplayıcılar

def collect_tailscale():
    raw = run("tailscale.json", ["tailscale", "status", "--json"])
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        errors.append(f"tailscale.json: {e}")
        return None


def ts_short(node):
    dns = (node.get("DNSName") or "").split(".")[0]
    return (dns or node.get("HostName") or "?").lower()


def ts_info(node, is_self=False):
    ips = node.get("TailscaleIPs") or []
    v4 = next((i for i in ips if ":" not in i), ips[0] if ips else None)
    if is_self:
        path = "bu cihaz"
    elif node.get("CurAddr"):
        path = "doğrudan"
    elif node.get("Relay"):
        path = f"aktarıcı ({node['Relay']})"
    else:
        path = "bağlantı yok"
    return {
        "name": ts_short(node),
        "ip": v4,
        "os": node.get("OS"),
        "online": bool(node.get("Online")) or is_self,
        "path": path,
        "exit_offer": bool(node.get("ExitNodeOption")),
        "routes": node.get("PrimaryRoutes") or [],
        "last_seen": node.get("LastSeen"),
    }


def collect_self_ifaces():
    """Pi'nin kendi arayüzleri: arp-scan kendini listelemez."""
    raw = run("ip_addr.json", ["ip", "-j", "addr", "show"])
    res = []
    if not raw:
        return res
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return res
    for link in data:
        name = link.get("ifname", "")
        mac = norm_mac(link.get("address"))
        if not mac or name.startswith(("docker", "br-", "veth", "tailscale", "lo")):
            continue
        for a in link.get("addr_info", []):
            if a.get("family") == "inet":
                res.append({"ifname": name, "mac": mac, "ip": a.get("local")})
    return res


def parse_arpscan(text, oui):
    """arp-scan --plain çıktısı: IP<TAB>MAC[<TAB>Üretici]"""
    out = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        mac = norm_mac(parts[1])
        try:
            ipaddress.ip_address(parts[0].strip())
        except ValueError:
            continue
        if not mac:
            continue
        vendor = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
        if vendor:
            vendor = re.sub(r"\s*\(DUP: \d+\)\s*$", "", vendor) or None
        if vendor and vendor.lower() in ("(unknown)", "unknown"):
            vendor = None
        if vendor and "locally administered" in vendor.lower():
            vendor = None
        out.append({"ip": parts[0].strip(), "mac": mac,
                    "vendor": vendor or vendor_for(mac, oui)})
    return out


def collect_docker():
    raw = run("docker.txt", ["docker", "ps", "--format",
                             "{{.Names}}\t{{.Image}}\t{{.Ports}}"])
    services = []
    for line in (raw or "").splitlines():
        parts = line.split("\t")
        if not parts or not parts[0]:
            continue
        ports = sorted({m for m in re.findall(r":(\d+)->", parts[2] if len(parts) > 2 else "")},
                       key=int)
        services.append({"name": parts[0], "image": parts[1] if len(parts) > 1 else "",
                         "ports": ports})
    return services


def collect_router(cfg):
    r = cfg.get("router", {})
    cmd = ["ssh", "-i", r.get("key", os.path.join(HOME, "keys", "router_ed25519")),
           "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
           "-o", "StrictHostKeyChecking=accept-new",
           "-o", f"UserKnownHostsFile={os.path.join(DATA_DIR, 'known_hosts')}",
           f"{r.get('user', 'root')}@{r.get('host', '192.168.77.1')}", "topo-collect"]
    raw = run("router.txt", cmd, timeout=40)
    if raw is None or "#END" not in raw:
        if raw is not None:
            errors.append("router: çıktı eksik (#END yok)")
        return None
    sections, cur = {}, None
    for line in raw.splitlines():
        if line.startswith("#") and line[1:].isupper():
            cur = line[1:]
            sections[cur] = []
        elif cur:
            sections[cur].append(line)
    return sections


# ---------------------------------------------------------------- model

# ---------------------------------------------------------------- sürüm / güncelleme

def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return default


def git(*args, timeout=20):
    try:
        out = subprocess.run(["git", "-C", APP, *args], capture_output=True, text=True,
                             timeout=timeout)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def app_info(cfg):
    """Kurulu sürüm ve (birkaç saatte bir) depoda yeni sürüm olup olmadığı."""
    info = {"version": read_text(os.path.join(APP, "VERSION"), "?"),
            "rev": None, "update": None}
    if FIXTURES:
        return info
    info["rev"] = git("rev-parse", "--short", "HEAD")
    hours = cfg.get("general", {}).get("update_check_hours", 6)
    cache_path = os.path.join(DATA_DIR, "update.json")
    try:
        with open(cache_path, encoding="utf-8") as f:
            cache = json.load(f)
    except (OSError, json.JSONDecodeError):
        cache = {}
    last = cache.get("checked")
    due = hours and (not last or NOW - dt.datetime.fromisoformat(last) > dt.timedelta(hours=hours))
    if due:
        branch = cfg.get("general", {}).get("branch", "main")
        if git("fetch", "--quiet", "origin", branch, timeout=40) is not None:
            behind = git("rev-list", "--count", f"HEAD..origin/{branch}")
            cache = {"checked": NOW.isoformat(timespec="seconds"),
                     "behind": int(behind or 0),
                     "latest": git("show", f"origin/{branch}:VERSION") or "?",
                     "latest_rev": git("rev-parse", "--short", f"origin/{branch}")}
        else:
            cache = {"checked": NOW.isoformat(timespec="seconds"), "error": True,
                     **{k: v for k, v in cache.items() if k in ("behind", "latest", "latest_rev")}}
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f)
        except OSError:
            pass
    # Önbellekteki "geride" bilgisi, bu arada güncelleme yapılmışsa eskimiş olabilir.
    if cache.get("behind") and cache.get("latest_rev") != info["rev"]:
        info["update"] = {"latest": cache.get("latest"), "behind": cache.get("behind")}
    return info


def router_script_info(router):
    expected = None
    for line in read_text(os.path.join(APP, "router", "topo-collect")).splitlines():
        if line.startswith("TOPO_VERSION="):
            expected = line.split("=", 1)[1].strip()
    if router is None:
        return {"expected": expected, "installed": None, "ok": None}
    installed = ((router.get("VERSION") or ["0"])[0] or "0").strip()
    return {"expected": expected, "installed": installed, "ok": installed == expected}


class Graph:
    def __init__(self):
        self.nodes = {}
        self.overlay = []

    def add(self, nid, **kw):
        node = self.nodes.setdefault(nid, {"id": nid, "ips": [], "services": []})
        for k, v in kw.items():
            if k == "ips":
                for ip in v:
                    if ip and ip not in node["ips"]:
                        node["ips"].append(ip)
            elif v is not None:
                node[k] = v
        node["ips"].sort(key=ip_sort_key)
        return node


def main():
    with open(CONFIG_PATH, "rb") as f:
        cfg = tomllib.load(f)

    devcfg = {norm_mac(k): v for k, v in cfg.get("devices", {}).items() if norm_mac(k)}
    site_of = {k.lower(): v for k, v in cfg.get("tailscale", {}).get("site_of", {}).items()}
    ev1, ev2 = cfg.get("ev1", {}), cfg.get("ev2", {})
    forget_days = cfg.get("general", {}).get("forget_after_days", 14)
    web_dir = cfg.get("general", {}).get("web_dir", os.path.join(HOME, "www"))
    state_path = cfg.get("general", {}).get("state_file", os.path.join(DATA_DIR, "state.json"))
    oui = load_oui(os.environ.get("NODESK_OUI", cfg.get("general", {}).get(
        "oui_file", "/usr/share/arp-scan/ieee-oui.txt")))

    g = Graph()
    sites = [
        {"id": "ev1", "name": ev1.get("name", "Ev 1")},
        {"id": "ev2", "name": ev2.get("name", "Ev 2")},
        {"id": "oracle", "name": cfg.get("oracle", {}).get("name", "Oracle Cloud")},
        {"id": "mobile", "name": cfg.get("mobile", {}).get("name", "Uzak / Mobil")},
    ]

    g.add("internet", label="İnternet", kind="internet", site=None, parent=None, online=True)

    # ---------------------------------------------- Tailscale
    ts = collect_tailscale()
    ts_nodes = {}       # kısa ad -> info
    ts_by_id = {}       # node ID -> kısa ad
    if ts:
        me = ts.get("Self") or {}
        ts_nodes[ts_short(me)] = ts_info(me, is_self=True)
        ts_by_id[me.get("ID")] = ts_short(me)
        for p in (ts.get("Peer") or {}).values():
            ts_nodes[ts_short(p)] = ts_info(p)
            ts_by_id[p.get("ID")] = ts_short(p)
    ts_self = ts_short((ts or {}).get("Self") or {}) if ts else None

    # ---------------------------------------------- Ev 1
    ev1_gw = ev1.get("gateway_ip", "192.168.44.1")
    seen = {}  # id -> node kwargs (bu turda görülenler)

    self_ifaces = collect_self_ifaces()
    self_macs = {i["mac"] for i in self_ifaces}
    pi_id = "self"
    pi_ts = ts_nodes.get(ts_self) if ts_self else None
    seen[pi_id] = dict(
        label=ev1.get("server_name", "home-pi"), kind="server", site="ev1",
        ips=[i["ip"] for i in self_ifaces],
        macs=sorted(self_macs),
        ifaces=[f"{i['ifname']} {i['ip']} {i['mac']}" for i in self_ifaces],
        tailscale=pi_ts, services=collect_docker(), parent_hint="ev1-gw")

    arp1 = run("arpscan_ev1.txt", ["arp-scan", f"--interface={ev1.get('interface', 'eth0')}",
                                   "--localnet", "--plain", "--retry=2"], timeout=60)
    by_mac = {}
    for e in parse_arpscan(arp1, oui):
        if e["mac"] in self_macs:
            continue
        by_mac.setdefault(e["mac"], {"ips": [], "vendor": e["vendor"]})
        by_mac[e["mac"]]["ips"].append(e["ip"])
        by_mac[e["mac"]]["vendor"] = by_mac[e["mac"]]["vendor"] or e["vendor"]
    for mac, d in by_mac.items():
        nid = f"mac:{mac}"
        is_gw = ev1_gw in d["ips"]
        seen[nid] = dict(mac=mac, vendor=d["vendor"], ips=d["ips"], site="ev1",
                         kind="modem" if is_gw else None,
                         label=ev1.get("modem_name") if is_gw else None,
                         parent_hint=None if is_gw else "ev1-gw",
                         is_root=is_gw)
    if arp1 is None:
        errors.append("Ev 1 taraması başarısız; Ev 1 cihazları son bilinen durumlarıyla gösteriliyor")

    # ---------------------------------------------- Ev 2 (router)
    router = collect_router(cfg)
    router_id = "router"
    router_ts = ts_nodes.get(ev2.get("router_ts_name", "home-router"))
    router_kw = dict(label=ev2.get("router_name", "home-router"), kind="router", site="ev2",
                     tailscale=router_ts, parent_hint="ev2-gw")
    modem2_ip = ev2.get("modem_ip", "192.168.1.1")
    if router is not None:
        ips, macs = [], []
        for line in router.get("ADDR", []):
            m = re.search(r"\d+:\s+(\S+)\s+inet\s+(\S+)/", line)
            if m and m.group(1) != "lo" and not m.group(1).startswith("tailscale"):
                ips.append(m.group(2))
        router_kw["ips"] = ips
        seen[router_id] = router_kw

        # WAN tarafı: H3600P ağı
        for e in parse_arpscan("\n".join(router.get("ARPSCAN_WAN", [])), oui):
            nid = f"mac:{e['mac']}"
            is_gw = e["ip"] == modem2_ip
            seen[nid] = dict(mac=e["mac"], vendor=e["vendor"], ips=[e["ip"]], site="ev2",
                             kind="modem" if is_gw else None,
                             label=ev2.get("modem_name") if is_gw else None,
                             parent_hint=None if is_gw else "ev2-gw", is_root=is_gw)

        # Router LAN: DHCP kiraları + şu an erişilebilir komşular
        lan = {}
        for line in router.get("LEASES", []):
            p = line.split()
            if len(p) >= 4 and norm_mac(p[1]):
                lan[norm_mac(p[1])] = {"ip": p[2], "hostname": None if p[3] == "*" else p[3],
                                       "lease": True, "reachable": False}
        for line in router.get("NEIGH", []):
            m = re.match(r"(\S+) dev (\S+) lladdr (\S+) .*?(REACHABLE|STALE|DELAY|PROBE|PERMANENT)", line)
            if not m or m.group(2) != ev2.get("lan_dev", "br-lan"):
                continue
            mac = norm_mac(m.group(3))
            if not mac:
                continue
            d = lan.setdefault(mac, {"ip": m.group(1), "hostname": None, "lease": False})
            d["reachable"] = True
        for mac, d in lan.items():
            nid = f"mac:{mac}"
            seen[nid] = dict(mac=mac, vendor=vendor_for(mac, oui), ips=[d["ip"]],
                             hostname=d["hostname"], site="ev2", parent_hint=router_id,
                             online_override=bool(d.get("reachable")),
                             note=None if d.get("reachable") else
                             "DHCP kirası var ama şu an router'ın ARP tablosunda yok")

        # Router hangi exit node'u kullanıyor?
        ex = (router.get("EXITNODE") or [""])[0].strip()
        if ex and ex in ts_by_id:
            g.overlay.append({"from": router_id, "to_ts": ts_by_id[ex], "kind": "exit",
                              "label": "exit node"})
    else:
        errors.append("Router'a ulaşılamadı; Ev 2 son bilinen durumuyla gösteriliyor")

    # ---------------------------------------------- Tailscale-only düğümler
    for name, info in ts_nodes.items():
        site = site_of.get(name, "mobile")
        if name == ts_self:
            continue
        if name == ev2.get("router_ts_name", "home-router"):
            continue
        nid = f"ts:{name}"
        seen[nid] = dict(label=name, kind="cloud-vm" if site == "oracle" else
                         ("laptop" if info.get("os") in ("linux", "windows", "macOS") else "phone"),
                         site=site, ips=[info["ip"]] if info.get("ip") else [],
                         tailscale=info, parent_hint=f"{site}-gw",
                         ts_only=True, online_override=info["online"])

    # ---------------------------------------------- durum (son görülme)
    try:
        with open(state_path, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError):
        state = {}

    now_s = NOW.isoformat(timespec="seconds")
    for nid, kw in seen.items():
        st = state.setdefault(nid, {"first_seen": now_s})
        if kw.get("online_override", True):
            st["last_seen"] = now_s
        st["snapshot"] = {k: v for k, v in kw.items() if k not in ("online_override",)}

    # Bu tur görülmeyen ama yakın zamanda görülenleri çevrimdışı olarak tut
    # (uyuyan telefonlar/TV'ler haritadan kaybolmasın).
    failed_sites = set()
    if arp1 is None:
        failed_sites.add("ev1")
    if router is None:
        failed_sites.add("ev2")
    cutoff = NOW - dt.timedelta(days=forget_days)
    for nid in list(state):
        st = state[nid]
        last = dt.datetime.fromisoformat(st.get("last_seen", st.get("first_seen")))
        if nid not in seen and last < cutoff:
            del state[nid]

    # ---------------------------------------------- grafik
    sites_present = {"ev1", "ev2"}
    for s in sites:
        if s["id"] not in sites_present and any(
                st["snapshot"].get("site") == s["id"] for st in state.values()):
            sites_present.add(s["id"])

    # Her site için kök düğüm: modem ya da yer tutucu
    roots = {}
    for nid, st in state.items():
        snap = st["snapshot"]
        if snap.get("is_root"):
            roots[f"{snap['site']}-gw"] = nid
    defaults = {
        "ev1-gw": dict(label=ev1.get("modem_name", "Ev 1 modem"), kind="modem", site="ev1",
                       ips=[ev1_gw]),
        "ev2-gw": dict(label=ev2.get("modem_name", "Ev 2 modem"), kind="modem", site="ev2",
                       ips=[modem2_ip]),
        "oracle-gw": dict(label=cfg.get("oracle", {}).get("name", "Oracle Cloud"), kind="cloud",
                          site="oracle", ips=[]),
        "mobile-gw": dict(label=cfg.get("mobile", {}).get("root_name", "Gezgin cihazlar"),
                          kind="roam", site="mobile", ips=[]),
    }
    for gw, kw in defaults.items():
        if gw.split("-")[0] not in sites_present:
            continue
        if gw not in roots:
            roots[gw] = gw
            g.add(gw, parent="internet", online=True, **kw)

    for nid, st in state.items():
        snap = dict(st["snapshot"])
        mac = snap.get("mac")
        conf = devcfg.get(mac, {}) if mac else {}
        if nid == pi_id:
            conf = cfg.get("devices", {}).get("self", {})
        online = nid in seen and (seen[nid].get("online_override", True))
        hint = snap.pop("parent_hint", None)
        parent = "internet" if snap.get("is_root") else roots.get(hint, hint)
        if conf.get("parent"):
            pm = norm_mac(conf["parent"])
            parent = f"mac:{pm}" if pm else conf["parent"]
        label = conf.get("name") or snap.get("label") or snap.get("hostname") \
            or fallback_label(snap.get("vendor"), mac, (snap.get("ips") or [None])[0])
        kind = conf.get("type") or snap.get("kind") or guess_type(snap.get("vendor"), mac)
        for k in ("label", "kind", "ts_only", "is_root"):
            snap.pop(k, None)
        g.add(nid, label=label, kind=kind, parent=parent, online=online,
              last_seen=st.get("last_seen"), first_seen=st.get("first_seen"),
              random_mac=is_local_mac(mac) if mac else None,
              stale=snap.get("site") in failed_sites and nid not in seen,
              short_vendor=short_vendor(snap.get("vendor")),
              **snap)

    # Kökü olmayan (eski) ebeveyn referanslarını düzelt
    for n in g.nodes.values():
        if n.get("parent") and n["parent"] not in g.nodes:
            n["parent"] = roots.get(f"{n.get('site')}-gw", "internet")

    # Tailscale overlay: ad -> düğüm id
    ts_to_node = {}
    for n in g.nodes.values():
        if n.get("tailscale"):
            ts_to_node[n["tailscale"]["name"]] = n["id"]
    overlay = []
    for o in g.overlay:
        if o["to_ts"] in ts_to_node:
            overlay.append({"from": o["from"], "to": ts_to_node[o["to_ts"]],
                            "kind": o["kind"], "label": o["label"]})

    data = {
        "generated": now_s,
        "sites": [s for s in sites if s["id"] in sites_present],
        "nodes": sorted(g.nodes.values(), key=lambda n: (n.get("site") or "", ip_sort_key(
            (n.get("ips") or ["0.0.0.0"])[0]))),
        "overlay": overlay,
        "errors": errors,
        "app": app_info(cfg),
        "router_script": router_script_info(router),
    }

    os.makedirs(web_dir, exist_ok=True)
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    for path, obj in ((os.path.join(web_dir, "data.json"), data), (state_path, state)):
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".tmp-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)

    online = sum(1 for n in data["nodes"] if n.get("online"))
    log(f"{len(data['nodes'])} düğüm ({online} çevrimiçi), {len(errors)} hata")
    for e in errors:
        log(f"  ! {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
