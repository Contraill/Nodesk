"""Ham kaynak verilerini haritaya (data.json) dönüştürür.

build() saf bir fonksiyondur: ağ/disk erişimi yapmaz. Böylece arayüzden yapılan bir
ad değişikliği tarama beklemeden, son ham veriden yeniden hesaplanabilir.
"""

import datetime as dt
import ipaddress
import re
import struct

from . import passive, probe, sites as sitesmod, sources, util

ROUTER_FRESH_MIN = 15      # router ajanı 5 dakikada bir rapor verir
AGENT_FRESH_MIN = 20

TYPE_RULES = [
    (r"roborock|rockrobo|roomba|dreame|vacuum", "vacuum"),
    (r"yeelink|yeelight|\bhue\b|lamp|bulb|\blight\b", "lamp"),
    (r"imilab|camera|ipcam|ezviz|hikvision|dahua|reolink|_rtsp", "camera"),
    (r"appletv", "tv"), (r"audioaccessory|homepod", "speaker"), (r"\bimac|macmini|macpro", "pc"),
    (r"_googlecast|webos|tizen|bravia|smart-?tv|androidtv|android tv|chromecast|lgwebos|"
     r"vestel|roku|fire ?tv|\btv\b", "tv"),
    (r"_ipp|_printer|_pdl-datastream|printer|epson|brother|canon", "printer"),
    (r"playstation|xbox|nintendo", "console"),
    (r"ipad|galaxy[ _-]?tab|tablet", "tablet"),
    (r"iphone|galaxy|\bsm-|android|redmi|pixel|oneplus|huawei|honor|oppo|vivo|realme|phone", "phone"),
    (r"macbook|laptop|thinkpad|notebook", "laptop"),
    (r"desktop-|msft 5\.0|windows|\bpc\b", "pc"),
    (r"_spotify-connect|sonos|speaker|_raop", "speaker"),
    (r"synology|qnap|\bnas\b", "nas"),
    (r"espressif|tuya|shelly|tasmota|esp32|esp8266|xiaomi|aqara|sonoff", "iot"),
    (r"keenetic|zyxel|tp-link|extender|repeater|mesh", "ap"),
    (r"raspberry", "server"),
    (r"apple", "phone"),
]


def os_guess(names):
    """DHCP parmak izi (opsiyon 60 istemci sınıfı, 55 istenen seçenekler) ve Apple model kodundan
    işletim sistemi. Her cihaz ağa katılırken DHCP yaptığı için en az yanıtsız kalan kaynak."""
    v = (names.get("dhcp_vendor") or "").lower()
    fp = (names.get("dhcp_fp") or "").split(",")
    model = (names.get("model") or "").lower()
    if v.startswith("android-dhcp-"):
        return "Android " + v.rsplit("-", 1)[-1]
    if v.startswith("android"):
        return "Android"
    if v.startswith("msft"):
        return "Windows"
    if v.startswith("dhcpcd") and "linux" in v:
        return "Linux"
    if v.startswith("udhcp"):
        return "Gömülü Linux"
    if model.startswith(("iphone", "ipad", "ipod")):
        return "iOS"
    if model.startswith(("macbook", "imac", "macmini", "macpro", "mac1")):
        return "macOS"
    if fp[:2] == ["1", "121"] and "252" in fp:   # Apple'ın DHCP istemcisi (iOS/macOS)
        return "Apple"
    return None


def guess_type(vendor, mac, names=None):
    names = names or {}
    text = " ".join(str(x) for x in [
        vendor or "", names.get("dhcp_name", ""), names.get("mdns_name", ""), os_guess(names) or "",
        names.get("friendly", ""), names.get("model", ""), names.get("ssdp_server", ""),
        names.get("dhcp_vendor", ""), names.get("nb_name", ""),
        " ".join(names.get("mdns_services", []))]).lower()
    for pat, kind in TYPE_RULES:
        if re.search(pat, text):
            return kind
    if not vendor and util.is_local_mac(mac):
        return "phone"   # rastgele MAC: büyük ihtimalle telefon/tablet
    return "device"


def best_name(names):
    for k in ("friendly", "dhcp_name", "mdns_name", "nb_name"):
        v = names.get(k)
        if v and v.lower() not in ("localhost", "android", "*"):
            return v
    inst = names.get("mdns_instances") or []
    return inst[0] if inst else None


NAME_KEYS = passive.NAME_FIELDS + passive.LIST_FIELDS


def twin_mac(a, b):
    """50:ff:20:73:86:18 ve 52:ff:20:53:86:18: aynı cihazın ikinci ('yerel yönetimli') MAC'i.
    Bazı tekrarlayıcılar (örn. Keenetic) DHCP'de birini, ARP'de öbürünü kullanır."""
    try:
        x, y = a.split(":"), b.split(":")
        return (a != b and len(x) == len(y) == 6 and x[1:3] == y[1:3] and x[4:] == y[4:]
                and (int(x[0], 16) & 0xFC) == (int(y[0], 16) & 0xFC))
    except (ValueError, AttributeError):
        return False


ROUTER_PORTS = {22: ("dropbear", "SSH"), 53: ("dnsmasq", "DNS"), 80: ("uhttpd", "LuCI"),
                443: ("uhttpd", "LuCI"), 8080: ("uhttpd", "LuCI")}


def router_name_obs(sections):
    """Router raporunun #NAMES satırları ("ip nb|mdns|dhcp hex") -> pasif kayda gözlemler.
    nb/mdns: router'ın ad sorusuna yanıtlar ve duyduğu mDNS; dhcp: duyduğu DHCP istekleri."""
    mac_of = {}
    for e in sources.parse_arpscan("\n".join(sections.get("ARPSCAN_WAN") or [])):
        mac_of[e["ip"]] = e["mac"]
    for line in (sections.get("LEASES") or []) + (sections.get("NEIGH") or []):
        p = line.split()
        if len(p) >= 4 and util.norm_mac(p[1]) and util.is_ipv4(p[2]):          # kira: zaman mac ip ad
            mac_of[p[2]] = util.norm_mac(p[1])
        elif len(p) >= 5 and p[3] == "lladdr" and util.is_ipv4(p[0]) and util.norm_mac(p[4]):
            mac_of[p[0]] = util.norm_mac(p[4])
    out = []
    for line in sections.get("NAMES") or []:
        p = line.split()
        if len(p) != 3:
            continue
        ip, kind, hx = p
        try:
            data = bytes.fromhex(hx)
            if kind == "dhcp" and len(data) >= 240 and data[236:240] == b"\x63\x82\x53\x63":
                out += passive._parse_dhcp(data)
            elif kind == "nb":
                out.append({"mac": mac_of.get(ip), "ip": ip, "via": "probe", "nb_name": probe.parse_nbstat(data)})
            elif kind == "mdns":
                out.append(passive.mdns_obs(data, {"mac": mac_of.get(ip), "ip": ip, "via": "mdns"}))
        except (ValueError, struct.error, IndexError):
            continue
    return [o for o in out if o.get("mac")]


def parse_proc_listen(lines):
    """/proc/net/tcp(6) 'yerel_adres:port' (onaltılık) -> dışarı açık portlar."""
    ports = set()
    for line in lines or []:
        addr, _, port = line.strip().rpartition(":")
        try:
            port = int(port, 16)
        except ValueError:
            continue
        if addr in ("0100007F", "00000000000000000000000001000000") or addr.endswith("7F") and len(addr) == 8:
            continue   # 127.x / ::1
        if port < 32768:
            ports.add(port)
    by = {}
    for p in sorted(ports):
        proc, name = ROUTER_PORTS.get(p, (f"port-{p}", f"Port {p}"))
        by.setdefault(proc, {"name": name, "proc": proc, "ports": []})["ports"].append(p)
    return list(by.values())


def fallback_label(vendor, mac, ip, names=None):
    """Adı bilinmeyen cihaz için geçici ad: üretici, yoksa işletim sistemi, yoksa tahmin."""
    tail = f" (.{ip.rsplit('.', 1)[-1]})" if ip and "." in ip else ""
    sv = util.short_vendor(vendor)
    if sv:
        return sv + tail
    os_name = os_guess(names or {})
    if os_name:
        return os_name + tail
    if util.is_local_mac(mac):
        return "Telefon/tablet?" + tail
    return "Bilinmeyen" + tail


# ---------------------------------------------------------------- Tailscale

def ts_short(node):
    dns = (node.get("DNSName") or "").split(".")[0]
    return (dns or node.get("HostName") or "?").lower()


def ts_info(node, is_self=False):
    ips = node.get("TailscaleIPs") or []
    v4 = next((i for i in ips if ":" not in i), ips[0] if ips else None)
    # Relay alanı bağlantının değil, cihazın "ev" DERP bölgesidir: her eşte doludur. Aktarıcı
    # yalnızca trafik varken (Active) doğrudan adres (CurAddr) yoksa; trafik yoksa "boşta".
    if is_self:
        path = "bu cihaz"
    elif not node.get("Online"):
        path = "bağlantı yok"
    elif node.get("CurAddr"):
        path = "doğrudan"
    elif node.get("Active"):
        path = f"aktarıcı ({node.get('Relay') or 'DERP'})"
    else:
        path = "boşta"
    addrs = []
    for a in (node.get("Addrs") or []) + [node.get("CurAddr") or ""]:
        host = a.rpartition(":")[0].strip("[]")
        if util.is_ipv4(host) and host not in addrs:
            addrs.append(host)
    return {"name": ts_short(node), "ip": v4, "os": node.get("OS"), "addrs": addrs,
            "online": bool(node.get("Online")) or is_self, "path": path,
            "exit_offer": bool(node.get("ExitNodeOption")),
            "routes": node.get("PrimaryRoutes") or [], "last_seen": node.get("LastSeen")}


# ---------------------------------------------------------------- servisler

def docker_services(containers, app_name):
    out = []
    for c in containers or []:
        app = c.get("project")
        out.append({
            "id": "docker:" + c["name"], "name": c["name"], "ports": c["ports"],
            "image": c["image"], "state": c["state"], "status": c.get("status"),
            "source": "docker", "app": app, "app_name": app_name(app) if app else None,
        })
    return out


def system_services(ports):
    return [{"id": "system:" + p["proc"], "name": p["name"], "ports": p["ports"],
             "source": "system", "app": "_system", "app_name": "Sistem", "state": "running",
             "proc": p["proc"]} for p in ports or []]


ICON_CDN = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/{}.png"
ICON_SLUGS = [   # (aranan, ikon adı) -> imaj, proje, container ya da süreç adında geçerse
    ("gitea", "gitea"), ("casaos", "casaos"), ("pihole", "pi-hole"), ("pi-hole", "pi-hole"),
    ("homeassistant", "home-assistant"), ("home-assistant", "home-assistant"),
    ("jellyfin", "jellyfin"), ("plex", "plex"), ("portainer", "portainer"),
    ("nextcloud", "nextcloud"), ("grafana", "grafana"), ("prometheus", "prometheus"),
    ("uptime-kuma", "uptime-kuma"), ("vaultwarden", "vaultwarden"), ("immich", "immich"),
    ("syncthing", "syncthing"), ("transmission", "transmission"), ("qbittorrent", "qbittorrent"),
    ("adguard", "adguard-home"), ("postgres", "postgres"), ("redis", "redis"), ("mongo", "mongodb"),
    ("code-server", "code-server"), ("filebrowser", "filebrowser"), ("homarr", "homarr"),
    ("n8n", "n8n"), ("ollama", "ollama"), ("open-webui", "open-webui"), ("traefik", "traefik"),
    ("wg-easy", "wireguard"), ("wireguard", "wireguard"), ("cups", "cups"), ("caddy", "caddy"),
    ("nginx", "nginx"), ("tailscale", "tailscale"),
]
GLYPHS = [  # yerleşik çizgi simgeler (internet gerekmez)
    (("sshd", "dropbear", "ssh"), "terminal"), (("smbd", "samba"), "folder"),
    (("vnc",), "screen"), (("postgres", "mariadb", "mysql", "redis", "mongo"), "database"),
    (("dnsmasq", "pihole", "adguard"), "dns"), (("nodesk",), "nodesk"),
]


def service_icon(project, items, casaos, override):
    """-> (uzak ikon adresi ya da None, yerleşik simge adı)"""
    words = " ".join(filter(None, [project] + [f"{c.get('image', '')} {c.get('name', '')} "
                                               f"{c.get('proc', '')}" for c in items])).lower()
    glyph = next((g for keys, g in GLYPHS if any(k in words for k in keys)), "app")
    if override:
        return override, glyph
    if project and (casaos.get(project) or {}).get("icon"):
        return casaos[project]["icon"], glyph
    for key, slug in ICON_SLUGS:
        if key in words and glyph not in ("terminal", "folder", "screen", "nodesk"):
            return ICON_CDN.format(slug), glyph
    return None, glyph


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:40] or "x"


def service_nodes(nodes, ov_dev, ov_apps, casaos, health, icon_files):
    """Her cihazın servislerini o cihaza bağlı ayrı düğümlere çevirir."""
    out, wanted = {}, set()
    for host in list(nodes.values()):
        groups = {}
        for s in host.get("services") or []:
            if s["source"] == "docker":
                key = f"svc:{host['id']}:{s['app']}" if s.get("app") else f"svc:{host['id']}:c:{s['name']}"
            elif s["source"] == "system":
                key = f"svc:{host['id']}:sys:{s['proc']}"
            else:
                key = f"svc:{host['id']}:m:{slug(s['name'])}"
            groups.setdefault(key, []).append(s)
        ids = []
        for key, items in groups.items():
            first, ov = items[0], ov_dev.get(key, {})
            app = first.get("app") if first["source"] == "docker" else None
            auto = (first.get("app_name") or first["name"]) if app else first["name"]
            running = [c for c in items if (c.get("state") or "running") == "running"]
            ports = sorted({p for c in (running or items) for p in c.get("ports") or []})
            hstate = None
            if host["id"] == "self" and running and ports and health:
                checks = [health.get(p) for p in ports if p in health]
                if checks:
                    hstate = "ok" if all(checks) else ("partial" if any(checks) else "fail")
            icon_url, glyph = service_icon(app, items, casaos, ov.get("icon"))
            icon_local = icon_files.get(icon_url) if icon_url else None
            if icon_url and not icon_local:
                wanted.add(icon_url)
            hidden = bool(ov.get("hidden") or (app and ov_apps.get(app, {}).get("hidden")) or
                          any(c.get("hidden") for c in items))
            source = {"docker": "Docker" + (" (compose/CasaOS uygulaması)" if app else ""),
                      "system": "Pi'de sistem servisi" if host["id"] == "self" else "Sistem servisi",
                      "manual": "Elle eklendi"}[first["source"]]
            out[key] = {
                "id": key, "kind": "service", "label": ov.get("name") or auto, "auto_label": auto,
                "parent": host["id"], "site": host.get("site"), "host": host["id"],
                "online": bool(host.get("online") and running) and hstate != "fail",
                "state": "running" if running else (items[0].get("state") or "exited"),
                "health": hstate, "ports": ports, "app": app, "source": first["source"],
                "source_label": source, "url": next((c.get("url") for c in items if c.get("url")), None),
                "containers": [{"name": c["name"], "image": c.get("image"), "state": c.get("state"),
                                "status": c.get("status"), "ports": c.get("ports") or []}
                               for c in items] if first["source"] == "docker" else [],
                "icon": icon_local, "icon_url": icon_url, "glyph": glyph,
                "ips": [], "services": [], "tags": ov.get("tags") or [], "note": ov.get("note"),
                "hidden": hidden, "edited": bool(ov), "override": ov or None,
                "stale": host.get("stale"),
            }
            ids.append(key)
        host["service_ids"] = ids
    return out, sorted(wanted)


# Telefonların fabrika adları (model adı): iki aile üyesinde aynı olabilir, kimlik sayılmaz.
# "android-1a2b3c4d..." gibi cihaza özgü kimlik taşıyanlar sayılır.
GENERIC_NAME = re.compile(r"^(android|galaxy|samsung|redmi|poco|xiaomi|mi|pixel|iphone|ipad|oneplus|huawei|"
                          r"honor|oppo|vivo|realme|nokia|moto|motorola|tecno|infinix|sm)[ _-]?[a-z0-9 _+-]{0,20}$", re.I)
HEX_ID = re.compile(r"[0-9a-f]{8}", re.I)


def is_generic_name(name):
    return bool(GENERIC_NAME.match(name)) and not HEX_ID.search(name)


def same_device_groups(state, now, cfg_dev, ov_dev):
    """Aynı cihazın farklı MAC'leri (state kimlikleri) -> ([[nid, ...], ...], ayrı çiftler)

    Telefonlar her Wi-Fi ağında ayrı rastgele MAC kullanır; ev içinde modemden extender'a
    geçince başka bir cihaz gibi görünür. Kanıtlar:
      * config.toml'da aynı adla yazılmış MAC'ler (kullanıcının açık isteği)
      * arayüzden "aynı cihaz" seçimi (same_as)
      * rastgele MAC'lerde aynı DHCP ya da mDNS adı; fabrika adı ("Galaxy-S24") değilse
    İkisi aynı ARP taramasında birlikte görülürse (tek telefon aynı anda iki ağda olamaz)
    ayrı cihazdır; bu "ayrı" çiftler state'te kalıcı tutulur ve ad yüzünden bir daha birleşmez.
    """
    up = {}

    def find(x):
        while up.get(x, x) != x:
            x = up[x]
        return x

    snaps = {nid: st.get("snapshot") or {} for nid, st in state.items() if nid.startswith("mac:")}
    keys = {}
    for nid, snap in snaps.items():
        conf_name = (cfg_dev.get(nid[4:]) or {}).get("name")
        if conf_name:
            keys.setdefault(("conf", conf_name.lower()), []).append(nid)
        if util.is_local_mac(nid[4:]):
            names = snap.get("names") or {}
            for k in ("dhcp_name", "mdns_name"):
                if names.get(k):
                    keys.setdefault(("name", names[k].lower()), []).append(nid)
    pairs, apart = [], []
    for (kind, name), g in keys.items():
        for i, a in enumerate(g):
            for b in g[i + 1:]:
                if kind == "conf":
                    pairs.append((a, b))
                elif is_generic_name(name) or b in (state[a].get("apart") or []):
                    continue
                elif now(a) and now(b):
                    apart.append((a, b))
                else:
                    pairs.append((a, b))
    pairs += [(nid, ov["same_as"]) for nid, ov in ov_dev.items() if nid in snaps and ov.get("same_as") in snaps]
    for a, b in pairs:
        up[find(a)] = find(b)
    groups = {}
    for nid in snaps:
        groups.setdefault(find(nid), []).append(nid)
    return [sorted(g) for g in groups.values() if len(g) > 1], apart


def age_min(received, now):
    t = util.parse_iso(received)
    return (now - t).total_seconds() / 60 if t else None


# ---------------------------------------------------------------- ana fonksiyon

def build(raw, cfg, settings, overrides, state, oui, now, extra=None):
    extra = extra or {}
    # Gruplar (sites.py): tek yerel ağ, router ajanı başına bir grup, Tailscale grupları
    allsites = extra.get("sites") or sitesmod.resolve(sitesmod.from_config(cfg)[0], ["router"])
    loc = next(x for x in allsites if x["type"] == "local")
    LID = loc["id"]
    routers = [x for x in allsites if x["type"] == "router"]
    groups = [x for x in allsites if x["type"] == "group"]
    default_grp = next((x for x in groups if x.get("default")), groups[-1] if groups else loc)
    window = settings.get("online_window_min", 15)
    forget_days = cfg.get("general", {}).get("forget_after_days", 14)
    site_of = {k.lower(): v for k, v in (settings["ts_site"] if "ts_site" in settings
                                          else sitesmod.from_config(cfg)[1]).items()}
    site_of = {k: v for k, v in site_of.items() if v in {x["id"] for x in allsites}}
    cfg_dev = {util.norm_mac(k): v for k, v in cfg.get("devices", {}).items() if util.norm_mac(k)}
    cfg_apps = cfg.get("apps", {})
    ov_dev, ov_apps = overrides.get("devices", {}), overrides.get("apps", {})
    casaos = raw.get("casaos") or {}
    problems = []

    def app_name(p):
        return (ov_apps.get(p, {}).get("name") or cfg_apps.get(p) or
                (casaos.get(p) or {}).get("title") or p)

    ov_sites = overrides.get("sites", {})
    sites = [{"id": x["id"], "name": x["name"], "type": x["type"]} for x in allsites]
    for st_ in sites:
        st_["auto_name"] = st_["name"]
        st_["name"] = (ov_sites.get(st_["id"]) or {}).get("name") or st_["name"]
    seen = {}       # id -> alanlar (bu turda kanıtı olan düğümler)

    # ------------------------------------------------ Tailscale
    ts = raw.get("ts")
    ts_nodes, ts_by_id, ts_by_ip, ts_self = {}, {}, {}, None
    if ts:
        me = ts.get("Self") or {}
        ts_self = ts_short(me)
        for node, is_self in [(me, True)] + [(p, False) for p in (ts.get("Peer") or {}).values()]:
            info = ts_info(node, is_self)
            ts_nodes[info["name"]] = info
            ts_by_id[node.get("ID")] = info["name"]
            if info["ip"]:
                ts_by_ip[info["ip"]] = info["name"]

    # ------------------------------------------------ yerel ağ (Pi'nin kendi ağı)
    route = raw.get("route") or {}
    iface = loc.get("interface") or route.get("dev") or "eth0"
    ifaces = raw.get("ifaces") or []
    self_macs = {i["mac"] for i in ifaces}
    subnet = loc.get("subnet")
    if not subnet:
        for i in ifaces:
            if i["ifname"] == iface:
                subnet = str(ipaddress.ip_network(f"{i['ip']}/{i['prefix']}", strict=False))
    gw_ip = loc.get("gateway_ip") or route.get("gateway")

    obs = {}

    def ob(mac):
        return obs.setdefault(mac, {"ips": {}, "vendor": None, "online": False,
                                    "via": set(), "names": {}, "live": set()})

    for e in raw.get("arp") or []:
        if e["mac"] in self_macs or (subnet and not util.in_net(e["ip"], subnet)):
            continue
        o = ob(e["mac"])
        o["ips"][e["ip"]] = util.iso(now)
        o["online"] = True
        o["live"].add(e["ip"])
        o["via"].add("arp")
        o["vendor"] = o["vendor"] or e.get("vendor")
    for e in raw.get("neigh") or []:
        if e["mac"] in self_macs or e.get("dev") not in (iface, "wlan0") \
                or (subnet and not util.in_net(e["ip"], subnet)):
            continue
        o = ob(e["mac"])
        o["ips"].setdefault(e["ip"], None)
        o["via"].add("neigh")
        if e.get("state") in ("REACHABLE", "DELAY", "PROBE"):
            o["online"] = True
            o["live"].add(e["ip"])
    for mac, rec in (raw.get("passive") or {}).items():
        if mac in self_macs:
            continue
        last = util.parse_iso(rec.get("last"))
        ips = {ip: t for ip, t in (rec.get("ips") or {}).items()
               if not subnet or util.in_net(ip, subnet)}
        if not ips:
            continue
        o = ob(mac)
        o["via"].add("passive")
        for ip, t in ips.items():
            o["ips"][ip] = max(filter(None, [o["ips"].get(ip), t]), default=None)
            pt = util.parse_iso(t)
            if pt and now - pt <= dt.timedelta(minutes=window):
                o["live"].add(ip)
        if last and now - last <= dt.timedelta(minutes=window):
            o["online"] = True
        o["passive_last"] = rec.get("last")
        for k in NAME_KEYS:
            if rec.get(k):
                o["names"][k] = rec[k]

    ipinfo = raw.get("passive_ip") or {}

    def bridge_type(mac, o):
        conf, ov = cfg_dev.get(mac, {}), ov_dev.get(f"mac:{mac}", {})
        return ov.get("type") or conf.get("type") or guess_type(o["vendor"] or util.vendor_for(mac, oui), mac)

    # ---- Aynı cihazın ikinci MAC'i (haritada iki kez görünmesin). ARP'de bir IP'ye yanıt veren
    # MAC, o IP'yi DHCP'den başka bir MAC'le almışsa:
    #   * ikiz MAC (twin_mac): extender'ın iki arayüzü (örn. 50:ff:.. / 52:ff:..)
    #   * aynı DHCP adı: hem kablolu hem Wi-Fi bağlı cihaz (LG TV); Linux iki IP'nin ARP'sine de
    #     tek kartla yanıt verir. Farklı adlı cihazlar extender (MAC-NAT) arkasıdır, aşağıda ayrılır.
    alias = {}
    for mac, o in obs.items():
        for ip in o["ips"]:
            real = (ipinfo.get(ip) or {}).get("real_mac")
            if (not real or real == mac or real not in obs or real in alias or mac in alias
                    or real in alias.values()):
                continue
            dn = o["names"].get("dhcp_name")
            if twin_mac(real, mac) or (dn and dn == obs[real]["names"].get("dhcp_name")
                                       and bridge_type(mac, o) != "ap"):
                alias[real] = mac
    for a, m in alias.items():
        o, src = obs[m], obs.pop(a)
        for ip, t in src["ips"].items():
            o["ips"][ip] = max(filter(None, [o["ips"].get(ip), t]), default=None)
        o["live"] |= src["live"]
        o["via"] |= src["via"]
        o["online"] = o["online"] or src["online"]
        o["vendor"] = o["vendor"] or src["vendor"]
        for k, v in src["names"].items():
            o["names"].setdefault(k, v)
        o.setdefault("aliases", []).append(a)
        state.pop(f"mac:{a}", None)

    # ---- MAC-NAT yapan extender'lar (örn. Keenetic tekrarlayıcı modu): arkasındaki cihazlar
    # extender'ın MAC'iyle görünür. Her IP'yi ayrı cihaza çevir; gerçek MAC'i DHCP'den
    # (pasif dinleme) biliniyorsa onu kullan, bilinmiyorsa IP'ye göre geçici bir cihaz yap.
    pseudo, retired = {}, set()
    # IP'nin son bilinen sahibi (geçmiş turlar): extender arkasına geçen cihazın kimliği kalsın
    hist = {ip: nid[4:] for nid, st in state.items() if nid.startswith("mac:") and nid[4:] not in obs
            and (st.get("snapshot") or {}).get("site") == LID
            for ip in (st.get("snapshot") or {}).get("ips") or []}
    bridges = [m for m, o in obs.items() if len(o["ips"]) >= 2 and bridge_type(m, o) == "ap"]
    owner = {ip: m for m, o in obs.items() if m not in bridges for ip in o["ips"]}
    for b in bridges:
        o = obs[b]
        mine = [ip for ip in o["ips"] if twin_mac((ipinfo.get(ip) or {}).get("real_mac") or "", b)]
        own = ov_dev.get(f"mac:{b}", {}).get("ip") or cfg_dev.get(b, {}).get("ip")
        if not own:
            own = max(mine, key=lambda ip: o["ips"][ip] or "", default=None)
        if own not in o["ips"]:
            own = min(o["ips"], key=util.ip_sort_key)
        for ip in [i for i in list(o["ips"]) if i != own]:
            t, live = o["ips"].pop(ip), ip in o["live"]
            o["live"].discard(ip)
            if ip in mine:       # extender'ın kendi eski IP'si
                retired.add(ip)
                continue
            info = ipinfo.get(ip) or {}
            real = owner.get(ip) or info.get("real_mac") or hist.get(ip)
            if real in (b, None) or real in self_macs or twin_mac(real, b):
                real = None
            if real:
                r = ob(real)
                r["ips"][ip] = max(filter(None, [r["ips"].get(ip), t]), default=None)
                if live:
                    r["online"] = True
                    r["live"].add(ip)
                r["via"].add("extender")
                r["bridge"] = b
                for k in NAME_KEYS:
                    if info.get(k) and not r["names"].get(k):
                        r["names"][k] = info[k]
            else:
                pseudo[ip] = {"t": t, "live": live, "bridge": b,
                              "names": {k: info[k] for k in NAME_KEYS if info.get(k)}}
        # Extender'ın topladığı adlar aslında arkasındakilerin olabilir: sadece kendi IP'sininkiler
        o["names"] = {k: v for k, v in (ipinfo.get(own) or {}).items() if k in NAME_KEYS}
    for ip, p in pseudo.items():
        seen[f"ip:{ip}"] = dict(
            ips=[ip], site=LID, parent_hint=f"mac:{p['bridge']}", online=p["live"],
            via=["extender"], names=p["names"], vendor=None,
            note="Extender (MAC-NAT) üzerinden bağlı; gerçek MAC adresi cihaz ağa yeniden "
                 "bağlandığında (DHCP) öğrenilir ve kalıcı kimliğe geçer.")

    # Aynı MAC'in en güncel IP'leri önce
    arp_by_ip = {e["ip"]: e["mac"] for e in raw.get("arp") or []}
    for mac, o in obs.items():
        vendor = o["vendor"] or util.vendor_for(mac, oui)
        ips = sorted(o["ips"], key=lambda ip: (o["ips"][ip] or ""), reverse=True)
        # Uzun süredir görülmeyen eski IP'leri at (DHCP değişince)
        recent = [ip for ip in ips if o["ips"][ip] and
                  now - util.parse_iso(o["ips"][ip]) < dt.timedelta(hours=24)]
        ips = recent or ips[:1]
        is_gw = gw_ip in o["ips"]
        seen[f"mac:{mac}"] = dict(
            mac=mac, vendor=vendor, ips=sorted(ips, key=util.ip_sort_key), site=LID,
            kind="modem" if is_gw else None,
            label=loc.get("modem_name") if is_gw else None,
            parent_hint=None if is_gw else (f"mac:{o['bridge']}" if o.get("bridge") else f"{LID}-gw"),
            is_root=is_gw, online=o["online"], via=sorted(o["via"]), names=o["names"],
            aliases=o.get("aliases"),
            now=any(arp_by_ip.get(ip) in (mac, o.get("bridge")) for ip in o["live"]))
    # Artık bir MAC'e bağlanan IP'lerin geçici (ip:) kayıtları kopya olarak kalmasın
    taken = retired | {ip for nid, kw in seen.items() if nid.startswith("mac:") for ip in kw["ips"]}
    for nid in [n for n in state if n.startswith("ip:") and n not in seen and n[3:] in taken]:
        del state[nid]

    ev1_failed = raw.get("arp") is None and raw.get("passive") is None
    if raw.get("arp") is None and settings["sources"].get("arp"):
        problems.append("Ev 1 ARP taraması yapılamadı.")

    # ------------------------------------------------ Pi (bu cihaz)
    containers = raw.get("docker")
    pi_services = docker_services(containers, app_name) + system_services(raw.get("host_ports"))
    seen["self"] = dict(
        label=loc.get("server_name") or raw.get("hostname") or "Nodesk", kind="server", site=LID,
        ips=[i["ip"] for i in ifaces], macs=sorted(self_macs),
        ifaces=[f"{i['ifname']} {i['ip']} {i['mac']}" for i in ifaces],
        tailscale=ts_nodes.get(ts_self), services=pi_services, parent_hint=f"{LID}-gw",
        online=True, via=["self"])

    # ------------------------------------------------ exit node bağları (Pi tarafı)
    reports = raw.get("reports") or {}
    # Exit node kullanımı: kullanan cihazın kendi seçimi ya da exit node'un bağlantı tablosu
    overlay = []
    ex_self = ((ts or {}).get("ExitNodeStatus") or {}).get("ID")
    if ex_self in ts_by_id:
        overlay.append({"from": "self", "to_ts": ts_by_id[ex_self]})

    def exit_clients(host, lines):
        for line in lines or []:
            ip = (line.split() or [""])[0]
            if ip in ts_by_ip:
                overlay.append({"from_ts": ts_by_ip[ip], "to": host})

    exit_clients("self", list(raw.get("exit_clients") or {}))

    # ------------------------------------------------ router grupları (her OpenWrt ajanı)
    heard = raw.get("passive_ev2") or {}

    def rnames(mac):
        return {k: v for k, v in (heard.get(mac) or {}).items() if k in NAME_KEYS and v}

    router_ids, router_fresh_of, modem_ip_of, router_script = {}, {}, {}, None
    for rs in routers:
        agent, SID = rs["agent"], rs["id"]
        rid = "router" if agent == "router" else f"router:{agent}"
        rep_ = reports.get(agent)
        age = age_min(rep_.get("received"), now) if rep_ else None
        sec = rep_.get("sections") if rep_ else None
        fresh = bool(sec) and age is not None and age <= ROUTER_FRESH_MIN
        router_fresh_of[SID] = fresh
        # router'ın Tailscale adı: ayarda yoksa raporundaki tailscale0 adresinden
        ts_name = rs.get("router_ts_name")
        for line in (sec or {}).get("ADDR", []):
            m = re.search(r"\d+:\s+(tailscale\S*)\s+inet\s+(\S+)/", line)
            if m and not ts_name:
                ts_name = ts_by_ip.get(m.group(2))
        router_ids[ts_name] = rid
        # modem: ayarda yoksa router'ın varsayılan rotasındaki geçit
        mip = rs.get("modem_ip")
        for line in (sec or {}).get("ROUTE", []):
            m = re.search(r"default via (\S+)", line)
            if m and not mip:
                mip = m.group(1)
        modem_ip_of[SID] = mip
        rts = ts_nodes.get(ts_name)
        kw = dict(label=rs.get("router_name") or ts_name or agent, kind="router", site=SID,
                  tailscale=rts, parent_hint=f"{SID}-gw", via=["tailscale"],
                  online=bool(rts and rts["online"]) or fresh,
                  agent={"name": agent, "received": rep_ and rep_.get("received"), "fresh": fresh})
        if sec and fresh and settings["sources"].get("router", True):
            ips = []
            for line in sec.get("ADDR", []):
                m = re.search(r"\d+:\s+(\S+)\s+inet\s+(\S+)/", line)
                if m and m.group(1) != "lo" and not m.group(1).startswith("tailscale"):
                    ips.append(m.group(2))
            kw["ips"] = ips
            kw["via"] = ["tailscale", "ajan"]
            for e in sources.parse_arpscan("\n".join(sec.get("ARPSCAN_WAN", []))):
                is_gw = e["ip"] == mip
                seen[f"mac:{e['mac']}"] = dict(
                    mac=e["mac"], vendor=e["vendor"] or util.vendor_for(e["mac"], oui),
                    ips=[e["ip"]], site=SID, kind="modem" if is_gw else None,
                    label=rs.get("modem_name") if is_gw else None,
                    parent_hint=None if is_gw else f"{SID}-gw", is_root=is_gw, online=True, now=True,
                    via=["router arp"], names=rnames(e["mac"]))
            lan = {}
            for line in sec.get("LEASES", []):
                p = line.split()
                if len(p) >= 4 and util.norm_mac(p[1]):
                    lan[util.norm_mac(p[1])] = {"ip": p[2], "hostname": None if p[3] == "*" else p[3],
                                                "reachable": False}
            for line in sec.get("NEIGH", []):
                m = re.match(r"(\S+) dev (\S+) lladdr (\S+) .*?(REACHABLE|STALE|DELAY|PROBE|PERMANENT)",
                             line)
                if not m or m.group(2) != rs.get("lan_dev", "br-lan"):
                    continue
                mac = util.norm_mac(m.group(3))
                if mac:
                    d = lan.setdefault(mac, {"ip": m.group(1), "hostname": None})
                    d["reachable"] = True
            for mac, d in lan.items():
                names = {**rnames(mac), **({"dhcp_name": d["hostname"]} if d["hostname"] else {})}
                seen[f"mac:{mac}"] = dict(
                    mac=mac, vendor=util.vendor_for(mac, oui), ips=[d["ip"]], site=SID,
                    parent_hint=rid, online=bool(d.get("reachable")), now=bool(d.get("reachable")),
                    names=names,
                    via=["router dhcp"] + (["router arp"] if d.get("reachable") else []),
                    note=None if d.get("reachable") else
                    "DHCP kirası var ama şu an router'ın ARP tablosunda yok")
            if sec.get("LISTEN") is not None:
                kw["services"] = system_services(parse_proc_listen(sec.get("LISTEN")))
            ex = ((sec.get("EXITNODE") or [""])[0] or "").strip()
            if ex and ex in ts_by_id:
                overlay.append({"from": rid, "to_ts": ts_by_id[ex]})
            exit_clients(rid, sec.get("EXITCLIENTS"))
        seen[rid] = kw
        if settings["sources"].get("router", True):
            if not rep_ or not rep_.get("received"):
                problems.append(f"{rs['name']}: router ajanı ({agent}) henüz rapor göndermedi. "
                                "Kurulum komutu: Ayarlar > Ajanlar.")
            elif not fresh:
                problems.append(f"{rs['name']}: router ajanının son raporu {round(age)} dakika önce geldi; "
                                "son bilinen durumuyla gösteriliyor.")
        if router_script is None:
            installed = ((sec or {}).get("VERSION") or [None])[0] if sec else None
            router_script = {"expected": extra.get("topo_expected"), "installed": installed,
                             "ok": None if installed is None else installed == extra.get("topo_expected"),
                             # 3 ve sonrası kendini günceller; daha eskisinin bir kez elle güncellenmesi gerekir
                             "self_update": (installed or "0").isdigit() and int(installed or 0) >= 3}
    router_script = router_script or {"expected": extra.get("topo_expected"), "installed": None,
                                      "ok": None, "self_update": False}

    # ------------------------------------------------ Tailscale düğümleri
    lan_by_ip = {}
    for nid, kw in seen.items():
        if (nid.startswith("mac:") or nid.startswith("ip:")) and kw.get("online") and not kw.get("is_root"):
            for ip in kw.get("ips") or []:
                lan_by_ip.setdefault(ip, nid)
    for name, info in ts_nodes.items():
        if name == ts_self or name in router_ids:
            continue
        site = site_of.get(name, default_grp["id"])
        grp = next((x for x in allsites if x["id"] == site), default_grp)
        kind = ("cloud-vm" if grp.get("kind") == "cloud" else
                "laptop" if info.get("os") in ("linux", "windows", "macOS") else "phone")
        lan_id = next((lan_by_ip[a] for a in info.get("addrs") or [] if a in lan_by_ip), None)
        if info["online"] and lan_id and lan_id in seen and site == default_grp["id"]:
            # Tailscale'in bildirdiği yerel IP şu an evlerimizden birinde canlı: cihaz evde.
            # Aynı cihaz iki kez görünmesin: yerel kaydı tailnet cihazıyla birleştir.
            lan = seen.pop(lan_id)
            state.pop(lan_id, None)
            seen[f"ts:{name}"] = {**lan, "label": name, "kind": kind, "tailscale": info,
                                  "ips": (lan.get("ips") or []) + ([info["ip"]] if info.get("ip") else []),
                                  "via": sorted(set(lan.get("via") or []) | {"tailscale"}),
                                  "online": True, "roam": lan_id, "is_root": False}
            continue
        seen[f"ts:{name}"] = dict(
            label=name, site=site, ips=[info["ip"]] if info.get("ip") else [], kind=kind,
            tailscale=info, parent_hint=f"{site}-gw", online=info["online"], via=["tailscale"])

    # ------------------------------------------------ diğer ajanlar (sunucular)
    agents_out = []
    for name, rep in reports.items():
        a = age_min(rep.get("received"), now)
        fresh = a is not None and a <= (ROUTER_FRESH_MIN if rep["kind"] == "router" else AGENT_FRESH_MIN)
        usage = dict(x.split("=", 1) for x in (rep.get("sections") or {}).get("SELF", []) if "=" in x)
        entry = {"name": name, "kind": rep["kind"], "received": rep.get("received"),
                 "age_min": round(a, 1) if a is not None else None, "fresh": fresh,
                 "from": rep.get("from"), "node": None,
                 "usage": {k: int(v) for k, v in usage.items() if v.strip().isdigit()} or None}
        agents_out.append(entry)
        if rep["kind"] != "linux" or not rep.get("sections") or not settings["sources"].get("agents", True):
            continue
        sec = rep["sections"]
        host = [x.strip() for x in sec.get("HOST", []) if x.strip()]
        ts_ip = next((x for x in host if x.startswith("100.")), None)
        tsn = ts_by_ip.get(ts_ip) if ts_ip else None
        nid = ("self" if tsn == ts_self else router_ids[tsn] if tsn in router_ids
               else f"ts:{tsn}" if tsn else None)
        if nid is None:
            hn = (host[0] if host else name).lower()
            nid = f"ts:{hn}" if f"ts:{hn}" in seen else None
        if nid is None or nid not in seen:
            continue
        entry["node"] = nid
        dock = sources.parse_docker_ps_json(sec.get("DOCKER", []))
        skip = {p for c in dock if c["host_network"] for p in c["ports"]}
        svcs = docker_services(dock, app_name) + system_services(
            sources.parse_ss("\n".join(sec.get("PORTS", [])), skip))
        if fresh:
            seen[nid]["services"] = (seen[nid].get("services") or []) + svcs
        seen[nid]["agent"] = {"name": name, "received": rep.get("received"), "fresh": fresh}
        if fresh:
            ex = ((sec.get("EXITNODE") or [""])[0] or "").strip()
            if ex in ts_by_id:
                overlay.append({"from": nid, "to_ts": ts_by_id[ex]})
            exit_clients(nid, sec.get("EXITCLIENTS"))
        if not fresh:
            problems.append(f"{name} ajanının son raporu {round(a)} dakika önce geldi.")

    # ------------------------------------------------ geçmiş (son görülme)
    now_s = util.iso(now)
    for nid, kw in seen.items():
        st = state.setdefault(nid, {"first_seen": now_s})
        if kw.get("online"):
            st["last_seen"] = now_s
        snap = {k: v for k, v in kw.items() if k not in ("online", "now")}
        old = st.get("snapshot") or {}
        # Bu turda hizmet listesi gelmediyse (örn. ajan raporu eskidi) eskisini koru
        if not snap.get("services") and old.get("services") and nid != "self":
            snap["services"] = old["services"]
        st["snapshot"] = snap
    cutoff = now - dt.timedelta(days=forget_days)
    for nid in list(state):
        st = state[nid]
        last = util.parse_iso(st.get("last_seen") or st.get("first_seen"))
        if nid not in seen and (not last or last < cutoff or
                                (nid.startswith("ip:") and now - last > dt.timedelta(hours=24))):
            del state[nid]

    # ------------------------------------------------ düğümler
    sites_present = {LID} | {x["id"] for x in routers} | {st["snapshot"].get("site") for st in state.values()}
    roots = {}
    for nid, st in state.items():
        snap = st["snapshot"]
        if snap.get("is_root"):
            roots[f"{snap['site']}-gw"] = nid
    nodes = {"internet": {"id": "internet", "label": "İnternet", "kind": "internet", "site": None,
                          "parent": None, "online": True, "ips": [], "services": []}}
    placeholders = {f"{LID}-gw": dict(label=loc.get("modem_name") or "Modem", kind="modem", site=LID,
                                      ips=[gw_ip] if gw_ip else [])}
    for rs in routers:
        mip = modem_ip_of.get(rs["id"])
        placeholders[f"{rs['id']}-gw"] = dict(label=rs.get("modem_name") or "Modem", kind="modem",
                                              site=rs["id"], ips=[mip] if mip else [])
    for g in groups:
        placeholders[f"{g['id']}-gw"] = dict(
            label=g.get("root_name") or g["name"], kind="roam" if g.get("default") else "cloud",
            site=g["id"], ips=[])
    for gw, kw in placeholders.items():
        if gw[:-3] in sites_present and gw not in roots:
            roots[gw] = gw
            ovg = ov_dev.get(gw, {})
            nodes[gw] = {"id": gw, "parent": "internet", "online": True, "services": [],
                         "placeholder": True, **kw, "auto_label": kw["label"],
                         "override": ovg or None, "edited": bool(ovg)}
            if ovg.get("name"):
                nodes[gw]["label"] = ovg["name"]

    # Aynı cihazın MAC'leri tek düğüm: kimlik (id, düzenlemeler) sabit, adres/konum en güncelinden
    def online_now(nid):
        return bool(seen.get(nid, {}).get("online"))

    groups, apart = same_device_groups(state, lambda n: bool(seen.get(n, {}).get("now")), cfg_dev, ov_dev)
    for a, b in apart:
        for x, y in ((a, b), (b, a)):
            state[x]["apart"] = sorted(set(state[x].get("apart") or []) | {y})
    merged, skip = {}, set()
    for g in groups:
        canon = min(g, key=lambda n: (n not in ov_dev and n[4:] not in cfg_dev, state[n].get("first_seen") or ""))
        live = max(g, key=lambda n: (online_now(n), state[n].get("last_seen") or ""))
        snap = dict(state[live]["snapshot"])
        snap["names"] = dict(snap.get("names") or {})
        for n in g:
            for k, v in (state[n]["snapshot"].get("names") or {}).items():
                snap["names"].setdefault(k, v)
        snap["aliases"] = sorted({m for n in g for m in [n[4:]] + (state[n]["snapshot"].get("aliases") or [])}
                                 - {snap.get("mac")})
        merged[canon] = {"snapshot": snap, "online": online_now(live), "live": live,
                         "first_seen": min(state[n].get("first_seen") or "~" for n in g),
                         "last_seen": max(state[n].get("last_seen") or "" for n in g) or None}
        skip |= set(g) - {canon}

    for nid, st in state.items():
        if nid in skip:
            continue
        st = merged.get(nid, st)
        snap = dict(st["snapshot"])
        mac = snap.get("mac")
        own = [nid[4:]] if nid.startswith("mac:") else []
        conf = cfg.get("devices", {}).get("self", {}) if nid == "self" else \
            ({} if snap.get("roam") else next(
                (cfg_dev[a] for a in own + [mac] + (snap.get("aliases") or []) if a in cfg_dev), {}))
        ov = ov_dev.get(nid, {})
        names = snap.pop("names", None) or {}
        hint = snap.pop("parent_hint", None)
        parent = "internet" if snap.get("is_root") else roots.get(hint, hint)
        pconf = ov.get("parent") or conf.get("parent")
        if pconf:
            pm = util.norm_mac(pconf)
            parent = f"mac:{pm}" if pm else pconf
        label = (ov.get("name") or conf.get("name") or snap.get("label") or best_name(names)
                 or fallback_label(snap.get("vendor"), mac, (snap.get("ips") or [None])[0], names))
        kind = ov.get("type") or conf.get("type") or snap.get("kind") \
            or guess_type(snap.get("vendor"), mac, names)
        services = list(snap.pop("services", None) or [])
        for i, s in enumerate(ov.get("services") or []):
            services.append({"id": f"manual:{i}", "name": s["name"],
                             "ports": [int(s["port"])] if s.get("port") else [],
                             "url": s.get("url"), "source": "manual", "app": "_manual",
                             "app_name": "Elle eklenen", "state": "running"})
        for s in services:
            if s.get("app") and ov_apps.get(s["app"], {}).get("hidden"):
                s["hidden"] = True
        for k in ("label", "kind", "is_root"):
            snap.pop(k, None)
        online = st["online"] if nid in merged else online_now(nid)
        site = snap.get("site")
        nodes[nid] = {
            **snap, "id": nid, "label": label, "kind": kind, "parent": parent, "online": online,
            "names": names, "services": services,
            "first_seen": st.get("first_seen"), "last_seen": st.get("last_seen"),
            "random_mac": util.is_local_mac(mac) if mac else None,
            "short_vendor": util.short_vendor(snap.get("vendor")),
            "stale": st.get("live", nid) not in seen and ((site == LID and ev1_failed) or
                                                          router_fresh_of.get(site) is False),
            "tags": ov.get("tags") or conf.get("tags") or [], "note": ov.get("note") or snap.get("note"),
            "hidden": bool(ov.get("hidden")), "edited": bool(ov), "override": ov or None,
            "auto_label": (conf.get("name") or snap.get("label") or best_name(names) or
                           fallback_label(snap.get("vendor"), mac, (snap.get("ips") or [None])[0], names)),
            "auto_kind": conf.get("type") or snap.get("kind") or guess_type(snap.get("vendor"), mac, names),
            "os": os_guess(names),
            # adı yalnızca tahmin (üretici/işletim sistemi/IP): kullanıcıya "adlandır" diye gösterilir
            "unnamed": bool(mac) and not (ov.get("name") or conf.get("name") or snap.get("label")
                                           or best_name(names)),
        }

    # Öneri (onay kullanıcıda): rastgele MAC'li bir cihaz kaybolduktan hemen sonra aynı türde yeni
    # biri geldiyse büyük ihtimalle aynı telefon başka Wi-Fi ağına geçmiştir
    near = dt.timedelta(minutes=window + 30)
    for n in nodes.values():
        if not (n.get("random_mac") and n["online"] and n.get("first_seen")):
            continue
        t0 = util.parse_iso(n["first_seen"])
        cands = [o for o in nodes.values() if o is not n and o.get("random_mac") and not o["online"]
                 and o.get("site") == n.get("site") and o["kind"] == n["kind"] and o.get("last_seen")
                 and (o.get("first_seen") or "") < n["first_seen"]
                 and abs(util.parse_iso(o["last_seen"]) - t0) <= near
                 and o["id"] != (n.get("override") or {}).get("not_same")]
        if len(cands) == 1:
            n["same_hint"] = {"id": cands[0]["id"], "label": cands[0]["label"]}

    # Geçersiz ya da döngü oluşturan ebeveynleri düzelt
    for n in nodes.values():
        if n["id"] == "internet":
            continue
        root = roots.get(f"{n.get('site')}-gw", "internet")
        if n.get("parent") not in nodes or n.get("parent") == n["id"]:
            n["parent"] = root if root != n["id"] else "internet"
    # Döngüde elle düzenlenmiş düğümün bağı koparılsın (diğerleri yerinde kalsın)
    for n in sorted(nodes.values(), key=lambda x: not x.get("edited")):
        cur, hops = n.get("parent"), 0
        while cur and cur != "internet" and hops < 60:
            if cur == n["id"]:
                root = roots.get(f"{n.get('site')}-gw", "internet")
                n["parent"] = root if root != n["id"] else "internet"
                break
            cur, hops = nodes.get(cur, {}).get("parent"), hops + 1

    svc_nodes, icon_wanted = service_nodes(nodes, ov_dev, ov_apps, casaos, raw.get("health") or {},
                                           extra.get("icon_files") or {})
    nodes.update(svc_nodes)

    ts_to_node = {n["tailscale"]["name"]: n["id"] for n in nodes.values() if n.get("tailscale")}
    links = {(o.get("from") or ts_to_node.get(o.get("from_ts")), o.get("to") or ts_to_node.get(o.get("to_ts")))
             for o in overlay}
    overlay = [{"from": a, "to": b, "kind": "exit"} for a, b in sorted(links)
               if a in nodes and b in nodes and a != b]

    for a in agents_out:
        if a["kind"] == "router":
            a["node"] = "router" if a["name"] == "router" else f"router:{a['name']}"

    for o in overlay:   # kartlarda ve panelde gösterilsin
        nodes[o["from"]]["exit_via"] = o["to"]
        nodes[o["to"]].setdefault("exit_users", []).append(o["from"])

    data = {
        "generated": now_s,
        "sites": [s for s in sites if s["id"] in sites_present],
        "nodes": sorted(nodes.values(), key=lambda n: (n.get("site") or "", util.ip_sort_key(
            (n.get("ips") or ["0.0.0.0"])[0]))),
        "overlay": overlay,
        "errors": problems,
        "agents": sorted(agents_out, key=lambda a: a["name"]),
        "router_script": router_script,
        "icon_wanted": icon_wanted,
        "baseline": min((st.get("first_seen") for st in state.values() if st.get("first_seen")),
                        default=now_s),
    }
    return data, state
