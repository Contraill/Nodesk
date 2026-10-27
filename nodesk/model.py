"""Ham kaynak verilerini haritaya (data.json) dönüştürür.

build() saf bir fonksiyondur: ağ/disk erişimi yapmaz. Böylece arayüzden yapılan bir
ad değişikliği tarama beklemeden, son ham veriden yeniden hesaplanabilir.
"""

import datetime as dt
import ipaddress
import re

from . import sources, util

ROUTER_FRESH_MIN = 15      # router ajanı 5 dakikada bir rapor verir
AGENT_FRESH_MIN = 20

TYPE_RULES = [
    (r"roborock|rockrobo|roomba|dreame|vacuum", "vacuum"),
    (r"yeelink|yeelight|\bhue\b|lamp|bulb|\blight\b", "lamp"),
    (r"imilab|camera|ipcam|ezviz|hikvision|dahua|reolink|_rtsp", "camera"),
    (r"_googlecast|webos|tizen|bravia|smart-?tv|androidtv|android tv|chromecast|lgwebos|"
     r"vestel|roku|fire ?tv|\btv\b", "tv"),
    (r"_ipp|_printer|_pdl-datastream|printer|epson|brother|canon", "printer"),
    (r"playstation|xbox|nintendo", "console"),
    (r"ipad|galaxy tab|tablet", "tablet"),
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


def guess_type(vendor, mac, names=None):
    names = names or {}
    text = " ".join(str(x) for x in [
        vendor or "", names.get("dhcp_name", ""), names.get("mdns_name", ""),
        names.get("friendly", ""), names.get("model", ""), names.get("ssdp_server", ""),
        names.get("dhcp_vendor", ""), " ".join(names.get("mdns_services", []))]).lower()
    for pat, kind in TYPE_RULES:
        if re.search(pat, text):
            return kind
    if not vendor and util.is_local_mac(mac):
        return "phone"   # rastgele MAC: büyük ihtimalle telefon/tablet
    return "device"


def best_name(names):
    for k in ("friendly", "dhcp_name", "mdns_name"):
        v = names.get(k)
        if v and v.lower() not in ("localhost", "android", "*"):
            return v
    inst = names.get("mdns_instances") or []
    return inst[0] if inst else None


def fallback_label(vendor, mac, ip):
    tail = f" (.{ip.rsplit('.', 1)[-1]})" if ip and "." in ip else ""
    sv = util.short_vendor(vendor)
    if sv:
        return sv + tail
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
    if is_self:
        path = "bu cihaz"
    elif node.get("CurAddr"):
        path = "doğrudan"
    elif node.get("Relay"):
        path = f"aktarıcı ({node['Relay']})"
    else:
        path = "bağlantı yok"
    return {"name": ts_short(node), "ip": v4, "os": node.get("OS"),
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


def age_min(received, now):
    t = util.parse_iso(received)
    return (now - t).total_seconds() / 60 if t else None


# ---------------------------------------------------------------- ana fonksiyon

def build(raw, cfg, settings, overrides, state, oui, now, extra=None):
    extra = extra or {}
    ev1, ev2 = cfg.get("ev1", {}), cfg.get("ev2", {})
    window = settings.get("online_window_min", 15)
    forget_days = cfg.get("general", {}).get("forget_after_days", 14)
    site_of = {k.lower(): v for k, v in cfg.get("tailscale", {}).get("site_of", {}).items()}
    cfg_dev = {util.norm_mac(k): v for k, v in cfg.get("devices", {}).items() if util.norm_mac(k)}
    cfg_apps = cfg.get("apps", {})
    ov_dev, ov_apps = overrides.get("devices", {}), overrides.get("apps", {})
    casaos = raw.get("casaos") or {}
    problems = []

    def app_name(p):
        return (ov_apps.get(p, {}).get("name") or cfg_apps.get(p) or casaos.get(p) or p)

    sites = [
        {"id": "ev1", "name": ev1.get("name", "Ev 1")},
        {"id": "ev2", "name": ev2.get("name", "Ev 2")},
        {"id": "oracle", "name": cfg.get("oracle", {}).get("name", "Oracle Cloud")},
        {"id": "mobile", "name": cfg.get("mobile", {}).get("name", "Uzak / Mobil")},
    ]
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

    # ------------------------------------------------ Ev 1
    iface = ev1.get("interface", "eth0")
    ifaces = raw.get("ifaces") or []
    self_macs = {i["mac"] for i in ifaces}
    subnet = ev1.get("subnet")
    if not subnet:
        for i in ifaces:
            if i["ifname"] == iface:
                subnet = str(ipaddress.ip_network(f"{i['ip']}/{i['prefix']}", strict=False))
    gw_ip = ev1.get("gateway_ip", "192.168.44.1")

    obs = {}

    def ob(mac):
        return obs.setdefault(mac, {"ips": {}, "vendor": None, "online": False,
                                    "via": set(), "names": {}})

    for e in raw.get("arp") or []:
        if e["mac"] in self_macs or (subnet and not util.in_net(e["ip"], subnet)):
            continue
        o = ob(e["mac"])
        o["ips"][e["ip"]] = util.iso(now)
        o["online"] = True
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
        if last and now - last <= dt.timedelta(minutes=window):
            o["online"] = True
        o["passive_last"] = rec.get("last")
        for k in ("dhcp_name", "dhcp_vendor", "mdns_name", "friendly", "model", "ssdp_server",
                  "mdns_services", "mdns_instances"):
            if rec.get(k):
                o["names"][k] = rec[k]

    # Aynı MAC'in en güncel IP'leri önce
    for mac, o in obs.items():
        vendor = o["vendor"] or util.vendor_for(mac, oui)
        ips = sorted(o["ips"], key=lambda ip: (o["ips"][ip] or ""), reverse=True)
        # Uzun süredir görülmeyen eski IP'leri at (DHCP değişince)
        recent = [ip for ip in ips if o["ips"][ip] and
                  now - util.parse_iso(o["ips"][ip]) < dt.timedelta(hours=24)]
        ips = recent or ips[:1]
        is_gw = gw_ip in o["ips"]
        seen[f"mac:{mac}"] = dict(
            mac=mac, vendor=vendor, ips=sorted(ips, key=util.ip_sort_key), site="ev1",
            kind="modem" if is_gw else None,
            label=ev1.get("modem_name") if is_gw else None,
            parent_hint=None if is_gw else "ev1-gw", is_root=is_gw,
            online=o["online"], via=sorted(o["via"]), names=o["names"])

    ev1_failed = raw.get("arp") is None and raw.get("passive") is None
    if raw.get("arp") is None and settings["sources"].get("arp"):
        problems.append("Ev 1 ARP taraması yapılamadı.")

    # ------------------------------------------------ Pi (bu cihaz)
    containers = raw.get("docker")
    pi_services = docker_services(containers, app_name) + system_services(raw.get("host_ports"))
    seen["self"] = dict(
        label=ev1.get("server_name", "home-pi"), kind="server", site="ev1",
        ips=[i["ip"] for i in ifaces], macs=sorted(self_macs),
        ifaces=[f"{i['ifname']} {i['ip']} {i['mac']}" for i in ifaces],
        tailscale=ts_nodes.get(ts_self), services=pi_services, parent_hint="ev1-gw",
        online=True, via=["self"])

    # ------------------------------------------------ Ev 2 (router ajanı)
    reports = raw.get("reports") or {}
    router_rep = reports.get("router")
    router_age = age_min(router_rep.get("received"), now) if router_rep else None
    router_sec = router_rep.get("sections") if router_rep else None
    router_fresh = bool(router_sec) and router_age is not None and router_age <= ROUTER_FRESH_MIN
    router_ts_name = ev2.get("router_ts_name", "home-router")
    router_ts = ts_nodes.get(router_ts_name)
    modem2_ip = ev2.get("modem_ip", "192.168.1.1")
    overlay = []
    router_kw = dict(label=ev2.get("router_name", "home-router"), kind="router", site="ev2",
                     tailscale=router_ts, parent_hint="ev2-gw", via=["tailscale"],
                     online=bool(router_ts and router_ts["online"]) or router_fresh,
                     agent={"name": "router", "received": router_rep and router_rep.get("received"),
                            "fresh": router_fresh})
    if router_sec and router_fresh and settings["sources"].get("router", True):
        ips = []
        for line in router_sec.get("ADDR", []):
            m = re.search(r"\d+:\s+(\S+)\s+inet\s+(\S+)/", line)
            if m and m.group(1) != "lo" and not m.group(1).startswith("tailscale"):
                ips.append(m.group(2))
        router_kw["ips"] = ips
        router_kw["via"] = ["tailscale", "ajan"]
        for e in sources.parse_arpscan("\n".join(router_sec.get("ARPSCAN_WAN", []))):
            is_gw = e["ip"] == modem2_ip
            seen[f"mac:{e['mac']}"] = dict(
                mac=e["mac"], vendor=e["vendor"] or util.vendor_for(e["mac"], oui),
                ips=[e["ip"]], site="ev2", kind="modem" if is_gw else None,
                label=ev2.get("modem_name") if is_gw else None,
                parent_hint=None if is_gw else "ev2-gw", is_root=is_gw, online=True,
                via=["router arp"])
        lan = {}
        for line in router_sec.get("LEASES", []):
            p = line.split()
            if len(p) >= 4 and util.norm_mac(p[1]):
                lan[util.norm_mac(p[1])] = {"ip": p[2], "hostname": None if p[3] == "*" else p[3],
                                            "reachable": False}
        for line in router_sec.get("NEIGH", []):
            m = re.match(r"(\S+) dev (\S+) lladdr (\S+) .*?(REACHABLE|STALE|DELAY|PROBE|PERMANENT)",
                         line)
            if not m or m.group(2) != ev2.get("lan_dev", "br-lan"):
                continue
            mac = util.norm_mac(m.group(3))
            if mac:
                d = lan.setdefault(mac, {"ip": m.group(1), "hostname": None})
                d["reachable"] = True
        for mac, d in lan.items():
            names = {"dhcp_name": d["hostname"]} if d["hostname"] else {}
            seen[f"mac:{mac}"] = dict(
                mac=mac, vendor=util.vendor_for(mac, oui), ips=[d["ip"]], site="ev2",
                parent_hint="router", online=bool(d.get("reachable")), names=names,
                via=["router dhcp"] + (["router arp"] if d.get("reachable") else []),
                note=None if d.get("reachable") else
                "DHCP kirası var ama şu an router'ın ARP tablosunda yok")
        ex = ((router_sec.get("EXITNODE") or [""])[0] or "").strip()
        if ex and ex in ts_by_id:
            overlay.append({"from": "router", "to_ts": ts_by_id[ex], "kind": "exit"})
    seen["router"] = router_kw
    if settings["sources"].get("router", True):
        if not router_rep or not router_rep.get("received"):
            problems.append("Router ajanı henüz rapor göndermedi. Laptop'tan: "
                            "ssh pi@100.64.0.1 sudo nodesk router-script | "
                            "ssh root@100.64.0.2 sh")
        elif not router_fresh:
            problems.append(f"Router ajanının son raporu {round(router_age)} dakika önce geldi; "
                            "Ev 2 son bilinen durumuyla gösteriliyor.")
    router_script = {
        "expected": extra.get("topo_expected"),
        "installed": ((router_sec or {}).get("VERSION") or [None])[0] if router_sec else None,
    }
    router_script["ok"] = (None if router_script["installed"] is None
                           else router_script["installed"] == router_script["expected"])

    # ------------------------------------------------ Tailscale düğümleri
    for name, info in ts_nodes.items():
        if name in (ts_self, router_ts_name):
            continue
        site = site_of.get(name, "mobile")
        seen[f"ts:{name}"] = dict(
            label=name, site=site, ips=[info["ip"]] if info.get("ip") else [],
            kind="cloud-vm" if site == "oracle" else
            ("laptop" if info.get("os") in ("linux", "windows", "macOS") else "phone"),
            tailscale=info, parent_hint=f"{site}-gw", online=info["online"], via=["tailscale"])

    # ------------------------------------------------ diğer ajanlar (sunucular)
    agents_out = []
    for name, rep in reports.items():
        a = age_min(rep.get("received"), now)
        fresh = a is not None and a <= (ROUTER_FRESH_MIN if rep["kind"] == "router" else AGENT_FRESH_MIN)
        entry = {"name": name, "kind": rep["kind"], "received": rep.get("received"),
                 "age_min": round(a, 1) if a is not None else None, "fresh": fresh,
                 "from": rep.get("from"), "node": None}
        agents_out.append(entry)
        if rep["kind"] != "linux" or not rep.get("sections") or not settings["sources"].get("agents", True):
            continue
        sec = rep["sections"]
        host = [x.strip() for x in sec.get("HOST", []) if x.strip()]
        ts_ip = next((x for x in host if x.startswith("100.")), None)
        tsn = ts_by_ip.get(ts_ip) if ts_ip else None
        nid = ("self" if tsn == ts_self else "router" if tsn == router_ts_name
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
        if not fresh:
            problems.append(f"{name} ajanının son raporu {round(a)} dakika önce geldi.")

    # ------------------------------------------------ geçmiş (son görülme)
    now_s = util.iso(now)
    for nid, kw in seen.items():
        st = state.setdefault(nid, {"first_seen": now_s})
        if kw.get("online"):
            st["last_seen"] = now_s
        snap = {k: v for k, v in kw.items() if k != "online"}
        old = st.get("snapshot") or {}
        # Bu turda hizmet listesi gelmediyse (örn. ajan raporu eskidi) eskisini koru
        if not snap.get("services") and old.get("services") and nid != "self":
            snap["services"] = old["services"]
        st["snapshot"] = snap
    cutoff = now - dt.timedelta(days=forget_days)
    for nid in list(state):
        st = state[nid]
        last = util.parse_iso(st.get("last_seen") or st.get("first_seen"))
        if nid not in seen and (not last or last < cutoff):
            del state[nid]

    # ------------------------------------------------ düğümler
    sites_present = {"ev1", "ev2"} | {st["snapshot"].get("site") for st in state.values()}
    roots = {}
    for nid, st in state.items():
        snap = st["snapshot"]
        if snap.get("is_root"):
            roots[f"{snap['site']}-gw"] = nid
    nodes = {"internet": {"id": "internet", "label": "İnternet", "kind": "internet", "site": None,
                          "parent": None, "online": True, "ips": [], "services": []}}
    placeholders = {
        "ev1-gw": dict(label=ev1.get("modem_name", "Ev 1 modem"), kind="modem", site="ev1", ips=[gw_ip]),
        "ev2-gw": dict(label=ev2.get("modem_name", "Ev 2 modem"), kind="modem", site="ev2",
                       ips=[modem2_ip]),
        "oracle-gw": dict(label=cfg.get("oracle", {}).get("name", "Oracle Cloud"), kind="cloud",
                          site="oracle", ips=[]),
        "mobile-gw": dict(label=cfg.get("mobile", {}).get("root_name", "Gezgin cihazlar"),
                          kind="roam", site="mobile", ips=[]),
    }
    for gw, kw in placeholders.items():
        if gw.split("-")[0] in sites_present and gw not in roots:
            roots[gw] = gw
            nodes[gw] = {"id": gw, "parent": "internet", "online": True, "services": [],
                         "placeholder": True, **kw}

    for nid, st in state.items():
        snap = dict(st["snapshot"])
        mac = snap.get("mac")
        conf = cfg.get("devices", {}).get("self", {}) if nid == "self" else (cfg_dev.get(mac, {}) if mac else {})
        ov = ov_dev.get(nid, {})
        names = snap.pop("names", None) or {}
        hint = snap.pop("parent_hint", None)
        parent = "internet" if snap.get("is_root") else roots.get(hint, hint)
        pconf = ov.get("parent") or conf.get("parent")
        if pconf:
            pm = util.norm_mac(pconf)
            parent = f"mac:{pm}" if pm else pconf
        label = (ov.get("name") or conf.get("name") or snap.get("label") or best_name(names)
                 or fallback_label(snap.get("vendor"), mac, (snap.get("ips") or [None])[0]))
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
        online = bool(seen.get(nid, {}).get("online"))
        site = snap.get("site")
        nodes[nid] = {
            **snap, "id": nid, "label": label, "kind": kind, "parent": parent, "online": online,
            "names": names, "services": services,
            "first_seen": st.get("first_seen"), "last_seen": st.get("last_seen"),
            "random_mac": util.is_local_mac(mac) if mac else None,
            "short_vendor": util.short_vendor(snap.get("vendor")),
            "stale": nid not in seen and ((site == "ev1" and ev1_failed) or
                                          (site == "ev2" and not router_fresh)),
            "tags": ov.get("tags") or conf.get("tags") or [], "note": ov.get("note") or snap.get("note"),
            "hidden": bool(ov.get("hidden")), "edited": bool(ov), "override": ov or None,
            "auto_label": (conf.get("name") or snap.get("label") or best_name(names) or
                           fallback_label(snap.get("vendor"), mac, (snap.get("ips") or [None])[0])),
            "auto_kind": conf.get("type") or snap.get("kind") or guess_type(snap.get("vendor"), mac, names),
        }

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

    ts_to_node = {n["tailscale"]["name"]: n["id"] for n in nodes.values() if n.get("tailscale")}
    overlay = [{"from": o["from"], "to": ts_to_node[o["to_ts"]], "kind": o["kind"]}
               for o in overlay if o["to_ts"] in ts_to_node]

    for a in agents_out:
        if a["name"] == "router":
            a["node"] = "router"

    data = {
        "generated": now_s,
        "sites": [s for s in sites if s["id"] in sites_present],
        "nodes": sorted(nodes.values(), key=lambda n: (n.get("site") or "", util.ip_sort_key(
            (n.get("ips") or ["0.0.0.0"])[0]))),
        "overlay": overlay,
        "errors": problems,
        "agents": sorted(agents_out, key=lambda a: a["name"]),
        "router_script": router_script,
    }
    return data, state
