"""Builds data.json for the GitHub Pages demo: a made-up network, not taken from any real one.

    python3 demo/make_demo.py <out/live/data.json>
"""

import datetime as dt
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICON = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/{}.png"
rng = random.Random(7)
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
iso = lambda t: t.isoformat()


def history(kind):
    """7 days of 10-minute slots (most significant bit = 00:00 UTC)."""
    days, on = {}, 0
    for d in range(6, -1, -1):
        day = (now - dt.timedelta(days=d)).date()
        bits = 0
        for i in range(144):
            h = i / 6
            up = {"always": rng.random() > 0.002,
                  "day": 7 <= h < 23.5 and rng.random() > 0.05,
                  "evening": (18 <= h < 23 or (d in (1, 2) and 10 <= h < 16)) and rng.random() > 0.03,
                  "rare": 19 <= h < 21 and d % 2 == 0}[kind]
            bits = bits << 1 | up
            on += up
        days[str(day)] = f"{bits:036x}"
    return {"pct": round(100 * on / (144 * 7)), "days": days}


def mac(oui):
    return oui + ":" + ":".join(f"{rng.randrange(256):02x}" for _ in range(3))


NODES, OVERLAY = [], []


def dev(id_, label, kind, parent, site, ip=None, oui=None, vendor=None, hist="always", online=True, **kw):
    n = {"id": id_, "label": label, "auto_label": label, "kind": kind, "auto_kind": kind, "parent": parent,
         "site": site, "online": online, "ips": [ip] if ip else [], "vendor": vendor,
         "short_vendor": (vendor or "").split(",")[0].split(" Co")[0] or None, "names": {}, "via": ["arp", "passive"],
         "first_seen": iso(now - dt.timedelta(days=40)), "last_seen": iso(now if online else now - dt.timedelta(hours=9)),
         "tags": [], "note": None, "hidden": False, "edited": False, "override": None, "unnamed": False,
         "random_mac": oui == "rand", "os": None, "service_ids": [], "services": [], "history": history(hist)}
    if oui:
        n["mac"] = mac("da" if oui == "rand" else oui)
        n["id"] = n["id"] if not id_.startswith("mac:") else "mac:" + n["mac"]
    n.update(kw)
    NODES.append(n)
    return n["id"]


def ts(name, ip, os_, path="direct", online=True, **kw):
    return {"name": name, "ip": ip, "os": os_, "online": online, "path": path, "exit_offer": False,
            "routes": [], "addrs": [], "last_seen": iso(now), **kw}


def svc(host, name, ports, site, app=None, glyph="app", icon=None, source="docker", health="ok", containers=None):
    sid = f"svc:{host}:{app or 'sys:' + name.lower()}"
    n = {"id": sid, "kind": "service", "label": name, "auto_label": name, "parent": host, "host": host, "site": site,
         "online": True, "state": "running", "health": health, "ports": ports, "app": app, "source": source,
         "source_label": {"docker": "Docker (compose/CasaOS app)", "system": "System service"}[source],
         "url": None, "containers": containers or [], "icon": ICON.format(icon) if icon else None, "icon_url": None,
         "glyph": glyph, "ips": [], "services": [], "tags": [], "note": None, "hidden": False, "edited": False,
         "history": history("always")}
    NODES.append(n)
    next(x for x in NODES if x["id"] == host)["service_ids"].append(sid)


def ctr(name, image, ports):
    return {"name": name, "image": image, "state": "running", "status": "Up 6 days", "ports": ports}


# ---------------------------------------------------------------- Home (the Pi's network)
H = "home"
modem = dev("mac:", "ISP router", "modem", "internet", H, "192.168.1.1", "e0:19:54", "Example Telecom")
mesh = dev("mac:", "Mesh point", "ap", modem, H, "192.168.1.2", "60:a4:b7", "TP-Link Systems Inc")
dev("self", "nodesk-pi", "server", modem, H, "192.168.1.10", "d8:3a:dd", "Raspberry Pi Trading Ltd",
    tailscale=ts("nodesk-pi", "100.64.0.10", "linux", "this device", routes=["192.168.1.0/24", "0.0.0.0/0"], exit_offer=True),
    via=["self"], os="Linux")
NODES[-1]["ips"].append("100.64.0.10")
svc("self", "Nodesk", [8088], H, "nodesk-web", "nodesk")
NODES[-1]["icon"] = "icon.png"
svc("self", "Home Assistant", [8123], H, "homeassistant", icon="home-assistant")
svc("self", "Pi-hole", [53, 8080], H, "pihole", icon="pi-hole")
svc("self", "Immich", [2283], H, "immich", icon="immich", health="partial",
    containers=[ctr("immich-server", "ghcr.io/immich-app/immich-server:release", [2283]),
                ctr("immich-ml", "ghcr.io/immich-app/immich-machine-learning:release", []),
                ctr("immich-db", "postgres:16", []), ctr("immich-redis", "redis:7", [])])
svc("self", "SSH", [22], H, glyph="terminal", source="system")
svc("self", "Samba", [139, 445], H, glyph="folder", source="system")
nas = dev("mac:", "nas", "nas", modem, H, "192.168.1.20", "00:11:32", "Synology Incorporated", os="Linux")
svc(nas, "Jellyfin", [8096], H, "jellyfin", icon="jellyfin")
svc(nas, "SMB", [445], H, glyph="folder", source="system")
dev("mac:", "Workstation", "pc", modem, H, "192.168.1.30", "a8:5e:45", "ASUSTek COMPUTER INC.", "evening", os="Windows")
dev("mac:", "Living room TV", "tv", modem, H, "192.168.1.40", "a8:23:fe", "LG Electronics", "evening",
    names={"mdns_name": "Living-room-TV", "mdns_services": ["_airplay._tcp", "_spotify-connect._tcp"]})
dev("mac:", "Printer", "printer", modem, H, "192.168.1.50", "3c:2a:f4", "Brother Industries, LTD.", "rare", online=False)
dev("mac:", "Vacuum", "vacuum", modem, H, "192.168.1.60", "b0:4a:39", "Beijing Roborock Technology Co., Ltd.")
dev("mac:", "Hall lamp", "lamp", modem, H, "192.168.1.61", "28:6c:07", "XIAOMI Electronics,CO.,LTD")
dev("mac:", "Door camera", "camera", modem, H, "192.168.1.62", "9c:8e:cd", "Amcrest Technologies")
dev("mac:", "Espressif (.57)", "device", modem, H, "192.168.1.57", "24:0a:c4", "Espressif Inc.", unnamed=True)
dev("mac:", "Kitchen speaker", "speaker", mesh, H, "192.168.1.70", "48:a6:b8", "Sonos, Inc.",
    names={"mdns_name": "Kitchen", "mdns_services": ["_sonos._tcp", "_spotify-connect._tcp"]})
dev("mac:", "Sam's phone", "phone", mesh, H, "192.168.1.71", "rand", None, "day", os="Android 15",
    names={"dhcp_name": "Sams-phone"})
dev("mac:", "Android 14 (.73)", "phone", mesh, H, "192.168.1.73", "rand", None, "day", os="Android 14", unnamed=True)
dev("mac:", "Kids tablet", "tablet", mesh, H, "192.168.1.74", "rand", None, "evening", online=False, os="iPadOS")
laptop = dev("ts:alex-laptop", "Alex's laptop", "laptop", modem, H, "192.168.1.31", None, None, "evening",
             tailscale=ts("alex-laptop", "100.64.0.21", "macOS"), os="macOS")

# ---------------------------------------------------------------- Lake cabin (OpenWrt router agent)
C = "cabin"
lte = dev("mac:", "4G modem", "modem", "internet", C, "192.168.8.1", "00:1e:10", "Huawei Technologies Co.,Ltd")
dev("router:cabin", "cabin-router", "router", lte, C, "192.168.20.1", None, None,
    tailscale=ts("cabin-router", "100.64.0.30", "linux"), via=["tailscale", "agent"],
    agent={"name": "cabin", "received": iso(now - dt.timedelta(minutes=2)), "fresh": True})
NODES[-1]["ips"] += ["192.168.8.100"]
svc("router:cabin", "LuCI", [80, 443], C, glyph="app", source="system")
svc("router:cabin", "DNS", [53], C, glyph="dns", source="system")
dev("mac:", "Thermostat", "iot", "router:cabin", C, "192.168.20.11", "18:b4:30", "Nest Labs Inc.")
dev("mac:", "Cabin camera", "camera", "router:cabin", C, "192.168.20.12", "2c:aa:8e", "Wyze Labs Inc")
dev("mac:", "Old TV", "tv", "router:cabin", C, "192.168.20.13", "f0:1f:af", "Samsung Electronics Co.,Ltd", "rare", online=False)
dev("mac:", "Guest phone", "phone", "router:cabin", C, "192.168.20.40", "rand", None, "rare", online=False)

# ---------------------------------------------------------------- Cloud (Tailscale group)
K = "cloud"
dev("cloud-gw", "Cloud", "cloud", "internet", K, placeholder=True)
vps1 = dev("ts:vps-1", "vps-1", "cloud-vm", "cloud-gw", K, None, tailscale=ts("vps-1", "100.64.0.41", "linux", exit_offer=True),
           ips=["100.64.0.41"], agent={"name": "vps-1", "received": iso(now - dt.timedelta(minutes=3)), "fresh": True})
svc(vps1, "Caddy", [80, 443], K, "caddy", icon="caddy")
svc(vps1, "Vaultwarden", [8000], K, "vaultwarden", icon="vaultwarden")
svc(vps1, "Uptime Kuma", [3001], K, "uptime-kuma", icon="uptime-kuma")
svc(vps1, "SSH", [22], K, glyph="terminal", source="system")
dev("ts:vps-2", "vps-2", "cloud-vm", "cloud-gw", K, None, tailscale=ts("vps-2", "100.64.0.42", "linux", "relay (fra)"),
    ips=["100.64.0.42"])

# ---------------------------------------------------------------- Remote / Mobile (default group)
M = "mobile"
dev("mobile-gw", "Roaming devices", "roam", "internet", M, placeholder=True)
dev("ts:jo-phone", "Jo's phone", "phone", "mobile-gw", M, None, "day", tailscale=ts("jo-phone", "100.64.0.51", "android", "idle"),
    ips=["100.64.0.51"])
dev("ts:travel-laptop", "travel-laptop", "laptop", "mobile-gw", M, None, "rare", online=False,
    tailscale=ts("travel-laptop", "100.64.0.52", "windows", "offline", online=False), ips=["100.64.0.52"])

for n in NODES:   # placeholders are frames' top cards, not devices
    if n.get("placeholder"):
        for k in ("history", "mac", "vendor", "short_vendor", "names", "via", "os", "random_mac"):
            n.pop(k, None)

# Exit nodes: who goes out through whom
for a, b in (("router:cabin", "ts:vps-1"), ("ts:jo-phone", "self")):
    OVERLAY.append({"from": a, "to": b, "kind": "exit"})
    next(n for n in NODES if n["id"] == a)["exit_via"] = b
    next(n for n in NODES if n["id"] == b).setdefault("exit_users", []).append(a)

NODES.insert(0, {"id": "internet", "label": "Internet", "kind": "internet", "site": None, "parent": None,
                 "online": True, "ips": [], "services": [], "service_ids": []})
data = {
    "demo": True, "generated": iso(now), "baseline": iso(now - dt.timedelta(days=40)),
    "sites": [{"id": H, "name": "Home", "type": "local", "auto_name": "Home"},
              {"id": C, "name": "Lake cabin", "type": "router", "auto_name": "cabin"},
              {"id": K, "name": "Cloud", "type": "group", "auto_name": "Cloud"},
              {"id": M, "name": "Remote / Mobile", "type": "group", "auto_name": "Remote / Mobile"}],
    "nodes": NODES, "overlay": OVERLAY, "errors": [],
    "agents": [{"name": "cabin", "kind": "router", "received": iso(now), "age_min": 2.0, "fresh": True,
                "node": "router:cabin", "usage": {"listen_rss_kb": 1240, "mem_available_kb": 98304}},
               {"name": "vps-1", "kind": "linux", "received": iso(now), "age_min": 3.0, "fresh": True,
                "node": "ts:vps-1", "usage": None}],
    "router_script": {"ok": True, "self_update": True},
    "settings": {"auto": True, "interval_min": 5, "lang": "en", "agent_auto_update": True},
    "app": {"version": open(os.path.join(ROOT, "VERSION")).read().strip()},
    "apps": {}, "sources": {}, "scan": {},
}

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "demo", "_site", "live", "data.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    print(f"{out}: {len(NODES)} nodes")
