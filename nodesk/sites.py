"""Gruplar (haritadaki çerçeveler) ve nereden beslendikleri.

  local  : Pi'nin kendi yerel ağı (ARP, pasif dinleme, ad sorusu). Arayüz, alt ağ ve geçit
           kendiliğinden bulunur (varsayılan rota).
  router : bir OpenWrt router ajanının ağları: LAN (DHCP kiraları) ve WAN tarafındaki modem ağı.
           Kayıtlı her router ajanı kendiliğinden bir grup olur.
  group  : Tailscale cihazlarının toplandığı grup (bulut sunucular, gezgin cihazlar...).
           "default" grup, hiçbir gruba atanmamış Tailscale cihazlarını toplar.

Ayarlarda tutulur (settings.json: "sites", "ts_site"); eski config.toml'dan bir kez taşınır.
Grup kimlikleri değişmez, arayüzden verilen adlar ve düzenlemeler bu kimliklere bağlıdır.
"""

import re

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")
TYPES = ("local", "router", "group")
KEYS = {  # tür -> elle verilebilen ayarlar (yoksa kendiliğinden)
    "local": ("interface", "subnet", "gateway_ip", "modem_name", "server_name"),
    "router": ("agent", "modem_ip", "modem_name", "router_name", "router_ts_name", "lan_dev"),
    "group": ("kind", "default", "root_name"),
}


def from_config(cfg):
    """Eski config.toml ([ev1], [ev2], [oracle], [mobile], [tailscale.site_of]) -> yeni yapı."""
    sites = []
    ev1 = cfg.get("ev1") or {}
    sites.append({"id": "ev1", "type": "local", "name": ev1.get("name", "Home"),
                  **{k: ev1[k] for k in KEYS["local"] if ev1.get(k)}})
    if cfg.get("ev2"):
        ev2 = cfg["ev2"]
        sites.append({"id": "ev2", "type": "router", "agent": "router", "name": ev2.get("name", "Home 2"),
                      **{k: ev2[k] for k in KEYS["router"] if ev2.get(k)}})
    if cfg.get("oracle"):
        sites.append({"id": "oracle", "type": "group", "kind": "cloud",
                      "name": cfg["oracle"].get("name", "Cloud")})
    mob = cfg.get("mobile") or {}
    sites.append({"id": "mobile", "type": "group", "kind": "roam", "default": True,
                  "name": mob.get("name", "Remote / Mobile"), "root_name": mob.get("root_name", "Roaming devices")})
    ts_site = {k.lower(): v for k, v in ((cfg.get("tailscale") or {}).get("site_of") or {}).items()}
    return sites, ts_site


def resolve(sites, router_agents):
    """Ayarlardaki gruplar + kayıtlı router ajanları -> eksiksiz grup listesi.
    Her zaman tam olarak bir yerel ağ ve bir varsayılan grup vardır."""
    # ajanı silinmiş router grubu haritadan kalkar (ayarda kalır: aynı adla yeniden eklenirse döner)
    out = [dict(s) for s in sites or [] if s.get("type") != "router" or s.get("agent") in router_agents]
    if not any(s["type"] == "local" for s in out):
        out.insert(0, {"id": "ev1", "type": "local", "name": "Home"})
    have = {s.get("agent") for s in out if s["type"] == "router"}
    for name in sorted(router_agents):
        if name not in have:   # ajanı kurulmuş ama grubu yok: kendiliğinden ekle
            sid = name if ID_RE.match(name) and name not in {s["id"] for s in out} else f"r-{len(out)}"
            out.append({"id": sid, "type": "router", "agent": name, "name": name})
    if not any(s["type"] == "group" and s.get("default") for s in out):
        out.append({"id": "mobile", "type": "group", "kind": "roam", "default": True,
                    "name": "Remote / Mobile", "root_name": "Roaming devices"})
    return out


def validate(sites):
    """Arayüzden gelen grup listesini denetler -> temiz liste (hata varsa ValueError)."""
    if not isinstance(sites, list) or not 1 <= len(sites) <= 20:
        raise ValueError("the group list must have 1-20 groups")
    out, ids = [], set()
    for s in sites:
        sid, typ = str(s.get("id") or ""), s.get("type")
        if not ID_RE.match(sid) or sid in ids:
            raise ValueError(f"invalid or duplicate group id: {sid!r}")
        if typ not in TYPES:
            raise ValueError(f"invalid group type: {typ!r}")
        ids.add(sid)
        clean = {"id": sid, "type": typ, "name": str(s.get("name") or sid).strip()[:40]}
        for k in KEYS[typ]:
            v = s.get(k)
            if v in (None, ""):
                continue
            if k == "default":
                clean[k] = bool(v)
            elif k == "kind":
                if v not in ("cloud", "roam", "site"):
                    raise ValueError("group kind: cloud | roam | site")
                clean[k] = v
            else:
                clean[k] = str(v).strip()[:60]
        out.append(clean)
    if sum(s["type"] == "local" for s in out) != 1:
        raise ValueError("there must be exactly one local network group")
    if sum(bool(s.get("default")) for s in out) > 1:
        raise ValueError("at most one default group is allowed")
    return out
