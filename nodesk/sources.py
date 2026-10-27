"""Veri kaynakları. Hiçbiri port taraması yapmaz.

Her fonksiyon başarısızlıkta None döner ve hatayı Runner.status'a yazar.
NODESK_FIXTURES ayarlıysa komutlar yerine o klasördeki dosyalar okunur (testler).
"""

import http.client
import json
import os
import re
import socket
import subprocess

from . import util


class Runner:
    def __init__(self, fixtures=None):
        self.fixtures = fixtures
        self.status = {}   # kaynak -> {"ok": bool, "count": int, "error": str}

    def mark(self, source, ok, count=None, error=None):
        self.status[source] = {k: v for k, v in
                               (("ok", ok), ("count", count), ("error", error)) if v is not None}

    def fixture(self, name):
        path = os.path.join(self.fixtures, name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return f.read()

    def cmd(self, source, key, argv, timeout=30):
        """Komut çıktısı ya da None. key: fixture dosya adı."""
        if self.fixtures:
            out = self.fixture(key)
            if out is None:
                self.mark(source, False, error="örnek veri yok")
            return out
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            self.mark(source, False, error=f"{argv[0]} bulunamadı")
            return None
        except subprocess.TimeoutExpired:
            self.mark(source, False, error=f"{argv[0]} {timeout} sn içinde bitmedi")
            return None
        if p.returncode != 0:
            err = "; ".join(line for line in p.stderr.strip().splitlines()
                            if not line.startswith("Warning: Permanently added"))[:200]
            self.mark(source, False, error=f"{argv[0]} çıkış kodu {p.returncode}: {err}")
            return None
        return p.stdout


# ---------------------------------------------------------------- Tailscale

def tailscale(r):
    raw = r.cmd("tailscale", "tailscale.json", ["tailscale", "status", "--json"])
    if raw is None:
        return None
    try:
        d = json.loads(raw)
    except json.JSONDecodeError as e:
        r.mark("tailscale", False, error=f"JSON okunamadı: {e}")
        return None
    r.mark("tailscale", True, count=len(d.get("Peer") or {}) + 1)
    return d


# ---------------------------------------------------------------- Pi'nin kendisi

def self_ifaces(r):
    """[{ifname, mac, ip, prefix}] (docker/veth/tailscale hariç)."""
    raw = r.cmd("self", "ip_addr.json", ["ip", "-j", "addr", "show"])
    res = []
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        data = []
    for link in data:
        name = link.get("ifname", "")
        mac = util.norm_mac(link.get("address"))
        if not mac or name.startswith(("docker", "br-", "veth", "tailscale", "lo")):
            continue
        for a in link.get("addr_info", []):
            if a.get("family") == "inet":
                res.append({"ifname": name, "mac": mac, "ip": a.get("local"),
                            "prefix": a.get("prefixlen", 24)})
    return res


def arpscan(r, iface):
    """Aktif ARP taraması (sadece yerel ağ, ~256 ARP paketi)."""
    raw = r.cmd("arp", "arpscan_ev1.txt",
                ["arp-scan", f"--interface={iface}", "--localnet", "--plain",
                 "--retry=3", "--timeout=800", "--backoff=1.5"], timeout=90)
    if raw is None:
        return None
    res = parse_arpscan(raw)
    r.mark("arp", True, count=len({e["mac"] for e in res}))
    return res


def parse_arpscan(text):
    """arp-scan --plain: IP<TAB>MAC[<TAB>Üretici]"""
    out = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not util.is_ipv4(parts[0].strip()):
            continue
        mac = util.norm_mac(parts[1])
        if not mac:
            continue
        vendor = parts[2].strip() if len(parts) > 2 else ""
        vendor = re.sub(r"\s*\(DUP: \d+\)\s*$", "", vendor)
        if not vendor or vendor.lower().startswith(("(unknown", "unknown")):
            vendor = None
        out.append({"ip": parts[0].strip(), "mac": mac, "vendor": vendor})
    return out


def neigh(r):
    """Pi'nin komşu (ARP) tablosu: son zamanlarda konuştuğu cihazlar."""
    raw = r.cmd("neigh", "neigh.json", ["ip", "-j", "-4", "neigh", "show"])
    if raw is None:
        return None
    try:
        data = json.loads(raw or "[]")
    except json.JSONDecodeError:
        r.mark("neigh", False, error="JSON okunamadı")
        return None
    res = []
    for e in data:
        mac = util.norm_mac(e.get("lladdr"))
        states = e.get("state") or []
        if mac and util.is_ipv4(e.get("dst")):
            res.append({"ip": e["dst"], "mac": mac, "dev": e.get("dev"),
                        "state": states[0] if states else ""})
    r.mark("neigh", True, count=len(res))
    return res


# ---------------------------------------------------------------- Docker

class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def docker_containers(r, sock="/var/run/docker.sock"):
    """Docker Engine API (unix soket) ile container listesi, normalize edilmiş."""
    if r.fixtures:
        raw = r.fixture("docker_containers.json")
        if raw is None:
            r.mark("docker", False, error="örnek veri yok")
            return None
        items = json.loads(raw)
    else:
        try:
            c = _UnixHTTP(sock)
            c.request("GET", "/containers/json?all=1")
            resp = c.getresponse()
            body = resp.read()
            c.close()
            if resp.status != 200:
                r.mark("docker", False, error=f"Docker API {resp.status}")
                return None
            items = json.loads(body)
        except (OSError, json.JSONDecodeError, http.client.HTTPException) as e:
            r.mark("docker", False, error=f"Docker API: {e}")
            return None
    res = []
    for it in items:
        labels = it.get("Labels") or {}
        ports = set()
        for p in it.get("Ports") or []:
            if p.get("PublicPort") and p.get("Type", "tcp") == "tcp" \
                    and not str(p.get("IP", "")).startswith("127."):
                ports.add(int(p["PublicPort"]))
        net_mode = ((it.get("HostConfig") or {}).get("NetworkMode")) or ""
        for p in re.findall(r"\d+", labels.get("nodesk.ports", "")):
            ports.add(int(p))
        res.append({
            "name": (it.get("Names") or ["?"])[0].lstrip("/"),
            "image": it.get("Image", ""),
            "state": it.get("State", ""),
            "status": it.get("Status", ""),
            "ports": sorted(ports),
            "project": labels.get("com.docker.compose.project"),
            "service": labels.get("com.docker.compose.service"),
            "host_network": net_mode == "host",
            "label_ports": bool(labels.get("nodesk.ports")),
        })
    r.mark("docker", True, count=sum(1 for c in res if c["state"] == "running"))
    return res


def parse_docker_ps_json(lines):
    """`docker ps -a --format '{{json .}}'` satırları (ajanlardan)."""
    res = []
    for line in lines or []:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            it = json.loads(line)
        except json.JSONDecodeError:
            continue
        labels = dict(kv.split("=", 1) for kv in (it.get("Labels") or "").split(",") if "=" in kv)
        ports = set()
        for m in re.finditer(r"(?:^|,\s*)([\d.]+|\[?::\]?):(\d+)->\d+/tcp", it.get("Ports") or ""):
            if not m.group(1).startswith("127."):
                ports.add(int(m.group(2)))
        for p in re.findall(r"\d+", labels.get("nodesk.ports", "")):
            ports.add(int(p))
        res.append({
            "name": it.get("Names", "?").split(",")[0],
            "image": it.get("Image", ""),
            "state": it.get("State", ""),
            "status": it.get("Status", ""),
            "ports": sorted(ports),
            "project": labels.get("com.docker.compose.project"),
            "service": labels.get("com.docker.compose.service"),
            "host_network": "host" in (it.get("Networks") or "").split(","),
            "label_ports": bool(labels.get("nodesk.ports")),
        })
    return res


def casaos_titles(r, projects, base="/var/lib/casaos/apps"):
    """CasaOS uygulama başlıkları: compose dosyasındaki x-casaos title."""
    out = {}
    for p in projects:
        if not p or "/" in p or p.startswith("."):
            continue
        if r.fixtures:
            text = r.fixture(os.path.join("casaos_apps", p, "docker-compose.yml"))
        else:
            text = util.read_text(os.path.join(base, p, "docker-compose.yml"), "") or None
        if not text:
            continue
        # x-casaos:\n  title:\n    en_us: Orbis  (en üst seviyedeki ilk title)
        m = re.search(r"^x-casaos:\s*$(?:\n[ \t]+.*)*?\n[ \t]+title:\s*\n[ \t]+\w+:\s*(.+)$",
                      text, flags=re.M)
        if m:
            out[p] = m.group(1).strip().strip("'\"")[:40]
    return out


# ---------------------------------------------------------------- Docker dışı servisler

PROC_NAMES = {
    "casaos-gateway": "CasaOS", "casaos": "CasaOS", "smbd": "Samba", "sshd": "SSH",
    "sshd-session": "SSH", "dropbear": "SSH", "wayvnc": "VNC", "x11vnc": "VNC",
    "vncserver-x11-core": "VNC", "vncserver-x11": "VNC", "cupsd": "Yazıcı (CUPS)",
    "apache2": "Apache", "httpd": "Apache", "lighttpd": "lighttpd", "pihole-FTL": "Pi-hole",
    "mysqld": "MariaDB", "mariadbd": "MariaDB", "postgres": "PostgreSQL",
    "redis-server": "Redis", "uhttpd": "LuCI", "rpcbind": None, "systemd-resolve": None,
    "systemd-resolved": None, "tailscaled": None, "docker-proxy": None, "containerd": None,
    "dockerd": None, "avahi-daemon": None, "dnsmasq": "DNS (dnsmasq)", "chronyd": None,
}


def parse_ss(text, skip_ports=()):
    """`ss -ltnpH` çıktısından süreç başına dinlenen portlar."""
    by_proc = {}
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) < 4 or f[0] != "LISTEN":
            continue
        local = f[3]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]")
        if not port.isdigit():
            continue
        port = int(port)
        if addr.startswith("127.") or addr in ("::1", "localhost") or addr.startswith("fe80") \
                or port >= 32768 or port in skip_ports:
            continue
        m = re.search(r'users:\(\("([^"]+)"', line)
        proc = m.group(1) if m else "?"
        if proc in PROC_NAMES and PROC_NAMES[proc] is None:
            continue
        name = PROC_NAMES.get(proc, proc)
        by_proc.setdefault(name, {"name": name, "proc": proc, "ports": set()})["ports"].add(port)
    return [{"name": v["name"], "proc": v["proc"], "ports": sorted(v["ports"])}
            for v in sorted(by_proc.values(), key=lambda v: min(v["ports"]))]


def host_ports(r, skip_ports=()):
    raw = r.cmd("host_ports", "ss.txt", ["ss", "-ltnpH"])
    if raw is None:
        return None
    res = parse_ss(raw, skip_ports)
    r.mark("host_ports", True, count=len(res))
    return res
