"""Pasif dinleme: ağa hiçbir paket göndermeden cihazları ve adlarını öğrenir.

Pi'nin eth0'ına zaten gelen yayın/çoklu yayın paketlerini okur:
  ARP        -> MAC + IP (cihaz ağda konuşuyor)
  DHCP       -> cihazın kendi verdiği ad (örn. "Galaxy-S24"), üretici sınıfı
  mDNS       -> .local adları, servis türleri (_googlecast, _airplay...), cihaz adları
  SSDP       -> UPnP sunucu bilgisi (TV'ler, medya cihazları)

Çekirdeğe bağlanan BPF filtresi sadece bu paketleri geçirir; Pi'nin üzerinden geçen
diğer trafik (exit node dahil) Python'a hiç ulaşmaz, işlemci yükü yok denecek kadar azdır.
"""

import ctypes
import ipaddress
import socket
import struct
import threading
import time

from . import util

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4
NAME_FIELDS = ("dhcp_name", "dhcp_vendor", "dhcp_fp", "mdns_name", "friendly", "model", "ssdp_server", "nb_name")
LIST_FIELDS = ("mdns_services", "mdns_instances")

# tcpdump -dd 'arp or (ip and udp and (port 67 or port 68 or port 5353 or port 1900))'
BPF = [
    (0x28, 0, 0, 0x0000000c), (0x15, 16, 0, 0x00000806), (0x15, 0, 16, 0x00000800),
    (0x30, 0, 0, 0x00000017), (0x15, 0, 14, 0x00000011), (0x28, 0, 0, 0x00000014),
    (0x45, 12, 0, 0x00001fff), (0xb1, 0, 0, 0x0000000e), (0x48, 0, 0, 0x0000000e),
    (0x15, 8, 0, 0x00000043), (0x15, 7, 0, 0x00000044), (0x15, 6, 0, 0x000014e9),
    (0x15, 5, 0, 0x0000076c), (0x48, 0, 0, 0x00000010), (0x15, 3, 0, 0x00000043),
    (0x15, 2, 0, 0x00000044), (0x15, 1, 0, 0x000014e9), (0x15, 0, 1, 0x0000076c),
    (0x6, 0, 0, 0x00040000), (0x6, 0, 0, 0x00000000),
]


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _ip(b):
    return socket.inet_ntoa(b)


def _clean(s, n=60):
    s = "".join(ch for ch in s if ch.isprintable()).strip()
    return s[:n] or None


# ---------------------------------------------------------------- DNS (mDNS)

def _dns_name(buf, off, depth=0):
    labels, jumped, end = [], False, off
    while True:
        if off >= len(buf) or depth > 20:
            raise ValueError("bad name")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("bad pointer")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        labels.append(buf[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def parse_mdns(payload):
    """-> {"a": {ad: ip}, "services": set, "instances": set, "txt": {anahtar: değer}}"""
    out = {"a": {}, "services": set(), "instances": set(), "txt": {}}
    if len(payload) < 12:
        return out
    _, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    off = 12
    for _ in range(qd):
        _, off = _dns_name(payload, off)
        off += 4
    if not flags & 0x8000:      # sadece yanıtlar ad bilgisi taşır
        return out
    for _ in range(an + ns + ar):
        name, off = _dns_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype, _, _, rdlen = struct.unpack("!HHIH", payload[off:off + 10])
        off += 10
        rdata = payload[off:off + rdlen]
        if rtype == 1 and rdlen == 4 and name.endswith(".local"):
            out["a"][name[:-6]] = _ip(rdata)
        elif rtype == 12:  # PTR: _googlecast._tcp.local -> "Salon TV._googlecast._tcp.local"
            target, _ = _dns_name(payload, off)
            if name.endswith(".in-addr.arpa") and target.endswith(".local"):   # ters sorgu yanıtı
                ip = ".".join(reversed(name[:-13].split(".")))
                if util.is_ipv4(ip):
                    out["a"][target[:-6]] = ip
            elif name.startswith("_") and ("._tcp" in name or "._udp" in name):
                svc = name.replace(".local", "")
                if svc.startswith("_services"):   # _services._dns-sd: hedef bir servis türü
                    out["services"].add(target.replace(".local", ""))
                else:
                    out["services"].add(svc)
                inst = target.split("._", 1)[0]
                if inst and not inst.startswith("_"):
                    out["instances"].add(inst)
        elif rtype == 16:  # TXT
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                kv = rdata[i + 1:i + 1 + ln].decode("utf-8", "replace")
                i += 1 + ln
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    if k in ("fn", "md", "model", "ty", "am", "rpMd") and v:   # rpMd: Apple model kodu
                        out["txt"][k] = v
        off += rdlen
    return out


def mdns_obs(payload, obs):
    """mDNS yanıtındaki adları gözleme ekler (obs["ip"] yanıtı gönderenin IP'si)."""
    try:
        m = parse_mdns(payload)
    except (ValueError, struct.error, IndexError):
        return obs
    for name, ip in m["a"].items():
        if ip == obs["ip"]:
            obs["mdns_name"] = _clean(name)
    if m["services"]:
        obs["mdns_services"] = sorted(m["services"])[:12]
    if m["instances"]:
        obs["mdns_instances"] = sorted(_clean(i) for i in m["instances"] if _clean(i))[:6]
    if m["txt"].get("fn"):
        obs["friendly"] = _clean(m["txt"]["fn"])
    model = next((m["txt"][k] for k in ("md", "model", "rpMd", "am") if m["txt"].get(k)), None)
    if model:
        obs["model"] = _clean(model)
    return obs


# ---------------------------------------------------------------- çerçeve ayrıştırma

def parse_frame(pkt):
    """Ethernet çerçevesi -> gözlem listesi [{mac, ip, ...}]"""
    if len(pkt) < 14:
        return []
    src_mac = _mac(pkt[6:12])
    etype = struct.unpack("!H", pkt[12:14])[0]
    if etype == 0x0806 and len(pkt) >= 42:
        sha, spa = _mac(pkt[22:28]), _ip(pkt[28:32])
        if spa != "0.0.0.0":
            return [{"mac": sha, "ip": spa, "via": "arp"}]
        return []
    if etype != 0x0800 or len(pkt) < 34:
        return []
    ihl = (pkt[14] & 0x0F) * 4
    if pkt[23] != 17:
        return []
    src_ip = _ip(pkt[26:30])
    u = 14 + ihl
    if len(pkt) < u + 8:
        return []
    sport, dport = struct.unpack("!HH", pkt[u:u + 4])
    payload = pkt[u + 8:]

    if {sport, dport} & {67, 68} and len(payload) >= 240 and payload[236:240] == b"\x63\x82\x53\x63":
        return _parse_dhcp(payload)
    if dport == 5353 or sport == 5353:
        return [mdns_obs(payload, {"mac": src_mac, "ip": src_ip, "via": "mdns"})]
    if dport == 1900 or sport == 1900:
        obs = {"mac": src_mac, "ip": src_ip, "via": "ssdp"}
        text = payload[:1500].decode("utf-8", "replace")
        for line in text.split("\r\n"):
            k, _, v = line.partition(":")
            k = k.strip().upper()
            if k in ("SERVER", "USER-AGENT") and v.strip():
                obs["ssdp_server"] = _clean(v, 120)
        return [obs]
    return []


def _parse_dhcp(b):
    op = b[0]
    chaddr = _mac(b[28:34])
    ciaddr, yiaddr = _ip(b[12:16]), _ip(b[16:20])
    opts, i = {}, 240
    while i < len(b) and b[i] != 255:
        code = b[i]
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        ln = b[i + 1]
        opts[code] = b[i + 2:i + 2 + ln]
        i += 2 + ln
    msg = opts.get(53, b"\x00")[0]
    obs = {"mac": chaddr, "via": "dhcp"}
    if op == 1:
        if ciaddr != "0.0.0.0":
            obs["ip"] = ciaddr
        elif msg == 3 and len(opts.get(50, b"")) == 4:   # REQUEST, istenen IP
            obs["ip"] = _ip(opts[50])
        if opts.get(12):
            obs["dhcp_name"] = _clean(opts[12].decode("utf-8", "replace"))
        if opts.get(60):
            obs["dhcp_vendor"] = _clean(opts[60].decode("utf-8", "replace"))
        if opts.get(55):   # istenen seçenekler ve sırası: işletim sisteminin parmak izi
            obs["dhcp_fp"] = ",".join(str(x) for x in opts[55][:40])
    elif op == 2 and msg == 5 and yiaddr != "0.0.0.0":     # ACK
        obs["ip"] = yiaddr
    return [obs]


# ---------------------------------------------------------------- dinleyici

class Passive:
    def __init__(self, path, iface="eth0", subnet=None, keep_days=14):
        self.path = path
        self.iface = iface
        self.subnet = ipaddress.ip_network(subnet, strict=False) if subnet else None
        self.keep_days = keep_days
        self.lock = threading.Lock()
        self.data = util.read_json(path, {}) or {}
        # IP başına bilgi: MAC-NAT yapan extender'ların (örn. Keenetic) arkasındaki cihazlar
        # aynı MAC'le görünür; adlarını IP üzerinden ayırt ederiz.
        self.ip_path = path[:-5] + "_ip.json" if path.endswith(".json") else path + "_ip"
        self.ipinfo = util.read_json(self.ip_path, {}) or {}
        self.dirty = False
        self.error = None
        self.running = False
        self.packets = 0
        self._stop = threading.Event()
        self._thread = None

    def set_subnet(self, subnet):
        try:
            self.subnet = ipaddress.ip_network(subnet, strict=False)
        except (ValueError, TypeError):
            pass

    def observe(self, obs, now=None):
        mac = util.norm_mac(obs.get("mac"))
        if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or int(mac[:2], 16) & 1:
            return
        ip = obs.get("ip")
        if ip and self.subnet and not (util.is_ipv4(ip) and ipaddress.ip_address(ip) in self.subnet):
            # Yönlendirilmiş trafik (kaynak MAC modeminki olur) ya da başka ağ
            if obs.get("via") != "dhcp":
                return
            ip = None
        t = util.iso(now or util.utcnow())
        with self.lock:
            rec = self.data.setdefault(mac, {"first": t, "ips": {}})
            rec["last"] = t
            if ip:
                rec["ips"][ip] = t
            for k in NAME_FIELDS:
                if obs.get(k):
                    rec[k] = obs[k]
            for k in LIST_FIELDS:
                if obs.get(k):
                    rec[k] = sorted(set(rec.get(k, [])) | set(obs[k]))[:16]
            if ip:
                info = self.ipinfo.get(ip) or {}
                if obs.get("via") == "dhcp":
                    if info.get("real_mac") != mac:   # IP başka cihaza geçti: eski adları unut
                        info = {"real_mac": mac}
                elif info.get("l2_mac") not in (None, mac) and not info.get("real_mac"):
                    info = {}
                else:
                    info["l2_mac"] = mac
                info["last"] = t
                for k in NAME_FIELDS:
                    if obs.get(k):
                        info[k] = obs[k]
                for k in LIST_FIELDS:
                    if obs.get(k):
                        info[k] = sorted(set(info.get(k, [])) | set(obs[k]))[:16]
                self.ipinfo[ip] = info
            self.dirty = True

    def snapshot(self):
        with self.lock:
            return {m: {**r, "ips": dict(r["ips"])} for m, r in self.data.items()}

    def snapshot_ip(self):
        with self.lock:
            return {ip: dict(v) for ip, v in self.ipinfo.items()}

    def prune_and_save(self, force=False):
        now = util.utcnow()
        with self.lock:
            cutoff = now.timestamp() - self.keep_days * 86400
            for mac in list(self.data):
                last = util.parse_iso(self.data[mac].get("last"))
                if not last or last.timestamp() < cutoff:
                    del self.data[mac]
                    self.dirty = True
            for ip in list(self.ipinfo):
                last = util.parse_iso(self.ipinfo[ip].get("last"))
                if not last or last.timestamp() < cutoff:
                    del self.ipinfo[ip]
                    self.dirty = True
            if not (self.dirty or force):
                return
            snap = {m: {**r, "ips": dict(r["ips"])} for m, r in self.data.items()}
            snap_ip = {ip: dict(v) for ip, v in self.ipinfo.items()}
            self.dirty = False
        util.write_json(self.path, snap, indent=None)
        util.write_json(self.ip_path, snap_ip, indent=None)

    # -------------------------------------------------- iş parçacığı
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="passive", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _open(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        insns = b"".join(struct.pack("HBBI", *ins) for ins in BPF)
        buf = ctypes.create_string_buffer(insns, len(insns))
        prog = struct.pack("HL", len(BPF), ctypes.addressof(buf))
        s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, prog)
        s.bind((self.iface, 0))
        s.settimeout(1.0)
        # Filtre bağlanmadan önce kuyruğa girmiş paketleri at
        s.setblocking(False)
        try:
            while s.recv(65535):
                pass
        except (BlockingIOError, OSError):
            pass
        s.settimeout(1.0)
        return s, buf

    def _run(self):
        last_save = time.monotonic()
        while not self._stop.is_set():
            try:
                sock, _buf = self._open()
            except OSError as e:
                self.error = f"{self.iface} dinlenemiyor: {e}"
                self.running = False
                self._stop.wait(60)
                continue
            self.error, self.running = None, True
            try:
                while not self._stop.is_set():
                    try:
                        pkt, addr = sock.recvfrom(65535)
                    except socket.timeout:
                        pkt = None
                    if pkt is not None and addr[2] != PACKET_OUTGOING:
                        self.packets += 1
                        try:
                            for obs in parse_frame(pkt):
                                self.observe(obs)
                        except (ValueError, struct.error, IndexError):
                            pass
                    if time.monotonic() - last_save > 60:
                        self.prune_and_save()
                        last_save = time.monotonic()
            except OSError as e:
                self.error = f"dinleme kesildi: {e}"
            finally:
                self.running = False
                sock.close()
            self._stop.wait(10)
        self.prune_and_save()
