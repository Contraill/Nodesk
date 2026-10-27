"""Etkin ad sorgusu (sadece Ev 1): pasif dinlemenin ad öğrenemediği cihazlara doğrudan sorar.

Her IP'ye günde en fazla bir kez, protokol başına tek paket:
  NetBIOS (UDP 137)  -> Windows/Samba bilgisayar adı (NBSTAT)
  mDNS    (UDP 5353) -> IP'nin .local adı (ters PTR) ve duyurduğu servis türleri
  SSDP    (UDP 1900) -> ağa tek M-SEARCH; yanıt verenlerin cihaz tanımından (XML) ad ve model
  mDNS    (multicast) -> ağa tek soru: Apple (_companion-link, _device-info: model kodu ve
                         "Ali'in iPhone'u" gibi ad), AirPlay, Chromecast, HomeKit, yazıcı
Port taraması değildir ve router'a hiç uğramaz: paketler Pi'nin kendi yerel ağında kalır.
Yanıtlar pasif dinlemeyle aynı kayda (passive.json) yazılır.
"""

import html
import select
import socket
import struct
import time
import urllib.parse
import urllib.request

from .passive import _clean, _dns_name, mdns_obs

SSDP_ADDR = ("239.255.255.250", 1900)
M_SEARCH = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
            b"MX: 2\r\nST: upnp:rootdevice\r\n\r\n")


def nbstat_query(tid):
    # Ad "*" (joker), NetBIOS ilk seviye kodlamasıyla: "CK" + 15 boş bayt ("AA")
    return (struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + b"\x20CK" + b"A" * 30 + b"\x00"
            + struct.pack("!HH", 0x21, 1))


def parse_nbstat(b):
    """NBSTAT yanıtı -> bilgisayar adı (ilk benzersiz <00> kaydı) ya da None"""
    _, _, qd, an, _, _ = struct.unpack("!HHHHHH", b[:12])
    off = 12
    for _ in range(qd):
        _, off = _dns_name(b, off)
        off += 4
    if not an:
        return None
    _, off = _dns_name(b, off)
    rtype = struct.unpack("!H", b[off:off + 2])[0]
    off += 10
    if rtype != 0x21 or off >= len(b):
        return None
    for i in range(b[off]):
        e = b[off + 1 + 18 * i:off + 19 + 18 * i]
        if len(e) < 18:
            break
        if e[15] == 0 and not struct.unpack("!H", e[16:18])[0] & 0x8000:
            return _clean(e[:15].decode("ascii", "replace"))
    return None


SERVICE_TYPES = ("_companion-link._tcp", "_device-info._tcp", "_airplay._tcp", "_raop._tcp",
                 "_googlecast._tcp", "_hap._tcp", "_ipp._tcp", "_spotify-connect._tcp")


def qname(name):
    labels = [p.encode() for p in name.split(".")]
    return b"".join(bytes([len(p)]) + p for p in labels) + b"\x00"


def mdns_services_query(tid):
    """Bilinen servis türlerinin hepsi tek pakette (PTR). Yanıt veren cihaz servis adını
    (çoğu zaman kullanıcının verdiği cihaz adı) ve TXT'de modelini söyler."""
    return (struct.pack("!HHHHHH", tid, 0, len(SERVICE_TYPES), 0, 0, 0)
            + b"".join(qname(t + ".local") + struct.pack("!HH", 12, 1) for t in SERVICE_TYPES))


def merge_obs(dst, src):
    """Aynı cihazdan gelen birden çok yanıtı birleştir (listeler birikir)."""
    for k, v in src.items():
        if isinstance(v, list):
            dst[k] = sorted(set(dst.get(k) or []) | set(v))[:16]
        elif v and k not in ("mac", "ip", "via"):
            dst[k] = v


def mdns_query(ip, tid):
    """Tek pakette iki soru: IP'nin ters PTR'si (.local adı) ve servis türleri listesi."""
    q = b"".join(qname(n) + struct.pack("!HH", 12, 1)
                 for n in (".".join(reversed(ip.split("."))) + ".in-addr.arpa", "_services._dns-sd._udp.local"))
    return struct.pack("!HHHHHH", tid, 0, 2, 0, 0, 0) + q


def ssdp_location(payload):
    for line in payload[:1500].decode("utf-8", "replace").split("\r\n"):
        k, _, v = line.partition(":")
        if k.strip().upper() == "LOCATION":
            return v.strip()
    return None


def xml_tag(text, tag):
    """Cihaz tanımından tek bir alan. Regex/XML ayrıştırıcı yok: sadece metin arama."""
    i = text.find(f"<{tag}>")
    j = text.find(f"</{tag}>", i)
    if i < 0 or j < 0:
        return None
    return _clean(html.unescape(text[i + len(tag) + 2:j]))


def upnp_description(url, ip, timeout=3):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "http" or u.hostname != ip:   # sadece yanıt veren cihazın kendisi
        return {}
    with urllib.request.urlopen(url, timeout=timeout) as r:
        text = r.read(64 * 1024).decode("utf-8", "replace")
    out = {"friendly": xml_tag(text, "friendlyName")}
    model = " ".join(filter(None, [xml_tag(text, "manufacturer"), xml_tag(text, "modelName")]))
    if model:
        out["model"] = model[:60]
    return {k: v for k, v in out.items() if v}


def run(targets, local_ip, wait=3.0):
    """targets: {ip: ARP'de görülen MAC} -> pasif dinlemeye verilecek gözlem listesi"""
    found = {ip: {"mac": mac, "ip": ip, "via": "probe"} for ip, mac in targets.items()}
    socks = []
    try:
        nb, md, ss = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3))
        socks = [nb, md, ss]
        for s in socks:
            s.bind((local_ip, 0))
        for s in (ss, md):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        for i, ip in enumerate(targets):
            for s, pkt, port in ((nb, nbstat_query(i + 1), 137), (md, mdns_query(ip, i + 1), 5353)):
                try:
                    s.sendto(pkt, (ip, port))
                except OSError:
                    pass
            time.sleep(0.02)   # paketleri yay: ağda ani yük olmasın
        ss.sendto(M_SEARCH, SSDP_ADDR)
        md.sendto(mdns_services_query(0), ("224.0.0.251", 5353))
        locations = {}
        end = time.monotonic() + wait
        while (left := end - time.monotonic()) > 0:
            ready, _, _ = select.select(socks, [], [], left)
            for s in ready:
                try:
                    data, (ip, _) = s.recvfrom(4096)
                except OSError:
                    continue
                if ip not in found:
                    continue
                try:
                    if s is nb and (name := parse_nbstat(data)):
                        found[ip]["nb_name"] = name
                    elif s is md:
                        merge_obs(found[ip], mdns_obs(data, {"ip": ip}))
                    elif s is ss and (loc := ssdp_location(data)):
                        locations.setdefault(ip, loc)
                except (ValueError, struct.error, IndexError):
                    pass
    finally:
        for s in socks:
            s.close()
    for ip, loc in locations.items():
        try:
            found[ip].update(upnp_description(loc, ip))
        except (OSError, ValueError):
            pass
    return [o for o in found.values() if len(o) > 3]
