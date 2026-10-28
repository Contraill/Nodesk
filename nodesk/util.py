"""Ortak yardımcılar: MAC/IP işlemleri, üretici veritabanı, JSON dosyaları."""

import datetime as dt
import ipaddress
import json
import os
import shutil
import re
import tempfile
import time
import threading

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def utcnow():
    if os.environ.get("NODESK_NOW"):  # testler için sabit zaman
        return dt.datetime.fromisoformat(os.environ["NODESK_NOW"])
    return dt.datetime.now(dt.timezone.utc)


def iso(t):
    return t.isoformat(timespec="seconds") if t else None


def parse_iso(s):
    try:
        return dt.datetime.fromisoformat(s) if s else None
    except (TypeError, ValueError):
        return None


def norm_mac(mac):
    mac = (mac or "").strip().lower().replace("-", ":")
    return mac if MAC_RE.match(mac) else None


def is_local_mac(mac):
    """Yerel yönetimli (çoğu zaman telefonların rastgele) MAC adresi mi?"""
    return bool(mac) and (int(mac.split(":")[0], 16) & 0x02) != 0


def ip_sort_key(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except (ValueError, TypeError):
        return 0


def is_ipv4(s):
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except (ValueError, TypeError):
        return False


def in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net, strict=False)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- üretici adları

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
    return " ".join(keep[:2]) or (words[0] if words else None)


# ---------------------------------------------------------------- JSON dosyaları

_write_lock = threading.Lock()


def read_json(path, default=None):
    """Bozuk dosya sessizce boş sayılmaz (bir sonraki kayıt verileri ezerdi): kenara alınır
    (<ad>.bozuk-<zaman>) ve son sağlam yedek (<ad>.bak) kullanılır."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError:
        return default
    except (json.JSONDecodeError, UnicodeDecodeError):
        bad = f"{path}.bozuk-{int(time.time())}"
        try:
            os.replace(path, bad)
        except OSError:
            pass
        print(f"[nodesk] bozuk dosya kenara alındı: {bad}", flush=True)
        try:
            with open(path + ".bak", encoding="utf-8") as f:
                data = json.load(f)
            write_json(path, data)
            print(f"[nodesk] yedekten geri yüklendi: {path}.bak", flush=True)
            return data
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return default


def write_json(path, obj, mode=0o644, indent=1, backup=True):
    """Atomik yazma: okuyan taraf hiçbir zaman yarım dosya görmez."""
    d = os.path.dirname(path) or "."
    with _write_lock:
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=indent)
            os.chmod(tmp, mode)
            if backup and os.path.exists(path):
                shutil.copy2(path, path + ".bak")   # son sağlam sürüm (read_json bozulursa kullanır)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def read_text(path, default=""):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return default


def parse_sections(text):
    """'#BÖLÜM' başlıklı metni {BÖLÜM: [satırlar]} sözlüğüne çevirir."""
    sections, cur = {}, None
    for line in (text or "").splitlines():
        if line.startswith("#") and len(line) > 1 and line[1:].replace("_", "").isalnum() \
                and line[1:].isupper():
            cur = line[1:]
            sections[cur] = []
        elif cur:
            sections[cur].append(line)
    return sections
