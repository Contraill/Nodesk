"""Kim düzenleyebilir, kim görebilir.

Varsayılan: harita herkese açık; düzenleme yalnızca Tailscale üzerinden (100.64.0.0/10) ve
Pi'nin kendisinden. Böylece ev Wi-Fi'ındaki misafir bir şey değiştiremez. İsteğe bağlı:
  * belirli Tailscale hesapları (kimlik `tailscale whois` ile, istemci beyanına güvenilmez)
  * parola (PBKDF2, `sudo nodesk password`); girişte HttpOnly oturum çerezi
  * haritayı görmek için de giriş (o zaman data.json herkese açık klasöre yazılmaz)
Ajanların rapor/kurulum uçları bunun dışında: onlar ajan anahtarıyla korunur.
"""

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time

from . import util

SESSION_DAYS = 30
COOKIE = "nodesk_session"
LOCAL = ("127.0.0.1", "::1")


def hash_password(pw, salt=None, rounds=200_000):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), rounds).hex()
    return {"salt": salt, "rounds": rounds, "hash": h}


class Auth:
    def __init__(self, path, whois=None):
        self.path = path
        self.lock = threading.Lock()
        self._whois_cache = {}
        self._whois = whois or self._tailscale_whois

    # ---------------------------------------------- kayıt (data/auth.json, 0600)
    def _load(self):
        return util.read_json(self.path, {}) or {}

    def _save(self, d):
        util.write_json(self.path, d, mode=0o600)

    def has_password(self):
        return bool(self._load().get("password"))

    def set_password(self, pw):
        if len(pw) < 8:
            raise ValueError("password must be at least 8 characters")
        with self.lock:
            d = self._load()
            d["password"] = hash_password(pw)
            d["sessions"] = {}          # parola değişince tüm oturumlar kapanır
            self._save(d)

    def check_password(self, pw):
        p = self._load().get("password")
        if not p:
            return False
        h = hash_password(pw, p["salt"], p["rounds"])["hash"]
        return hmac.compare_digest(h, p["hash"])

    def new_session(self):
        tok = secrets.token_urlsafe(32)
        with self.lock:
            d = self._load()
            now = time.time()
            ses = {k: v for k, v in (d.get("sessions") or {}).items() if v > now}
            ses[hashlib.sha256(tok.encode()).hexdigest()] = now + SESSION_DAYS * 86400
            d["sessions"] = ses
            self._save(d)
        return tok

    def end_session(self, tok):
        if not tok:
            return
        with self.lock:
            d = self._load()
            (d.get("sessions") or {}).pop(hashlib.sha256(tok.encode()).hexdigest(), None)
            self._save(d)

    def session_ok(self, tok):
        if not tok:
            return False
        exp = (self._load().get("sessions") or {}).get(hashlib.sha256(tok.encode()).hexdigest())
        return bool(exp and exp > time.time())

    # ---------------------------------------------- Tailscale kimliği
    def _tailscale_whois(self, ip):
        try:
            out = subprocess.run(["tailscale", "whois", "--json", ip], capture_output=True,
                                 text=True, timeout=5).stdout
            return ((json.loads(out) or {}).get("UserProfile") or {}).get("LoginName")
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    def whois(self, ip):
        hit = self._whois_cache.get(ip)
        if hit and hit[1] > time.time():
            return hit[0]
        login = self._whois(ip)
        self._whois_cache[ip] = (login, time.time() + 300)
        return login

    # ---------------------------------------------- karar
    def identify(self, ip, token, access):
        """-> (düzenleyebilir mi, görebilir mi, nasıl: 'password'|'pi'|'tailnet'|<hesap>|None)"""
        edit, how = False, None
        if self.session_ok(token):
            edit, how = True, "password"
        elif ip in LOCAL:
            edit, how = True, "pi"
        elif access.get("edit") == "everyone":
            edit, how = True, "everyone"
        elif access.get("edit", "tailnet") == "tailnet" and util.in_net(ip, "100.64.0.0/10"):
            users = [u.strip().lower() for u in access.get("ts_users") or [] if u.strip()]
            if not users:
                edit, how = True, "tailnet"
            else:
                login = (self.whois(ip) or "").lower()
                edit, how = login in users, login or None
        view = edit or access.get("view", "everyone") == "everyone"
        return edit, view, how


def cookie_token(header):
    for part in (header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE:
            return v
    return None


def set_password_cli(path):
    """sudo nodesk password: parolayı terminalden (görünmeden) iki kez sorar."""
    import getpass
    a = getpass.getpass("New Nodesk password: ")
    b = getpass.getpass("Tekrar: ")
    if a != b:
        print("Passwords do not match; nothing changed.")
        return 1
    try:
        Auth(path).set_password(a)
    except ValueError as e:
        print(e)
        return 1
    os.chmod(path, 0o600)
    print("Password saved; open sessions were logged out.")
    return 0
