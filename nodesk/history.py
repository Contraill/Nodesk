"""Çevrimiçi geçmişi ve bildirimler.

Geçmiş: her cihaz/servis için son 7 gün, 10 dakikalık dilimler. Gün başına 144 bit
(36 onaltılık karakter): {"2026-10-28": "ff00..."} (UTC günleri).

Bildirimler (isteğe bağlı, ntfy ya da Telegram): yeni cihaz, servis kapandı/düzeldi,
ajan sustu/döndü, exit node değişti. İlk çalışmada mevcut durum öğrenilir, bildirim yağmuru
olmaz; aynı olay 30 dakikada bir kereden fazla bildirilmez.
"""

import datetime as dt
import json
import threading
import time
import urllib.parse
import urllib.request

from . import util

SLOT_MIN, DAYS = 10, 7
SLOTS = 24 * 60 // SLOT_MIN


class History:
    def __init__(self, path):
        self.path = path
        self.data = util.read_json(path, {}) or {}

    def record(self, nodes, now):
        day, idx = now.strftime("%Y-%m-%d"), (now.hour * 60 + now.minute) // SLOT_MIN
        keep = {(now - dt.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(DAYS + 1)}
        for n in nodes:
            if n.get("placeholder") or n["kind"] == "internet" or not n.get("online"):
                continue
            days = self.data.setdefault(n["id"], {})
            bits = int(days.get(day) or "0", 16) | (1 << (SLOTS - 1 - idx))
            days[day] = f"{bits:0{SLOTS // 4}x}"
        for nid in list(self.data):
            self.data[nid] = {d: v for d, v in self.data[nid].items() if d in keep}
            if not self.data[nid]:
                del self.data[nid]
        util.write_json(self.path, self.data, indent=None)

    def summary(self, nid, now):
        """-> (son 7 günün çevrimiçi oranı %, gün -> onaltılık) ya da None"""
        days = self.data.get(nid)
        if not days:
            return None
        on = sum(bin(int(v, 16)).count("1") for v in days.values())
        # henüz 7 gün dolmadıysa ilk kaydın diliminden bu yana olan dilimlere göre
        first = min(days)
        idx = SLOTS - int(days[first], 16).bit_length()          # o günün ilk dolu dilimi
        t0 = dt.datetime.fromisoformat(first).replace(tzinfo=dt.timezone.utc) + dt.timedelta(minutes=idx * SLOT_MIN)
        total = max(1, min(DAYS * SLOTS, int((now - t0).total_seconds() // (SLOT_MIN * 60)) + 1))
        return {"pct": round(100 * min(on, total) / total), "days": days}


# ---------------------------------------------------------------- bildirimler

EVENTS = ("new_device", "service_down", "agent_silent", "exit_change")


class Notifier:
    def __init__(self, path):
        self.path = path
        self.state = util.read_json(path, {}) or {}
        self.last_error = None
        self.sent_at = {}

    def _send(self, cfg, title, body):
        try:
            if cfg.get("ntfy_url"):   # başlık sorgu parametresinde (HTTP başlığı Türkçe karakter taşımaz)
                sep = "&" if "?" in cfg["ntfy_url"] else "?"
                url = f"{cfg['ntfy_url']}{sep}title={urllib.parse.quote(title)}&tags=satellite"
                urllib.request.urlopen(urllib.request.Request(url, data=body.encode(), method="POST"),
                                       timeout=10).close()
            if cfg.get("telegram_token") and cfg.get("telegram_chat"):
                url = f"https://api.telegram.org/bot{urllib.parse.quote(cfg['telegram_token'], safe=':')}/sendMessage"
                data = json.dumps({"chat_id": cfg["telegram_chat"], "text": f"{title}\n{body}"}).encode()
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10).close()
            self.last_error = None
        except Exception as e:   # bildirim gitmese de harita çalışmaya devam eder
            self.last_error = f"{type(e).__name__}: {e}"[:200]
            print(f"[nodesk] bildirim gönderilemedi: {self.last_error}", flush=True)

    def send(self, cfg, title, body, key=None):
        if key and time.time() - self.sent_at.get(key, 0) < 1800:
            return
        if key:
            self.sent_at[key] = time.time()
        threading.Thread(target=self._send, args=(cfg, title, body), daemon=True).start()

    def check(self, data, cfg):
        """Önceki durumla karşılaştır, değişenleri bildir. -> gönderilecek (başlık, metin) listesi"""
        devs = {n["id"]: n for n in data["nodes"] if n["kind"] not in ("internet", "service")
                and not n.get("placeholder") and not n["id"].startswith("ip:")}   # ip: geçici kimlik
        svcs = {n["id"]: n for n in data["nodes"] if n["kind"] == "service" and not n.get("hidden")}
        agents = {a["name"]: a for a in data.get("agents") or []}
        exits = sorted(f"{o['from']}>{o['to']}" for o in data.get("overlay") or [])
        label = lambda nid: (devs.get(nid) or svcs.get(nid) or {}).get("label", nid)
        cur = {"devices": sorted(devs), "svc_up": sorted(k for k, n in svcs.items() if n["online"]),
               "agents_fresh": sorted(k for k, a in agents.items() if a.get("fresh")), "exits": exits}
        prev, out = self.state, []
        if prev:   # ilk çalışmada yalnızca öğren
            ev = cfg.get("events") or {}
            if ev.get("new_device", True):
                for nid in sorted(set(cur["devices"]) - set(prev.get("devices", []))):
                    n = devs[nid]
                    out.append(("Yeni cihaz", f"{n['label']} ({', '.join(n.get('ips') or []) or n.get('mac') or ''}) "
                                              f"{n.get('site') or ''} ağında görüldü.", f"new:{nid}"))
            if ev.get("service_down", True):
                for nid in sorted(set(prev.get("svc_up", [])) - set(cur["svc_up"])):
                    if nid in svcs:
                        out.append(("Servis kapandı", f"{label(nid)} ({label(svcs[nid].get('host'))}) yanıt vermiyor.",
                                    f"down:{nid}"))
                for nid in sorted(set(cur["svc_up"]) - set(prev.get("svc_up", []))):
                    out.append(("Servis düzeldi", f"{label(nid)} yeniden çalışıyor.", f"up:{nid}"))
            if ev.get("agent_silent", True):
                for name in sorted(set(prev.get("agents_fresh", [])) - set(cur["agents_fresh"])):
                    out.append(("Ajan sustu", f"{name} ajanı 15 dakikadır rapor göndermiyor.", f"silent:{name}"))
                for name in sorted(set(cur["agents_fresh"]) - set(prev.get("agents_fresh", []))):
                    out.append(("Ajan döndü", f"{name} ajanı yeniden rapor gönderiyor.", f"back:{name}"))
            if ev.get("exit_change", True) and cur["exits"] != prev.get("exits", []):
                txt = lambda e: " → ".join(label(x) for x in e.split(">"))
                now_ = ", ".join(txt(e) for e in cur["exits"]) or "exit node kullanan yok"
                out.append(("Exit node değişti", now_, None))
        self.state = cur
        util.write_json(self.path, cur, indent=None)
        if cfg.get("ntfy_url") or (cfg.get("telegram_token") and cfg.get("telegram_chat")):
            for title, body, key in out:
                self.send(cfg, title, body, key)
        return out
