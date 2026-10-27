"""Yerel önizleme: örnek verilerle sunucu + web arayüzü (nginx'in yaptığı işi taklit eder).

    python3 tests/preview.py            -> http://localhost:8099
"""

import http.server
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tests"))
os.environ.setdefault("NODESK_API_PORT", "8189")
import test_nodesk  # noqa: E402  (ortam değişkenlerini ve örnek ajanları hazırlar)
from nodesk import server  # noqa: E402

API = int(os.environ["NODESK_API_PORT"])
PORT = int(os.environ.get("PREVIEW_PORT", "8099"))
del os.environ["NODESK_NOW"]   # önizlemede gerçek saat (ajan raporları şimdi alınmış gibi)


class Proxy(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def translate_path(self, path):
        p = path.split("?")[0]
        if p.startswith("/live/"):
            return os.path.join(HOME, "www", p[len("/live/"):])
        return os.path.join(ROOT, "web", p.lstrip("/") or "index.html")

    def _proxy(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        req = urllib.request.Request(f"http://127.0.0.1:{API}{self.path}", data=body, method=self.command,
                                     headers={k: v for k, v in self.headers.items() if k.lower() == "content-type"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                code, data, ctype = r.status, r.read(), r.headers.get("Content-Type")
        except urllib.error.HTTPError as e:
            code, data, ctype = e.code, e.read(), e.headers.get("Content-Type")
        self.send_response(code)
        self.send_header("Content-Type", ctype or "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._proxy()
        return super().do_GET()

    do_POST = do_PUT = do_DELETE = _proxy


def shifted_fixtures():
    """Örnek pasif kayıtlarını şimdiki zamana kaydır (önizlemede cihazlar çevrimiçi görünsün)."""
    import datetime as dt
    import json
    d = os.path.join(HOME, "fixtures")
    shutil.copytree(test_nodesk.FIX, d)
    base = dt.datetime.fromisoformat(test_nodesk.NOW)
    delta = dt.datetime.now(dt.timezone.utc) - base
    shift = lambda t: (dt.datetime.fromisoformat(t) + delta).isoformat(timespec="seconds")
    p = json.load(open(os.path.join(d, "passive.json")))
    for rec in p.values():
        rec["first"], rec["last"] = shift(rec["first"]), shift(rec["last"])
        rec["ips"] = {ip: shift(t) for ip, t in rec["ips"].items()}
    json.dump(p, open(os.path.join(d, "passive.json"), "w"))
    return d


if __name__ == "__main__":
    HOME = test_nodesk.make_home()
    FIXTURES = shifted_fixtures()
    # ajan raporlarını "şimdi" alınmış say
    for name in ("router", "cloud-arm"):
        test_nodesk.store.Store(test_nodesk.store.Paths(HOME)).save_report(
            name, open(os.path.join(test_nodesk.FIX, "router.txt" if name == "router" else "agent_cloud-arm.txt")).read(), "test")
    server.API_PORT = API
    threading.Thread(target=server.serve, args=(HOME, FIXTURES), daemon=True).start()
    print(f"Önizleme: http://localhost:{PORT}  (veri: {HOME})", flush=True)
    try:
        http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Proxy).serve_forever()
    finally:
        shutil.rmtree(HOME, ignore_errors=True)
