#!/usr/bin/env bash
# Toplayıcıyı gerçek çıktılardan alınmış fixture'larla çalıştırır ve sonucu doğrular.
#   tests/run.sh            -> test
#   tests/run.sh --serve    -> test + http://localhost:8099 üzerinde önizleme
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/tests/out"
rm -rf "$OUT"; mkdir -p "$OUT"
NODESK_HOME="$OUT" NODESK_CONFIG="$ROOT/config.example.toml" NODESK_FIXTURES="$ROOT/tests/fixtures" \
NODESK_OUI="$ROOT/tests/fixtures/ieee-oui.txt" python3 "$ROOT/collector/collect.py"
python3 - "$OUT/www/data.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
ids = {n["id"]: n for n in d["nodes"]}
def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg)
    if not cond: sys.exit(1)
check(not d["errors"], "hata yok")
check(ids["self"]["label"] == "home-pi" and len(ids["self"]["services"]) >= 4, "Pi ve servisleri")
check("mac:88:a2:9e:35:f8:bc" not in ids, "Pi'nin kendi wlan0'ı ayrı cihaz olarak çıkmıyor")
check(ids["mac:52:ff:20:53:86:18"]["ips"] == ["192.168.44.4", "192.168.44.7"], "aynı MAC'in iki IP'si birleşiyor")
check(ids["router"]["parent"] == "mac:c0:49:43:1c:cc:12", "router H3600P altında")
check(ids["mac:1c:af:4a:55:4b:2c"]["parent"] == "router", "router LAN cihazı router altında")
check(ids["mac:aa:bb:cc:00:11:22"]["online"] is False, "sadece DHCP kirası olan cihaz çevrimdışı")
check(any(o["from"] == "router" and o["to"] == "self" for o in d["overlay"]), "exit node bağlantısı")
check(d["router_script"]["ok"] is True, "router script sürümü eşleşiyor")
check(ids["ts:cloud-arm"]["site"] == "oracle", "Oracle grubu")
PY
cp -r "$ROOT/web/." "$OUT/web/" 2>/dev/null || { mkdir -p "$OUT/web"; cp -r "$ROOT/web/." "$OUT/web/"; }
rm -rf "$OUT/web/live"; ln -s "$OUT/www" "$OUT/web/live"
if [ "${1:-}" = "--serve" ]; then
    echo "Önizleme: http://localhost:8099"; cd "$OUT/web" && python3 -m http.server 8099
fi
