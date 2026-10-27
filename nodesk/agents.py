"""Ajan kurulum scriptleri.

Ajanlar Pi'ye bağlanılmasını beklemez; kendi verilerini 5 dakikada bir Pi'ye gönderir
(POST /api/ingest). Böylece Pi'nin hiçbir cihaza SSH ile girmesi gerekmez.
"""

import os

from . import store

ROUTER_INSTALLER = r"""#!/bin/sh
# Nodesk router ajanı kurulumu (otomatik üretildi). Tekrar çalıştırmak güvenli.
# Yaptıkları: topo-collect ve nodesk-agent'ı kurar, cron'a 5 dakikalık satır ekler,
# eski (SSH) yöntemin anahtar satırını kaldırır. Mevcut ayarlarına dokunmaz.
set -e

if command -v curl >/dev/null 2>&1; then
    echo "gönderim aracı: curl"
elif uclient-fetch --help 2>&1 | grep -q -- '--post-file'; then
    echo "gönderim aracı: uclient-fetch"
else
    echo "HATA: curl yok ve uclient-fetch --post-file desteklemiyor. Hiçbir şey değiştirilmedi."
    exit 1
fi

umask 077
cat > /etc/nodesk-agent.conf <<'NODESK_EOF'
NODESK_URL='@URL@'
NODESK_EOF
umask 022

cat > /usr/sbin/topo-collect.new <<'NODESK_EOF'
@TOPO@
NODESK_EOF
chmod 755 /usr/sbin/topo-collect.new
mv /usr/sbin/topo-collect.new /usr/sbin/topo-collect

cat > /usr/sbin/nodesk-agent.new <<'NODESK_EOF'
#!/bin/sh
# Nodesk router ajanı: topo-collect çıktısını Pi'ye gönderir (cron, 5 dakikada bir).
. /etc/nodesk-agent.conf || exit 1
OUT=/tmp/nodesk-agent.txt
/usr/sbin/topo-collect > "$OUT" 2>/dev/null
if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 25 -H 'Content-Type: text/plain' --data-binary "@$OUT" "$NODESK_URL" >/dev/null
else
    uclient-fetch -q --timeout=25 -O /dev/null --post-file="$OUT" "$NODESK_URL"
fi
NODESK_EOF
chmod 755 /usr/sbin/nodesk-agent.new
mv /usr/sbin/nodesk-agent.new /usr/sbin/nodesk-agent

CRON=/etc/crontabs/root
touch "$CRON"
if grep -q '/usr/sbin/nodesk-agent' "$CRON"; then
    echo "cron satırı zaten var"
else
    if [ -s "$CRON" ] && [ -n "$(tail -c1 "$CRON")" ]; then echo >> "$CRON"; fi
    echo '*/5 * * * * /usr/sbin/nodesk-agent' >> "$CRON"
    /etc/init.d/cron restart >/dev/null 2>&1 || true
    echo "cron satırı eklendi"
fi

AK=/etc/dropbear/authorized_keys
if [ -f "$AK" ] && grep -qF 'topo@home-pi' "$AK"; then
    cp "$AK" /tmp/authorized_keys.yedek
    grep -vF 'topo@home-pi' "$AK" > "$AK.new" || true
    chmod 600 "$AK.new"
    mv "$AK.new" "$AK"
    echo "eski SSH yönteminin anahtar satırı kaldırıldı (yedek: /tmp/authorized_keys.yedek)"
fi

if /usr/sbin/nodesk-agent; then
    echo "ilk rapor Pi'ye gönderildi"
else
    echo "UYARI: Pi'ye ulaşılamadı; cron 5 dakikada bir tekrar deneyecek"
fi
echo "topo-collect sürümü: $(sed -n 's/^TOPO_VERSION=//p' /usr/sbin/topo-collect)"
echo "cron: $(grep -c '' "$CRON") satır"
[ -f "$AK" ] && echo "authorized_keys: $(grep -c '' "$AK") satır"
exit 0
"""

LINUX_INSTALLER = r"""#!/bin/sh
# Nodesk sunucu ajanı kurulumu (otomatik üretildi). Tekrar çalıştırmak güvenli.
# Bu sunucunun Docker container'larını ve dinleyen portlarını 5 dakikada bir Pi'ye bildirir.
# Port taraması yapmaz, gelen bağlantı açmaz.
set -e
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştır: ... | sudo sh"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "HATA: curl gerekli (apt install curl)"; exit 1; }

mkdir -p /etc/nodesk
umask 077
cat > /etc/nodesk/agent.conf <<'NODESK_EOF'
NODESK_URL='@URL@'
NODESK_EOF
umask 022

cat > /usr/local/sbin/nodesk-agent <<'NODESK_EOF'
#!/bin/sh
# Nodesk sunucu ajanı: Docker container'ları ve dinleyen portları Pi'ye gönderir.
. /etc/nodesk/agent.conf || exit 1
OUT=$(mktemp)
{
    echo "#AGENT"; echo "kind=linux"; echo "version=1"
    echo "#HOST"; hostname
    command -v tailscale >/dev/null 2>&1 && tailscale ip -4 2>/dev/null | head -1
    echo "#DOCKER"
    command -v docker >/dev/null 2>&1 && docker ps -a --format '{{json .}}' 2>/dev/null
    echo "#PORTS"; ss -ltnpH 2>/dev/null
    echo "#END"
} > "$OUT"
curl -fsS -m 25 -H 'Content-Type: text/plain' --data-binary "@$OUT" "$NODESK_URL" >/dev/null
rc=$?
rm -f "$OUT"
exit $rc
NODESK_EOF
chmod 755 /usr/local/sbin/nodesk-agent

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/nodesk-agent.service <<'NODESK_EOF'
[Unit]
Description=Nodesk ajanı: Pi'ye rapor gönder
After=network-online.target tailscaled.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nodesk-agent
NODESK_EOF
    cat > /etc/systemd/system/nodesk-agent.timer <<'NODESK_EOF'
[Unit]
Description=Nodesk ajanı: 5 dakikada bir

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
NODESK_EOF
    systemctl daemon-reload
    systemctl enable --now nodesk-agent.timer >/dev/null 2>&1
    echo "zamanlayıcı: systemd (nodesk-agent.timer)"
else
    echo '*/5 * * * * root /usr/local/sbin/nodesk-agent' > /etc/cron.d/nodesk-agent
    echo "zamanlayıcı: cron (/etc/cron.d/nodesk-agent)"
fi

if /usr/local/sbin/nodesk-agent; then
    echo "ilk rapor Pi'ye gönderildi"
else
    echo "UYARI: Pi'ye ulaşılamadı; 5 dakikada bir tekrar denenecek"
fi
echo "Kaldırmak için: systemctl disable --now nodesk-agent.timer; rm -f /etc/systemd/system/nodesk-agent.* /etc/cron.d/nodesk-agent /usr/local/sbin/nodesk-agent; rm -rf /etc/nodesk"
exit 0
"""


def topo_text():
    with open(os.path.join(store.APP_DIR, "router", "topo-collect"), encoding="utf-8") as f:
        return f.read().rstrip("\n")


def topo_version():
    for line in topo_text().splitlines():
        if line.startswith("TOPO_VERSION="):
            return line.split("=", 1)[1].strip()
    return None


def ingest_url(base, name, token):
    return f"{base.rstrip('/')}/api/ingest?agent={name}&token={token}"


def installer(kind, base, name, token):
    url = ingest_url(base, name, token)
    if kind == "router":
        return ROUTER_INSTALLER.replace("@URL@", url).replace("@TOPO@", topo_text())
    return LINUX_INSTALLER.replace("@URL@", url)


def install_commands(kind, base, name, token):
    url = f"{base.rstrip('/')}/api/agent/install?name={name}&token={token}"
    if kind == "router":
        return {
            "laptop": "ssh pi@100.64.0.1 sudo nodesk router-script | ssh root@100.64.0.2 sh",
            "direct": f"uclient-fetch -qO- '{url}' | sh",
        }
    return {"direct": f"curl -fsSL '{url}' | sudo sh"}
