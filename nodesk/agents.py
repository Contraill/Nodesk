"""Ajan kurulum scriptleri.

Ajanlar Pi'ye bağlanılmasını beklemez; kendi verilerini 5 dakikada bir Pi'ye gönderir
(POST /api/ingest). Böylece Pi'nin hiçbir cihaza SSH ile girmesi gerekmez.
"""

import os

from . import store

ROUTER_INSTALLER = r"""#!/bin/sh
# Nodesk router ajanı kurulumu (otomatik üretildi). Tekrar çalıştırmak güvenli.
# Yaptıkları: topo-collect ve nodesk-agent'ı kurar, cron'a 5 dakikalık satır ekler,
# eski (SSH) yöntemin anahtar satırını kaldırır. ucode-mod-socket kuruluysa salt dinleyen
# nodesk-listen servisini de kurar. Mevcut ayarlarına dokunmaz.
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
NODESK_INSTALL_URL='@INSTALL_URL@'
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
# Pi "ok update" derse yeni sürümü Pi'den (Tailscale/LAN, HTTP) alıp kendini günceller;
# bunun için kimsenin router'a SSH ile girmesi gerekmez.
. /etc/nodesk-agent.conf || exit 1
OUT=/tmp/nodesk-agent.txt
RESP=/tmp/nodesk-agent.resp
/usr/sbin/topo-collect > "$OUT" 2>/dev/null
rm -f "$RESP"
if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 25 -H 'Content-Type: text/plain' --data-binary "@$OUT" -o "$RESP" "$NODESK_URL" || exit 1
else
    uclient-fetch -q --timeout=25 -O "$RESP" --post-file="$OUT" "$NODESK_URL" || exit 1
fi
if [ -z "$NODESK_UPDATING" ] && [ -n "$NODESK_INSTALL_URL" ] && grep -q '^ok update' "$RESP" 2>/dev/null; then
    NEW=/tmp/nodesk-install.sh
    rm -f "$NEW"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -m 30 -o "$NEW" "$NODESK_INSTALL_URL"
    else
        uclient-fetch -q --timeout=30 -O "$NEW" "$NODESK_INSTALL_URL"
    fi
    if head -n 1 "$NEW" 2>/dev/null | grep -q '^#!/bin/sh' && grep -q 'NODESK_EOF' "$NEW"; then
        logger -t nodesk-agent "Pi'den yeni sürüm alındı, kuruluyor"
        NODESK_UPDATING=1 sh "$NEW" > /tmp/nodesk-install.log 2>&1 \
            && logger -t nodesk-agent "güncellendi" || logger -t nodesk-agent "güncelleme başarısız (/tmp/nodesk-install.log)"
    fi
    rm -f "$NEW"
fi
exit 0
NODESK_EOF
chmod 755 /usr/sbin/nodesk-agent.new
mv /usr/sbin/nodesk-agent.new /usr/sbin/nodesk-agent

if [ -f /usr/lib/ucode/socket.so ]; then
    cat > /usr/sbin/nodesk-listen.new <<'NODESK_EOF'
@LISTEN@
NODESK_EOF
    chmod 755 /usr/sbin/nodesk-listen.new
    mv /usr/sbin/nodesk-listen.new /usr/sbin/nodesk-listen
    cat > /etc/init.d/nodesk-listen <<'NODESK_EOF'
#!/bin/sh /etc/rc.common
# Nodesk: router'ın duyduğu DHCP/mDNS yayınlarını kaydeder (salt dinler, paket göndermez)
START=99
USE_PROCD=1
start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/ucode /usr/sbin/nodesk-listen
    procd_set_param respawn 3600 5 5
    procd_close_instance
}
NODESK_EOF
    chmod 755 /etc/init.d/nodesk-listen
    /etc/init.d/nodesk-listen enable || true
    if /etc/init.d/nodesk-listen restart; then echo "dinleyici (nodesk-listen): çalışıyor"
    else echo "UYARI: dinleyici başlatılamadı (ajan yine de çalışır)"; fi
else
    echo "dinleyici atlandı: ucode-mod-socket yok (apk add ucode-mod-socket)"
fi

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

if NODESK_UPDATING=1 /usr/sbin/nodesk-agent; then
    echo "ilk rapor Pi'ye gönderildi"
else
    echo "UYARI: Pi'ye ulaşılamadı; cron 5 dakikada bir tekrar deneyecek"
fi
echo "otomatik güncelleme: açık (Pi yeni sürüm olduğunu söyleyince ajan kendini günceller)"
echo "topo-collect sürümü: $(sed -n 's/^TOPO_VERSION=//p' /usr/sbin/topo-collect)"
echo "cron: $(grep -c '' "$CRON") satır"
[ -f "$AK" ] && echo "authorized_keys: $(grep -c '' "$AK") satır"
echo "Kaldırmak için: /etc/init.d/nodesk-listen disable; /etc/init.d/nodesk-listen stop; rm -f /etc/init.d/nodesk-listen /usr/sbin/nodesk-listen /usr/sbin/nodesk-agent /usr/sbin/topo-collect /etc/nodesk-agent.conf; sed -i '/nodesk-agent/d' /etc/crontabs/root"
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
NODESK_INSTALL_URL='@INSTALL_URL@'
NODESK_EOF
umask 022

cat > /usr/local/sbin/nodesk-agent <<'NODESK_EOF'
#!/bin/sh
# Nodesk sunucu ajanı: Docker container'ları ve dinleyen portları Pi'ye gönderir.
. /etc/nodesk/agent.conf || exit 1
OUT=$(mktemp)
RESP=$(mktemp)
{
    echo "#AGENT"; echo "kind=linux"; echo "version=@LINUX_VERSION@"
    echo "#HOST"; hostname
    command -v tailscale >/dev/null 2>&1 && tailscale ip -4 2>/dev/null | head -1
    echo "#DOCKER"
    command -v docker >/dev/null 2>&1 && docker ps -a --format '{{json .}}' 2>/dev/null
    echo "#PORTS"; ss -ltnpH 2>/dev/null
    echo "#EXITNODE"
    command -v tailscale >/dev/null 2>&1 && tailscale status --json 2>/dev/null | tr -d ' \n' |
        sed -n 's/.*"ExitNodeStatus":{"ID":"\([^"]*\)".*/\1/p'
    echo "#EXITCLIENTS"
    # Son 10 dakikada bu sunucu üzerinden internete çıkan tailnet cihazları (exit node kullananlar).
    # Aynı süzgeç router/topo-collect'te.
    { cat /proc/net/nf_conntrack 2>/dev/null || conntrack -L 2>/dev/null; } | awk -v est="$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || echo 432000)" '
{ p = 0; for (i = 1; i <= NF; i++) if ($i ~ /^(tcp|udp|icmp|udplite|sctp|gre)$/) { p = i; break }
  if (!p) next
  t = $(p + 2); s = ""; d = ""
  for (i = p + 3; i <= NF; i++) { if (s == "" && $i ~ /^src=/) s = substr($i, 5); else if (d == "" && $i ~ /^dst=/) d = substr($i, 5) }
  if (s ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./ && d ~ /^[0-9.]+$/ &&
      d !~ /^(10|127|0|100|169\.254|192\.168|172\.(1[6-9]|2[0-9]|3[01])|22[4-9]|23[0-9]|24[0-9]|25[0-5])\./ &&
      (t <= 600 || t >= est - 600)) n[s]++ }
END { for (k in n) print k, n[k] }'
    echo "#END"
} > "$OUT"
curl -fsS -m 25 -H 'Content-Type: text/plain' --data-binary "@$OUT" -o "$RESP" "$NODESK_URL"
rc=$?
if [ $rc -eq 0 ] && [ -z "$NODESK_UPDATING" ] && [ -n "$NODESK_INSTALL_URL" ] && grep -q '^ok update' "$RESP"; then
    NEW=$(mktemp)
    if curl -fsS -m 30 -o "$NEW" "$NODESK_INSTALL_URL" && head -n 1 "$NEW" | grep -q '^#!/bin/sh' \
            && grep -q 'NODESK_EOF' "$NEW"; then
        logger -t nodesk-agent "Pi'den yeni sürüm alındı, kuruluyor" 2>/dev/null
        NODESK_UPDATING=1 sh "$NEW" >/var/log/nodesk-agent-install.log 2>&1
    fi
    rm -f "$NEW"
fi
rm -f "$OUT" "$RESP"
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

if NODESK_UPDATING=1 /usr/local/sbin/nodesk-agent; then
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


def listen_text():
    with open(os.path.join(store.APP_DIR, "router", "nodesk-listen"), encoding="utf-8") as f:
        return f.read().rstrip("\n")


def topo_version():
    for line in topo_text().splitlines():
        if line.startswith("TOPO_VERSION="):
            return line.split("=", 1)[1].strip()
    return None


LINUX_AGENT_VERSION = "3"   # LINUX_INSTALLER değişince artır


def expected_version(kind):
    return topo_version() if kind == "router" else LINUX_AGENT_VERSION


def reported_version(kind, sections):
    sections = sections or {}
    if kind == "router":
        v = (sections.get("VERSION") or [""])[0].strip()
        return v or None
    for line in sections.get("AGENT", []):
        if line.startswith("version="):
            return line.split("=", 1)[1].strip() or None
    return None


def install_url(base, name, token):
    return f"{base.rstrip('/')}/api/agent/install?name={name}&token={token}"


def ingest_url(base, name, token):
    return f"{base.rstrip('/')}/api/ingest?agent={name}&token={token}"


def installer(kind, base, name, token):
    url, iurl = ingest_url(base, name, token), install_url(base, name, token)
    if kind == "router":
        return (ROUTER_INSTALLER.replace("@URL@", url).replace("@INSTALL_URL@", iurl)
                .replace("@TOPO@", topo_text()).replace("@LISTEN@", listen_text()))
    return (LINUX_INSTALLER.replace("@URL@", url).replace("@INSTALL_URL@", iurl)
            .replace("@LINUX_VERSION@", LINUX_AGENT_VERSION))


def install_commands(kind, base, name, token):
    url = install_url(base, name, token)
    if kind == "router":
        return {
            "laptop": "ssh pi@100.64.0.1 sudo nodesk router-script | ssh root@100.64.0.2 sh",
            "direct": f"uclient-fetch -qO- '{url}' | sh",
        }
    return {"direct": f"curl -fsSL '{url}' | sudo sh"}
