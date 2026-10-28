"""Nodesk'i Pi'den iz bırakmadan kaldırma.

İki yoldan başlar:
  * `sudo nodesk uninstall` (data/teardown-request dosyası)
  * web container'ı (nodesk-web) silindi, örn. CasaOS'tan "Sil": daha önce görülmüş container
    10 dakika boyunca hiç yoksa (durdurulmuş container sayılmaz; güncellemede birkaç saniyelik
    yokluk ve Pi'nin yeni açılması da sayılmaz)

Sıra: önce bütün ajanlara "kendini kaldır" denir (Pi hiçbir cihaza bağlanmaz; ajanlar bir sonraki
raporunda kendini siler). Web container'ı yoksa servis 8088'de yalnızca ajan raporlarını dinler.
Ajanlar bitince ya da en fazla 15 dakika sonra Pi tarafı silinir: servis, komut, web container'ı,
imajı (başka container kullanmıyorsa) ve bütün veri klasörü. Bu sürede container geri gelirse
(yeniden kurulum) kaldırma iptal edilir.
"""

import os
import shlex

APP_ID = "nodesk-web"
WEB_IMAGE = "nginx:1.27-alpine"
UNIT_DIR = "/etc/systemd/system"


def safe_home(home):
    """Silinecek klasör gerçekten bir Nodesk kurulumu mu? (kök, boş ya da başka klasör asla)"""
    home = os.path.realpath(home or "")
    return (home not in ("/", "") and home.count("/") >= 2
            and os.path.isfile(os.path.join(home, "app", "bin", "nodesk")))


def removal_script(home):
    """Pi tarafını tamamen kaldıran kabuk betiği (servis dışından, systemd-run ile çalışır)."""
    if not safe_home(home):
        raise ValueError(f"güvensiz veri klasörü, silinmez: {home!r}")
    h = shlex.quote(os.path.realpath(home))
    casaos_dir = shlex.quote(os.path.join(os.path.dirname(os.path.realpath(home)), APP_ID))
    return f"""set +e
sleep 2
systemctl disable --now nodesk.service nodesk.timer >/dev/null 2>&1
rm -f {UNIT_DIR}/nodesk.service {UNIT_DIR}/nodesk.timer
systemctl daemon-reload
rm -f /usr/local/bin/nodesk
command -v casaos-cli >/dev/null 2>&1 && casaos-cli app-management uninstall {APP_ID} -n >/dev/null 2>&1
docker rm -f {APP_ID} >/dev/null 2>&1
docker image rm {WEB_IMAGE} >/dev/null 2>&1   # başka bir container kullanıyorsa Docker silmez
rm -rf {h} {casaos_dir}
logger -t nodesk "Nodesk Pi'den tamamen kaldırıldı" 2>/dev/null
"""
