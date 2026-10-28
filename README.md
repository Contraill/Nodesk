# Nodesk

Ev ağlarının, uzaktaki bir evin (OpenWrt router), bulut sunucularının ve Tailscale tailnet'inin tek sayfalık, canlı haritası. Bir Raspberry Pi'de çalışır; arayüz Türkçedir.

- **Kim nerede:** Hangi cihaz hangi ağda, neyin altında (modem, router, extender); çevrimiçi mi, son 7 günde ne kadar açıktı.
- **Ne çalışıyor:** Pi'deki ve sunuculardaki servisler (Docker, CasaOS uygulamaları, sistem servisleri) ve sağlıkları.
- **Nasıl bağlı:** Tailnet'te kimin kime doğrudan ya da aktarıcı (DERP) üzerinden ulaştığı; kimin interneti hangi exit node üzerinden çıkıyor.
- **Ne değişti:** Yeni cihaz, kapanan servis, susan ajan, değişen exit node için isteğe bağlı bildirim (ntfy ya da Telegram).

## İlkeler

- **Port taraması yapmaz.** Cihazlar ağa katılırken (DHCP), kendini duyururken (mDNS, SSDP) söylediklerinden ve Pi'nin kendi ARP/komşu tablosundan öğrenilir. Adını söylemeyen cihazlara günde bir kez yalnızca ad sorusu sorulur (NetBIOS, mDNS); her IP'ye bir paket.
- **Pi hiçbir cihaza bağlanmaz.** Uzaktaki router ve sunucular kendi verilerini 5 dakikada bir Pi'ye gönderir (ajanlar, anahtarla). Ajanlar yeni sürümü de Pi'den kendileri alır.
- **Markaya özel entegrasyon yok.** Modem, extender ya da router markasından bağımsız çalışır. OpenWrt router için ajan, Linux sunucular için ajan vardır.
- **Bağımlılık yok.** Python standart kütüphanesi, tek dosyalık web arayüzü; web sunucusu olarak nginx container'ı.

## Gereksinimler

- Raspberry Pi (ya da 7/24 açık herhangi bir Linux makine), Python 3.11+, Docker (compose eklentisiyle), Tailscale, `arp-scan`, `git`, `curl`
- İsteğe bağlı: OpenWrt router (başka bir evi eklemek için), Linux sunucular (servislerini görmek için)
- CasaOS varsa web arayüzü CasaOS uygulaması olarak kurulur; yoksa `docker compose` ile.

```bash
sudo apt install -y git arp-scan curl
curl -fsSL https://get.docker.com | sh            # Docker + compose eklentisi
curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up
```

## Kurulum

```bash
sudo git clone https://github.com/Contraill/Nodesk.git /DATA/AppData/nodesk/app
sudo /DATA/AppData/nodesk/app/bin/nodesk install
```

Veri klasörü varsayılan olarak `/DATA/AppData/nodesk`'tir (CasaOS düzeni). Başka bir yer için iki komutta da `NODESK_HOME=/yol` ver. Kurulum tekrar çalıştırılabilir; bir şey bozulursa onarır.

Harita `http://<pi>:8088` adresindedir. İlk açılışta **kurulum sihirbazı** açılır:

1. Pi'nin bağlı olduğu ağ (arayüz, alt ağ, geçit) kendiliğinden bulunur; ağa bir ad verirsin.
2. Varsa başka evleri (router ajanı) ve sunucuları (sunucu ajanı) eklersin.
3. Tailscale cihazlarını gruplara koyarsın (örn. "Bulut", "Gezgin cihazlar").
4. Kimin düzenleyebileceğini seçersin.

<details><summary>Özel bir çatal (fork) kullanıyorsan: salt okunur deploy anahtarı</summary>

```bash
sudo mkdir -p /DATA/AppData/nodesk/keys && sudo chmod 700 /DATA/AppData/nodesk/keys
sudo ssh-keygen -q -t ed25519 -N "" -C nodesk-deploy -f /DATA/AppData/nodesk/keys/deploy_ed25519
sudo cat /DATA/AppData/nodesk/keys/deploy_ed25519.pub   # GitHub > Settings > Deploy keys (yazma izni yok)
sudo git -c core.sshCommand="ssh -i /DATA/AppData/nodesk/keys/deploy_ed25519 -o IdentitiesOnly=yes" \
  clone git@github.com:<sen>/Nodesk.git /DATA/AppData/nodesk/app
```
Kurulum, anahtar varsa güncellemelerde de onu kullanır.
</details>

## Başka evler ve sunucular: ajanlar

**Ayarlar > Ajanlar > Ekle**. Her ajanın kendi anahtarı olur; kurulum komutunu kopyalayıp o cihazda çalıştırırsın. Tekrar çalıştırmak güvenlidir.

| Ajan | Nerede | Ne gönderir |
|---|---|---|
| Router (OpenWrt) | `uclient-fetch -qO- '…' \| sh` (router'da) | DHCP kiraları, ARP tablosu, WAN tarafındaki modem ağı (`arp-scan` ile), dinleyen servisler, exit node. `ucode-mod-socket` kuruluysa: cihazların DHCP/mDNS ile söylediği adlar ve günde bir ad sorusu |
| Sunucu (Linux) | `curl -fsSL '…' \| sudo sh` | Docker container'ları, dinleyen portlar, exit node |

Her router ajanı haritada kendi grubu (çerçevesi) olur. Router'ın modemi ve Tailscale adı raporundan kendiliğinden bulunur.

## Erişim

Varsayılan: haritayı ağdaki herkes görür, **düzenlemeyi yalnızca Tailscale üzerinden bağlananlar** yapabilir. Böylece ev Wi-Fi'ındaki bir misafir ayarları değiştiremez. **Ayarlar > Erişim**'den şunlar seçilebilir:

- yalnızca belirli Tailscale hesapları (kimlik `tailscale whois` ile doğrulanır)
- parolayla giriş (`sudo nodesk password` ya da Ayarlar'dan)
- haritayı görmek için de giriş

Ajan uçları bu ayarlardan etkilenmez; kendi anahtarlarıyla korunurlar.

## Cihaz tanıma

Ad ve tür bu sırayla aranır:

1. senin verdiğin ad
2. cihazın DHCP'de söylediği ad
3. mDNS/NetBIOS/UPnP adı
4. üretici (MAC) ve işletim sistemi (DHCP parmak izi)

Telefonlar her Wi-Fi ağında farklı rastgele MAC kullanır. Aynı telefonun MAC'leri şu durumlarda tek cihaz sayılır:
- aynı (fabrika adı olmayan) DHCP/mDNS adını taşıyorlarsa,
- `config.toml`'da aynı adla yazılmışlarsa,
- ya da sen "Aynı cihaz" dersen.

Biri kaybolup hemen diğeri gelirse harita sorar. Üst satırdaki **N adsız** bağlantısı, adını söylemeyen cihazları tek ekranda adlandırmanı sağlar.

MAC-NAT yapan extender'ların (tekrarlayıcı) arkasındaki cihazlar ayrı ayrı gösterilir. Kablolu + Wi-Fi bağlı tek cihaz ve extender'ın iki MAC'i iki kez görünmez.

## Güncelleme

Harita yeni sürümü 6 saatte bir denetler ve üstte bildirir. **Ayarlar > Güncelle** ya da:

```bash
sudo nodesk update      # değişiklikleri gösterir, uygular, servisi ve web'i yeniler
sudo nodesk rollback    # bir önceki sürüme döner
```

`config.toml`, haritadaki düzenlemeler, geçmiş ve anahtarlar korunur. Ajanlar yeni sürümü bir sonraki raporlarında kendileri alır.

## Komutlar

| Komut | Ne yapar |
|---|---|
| `sudo nodesk status` | Sürüm, servis, web, ajanlar, son tarama |
| `sudo nodesk run` | Şimdi tara |
| `sudo nodesk logs 50` | Son günlük satırları |
| `sudo nodesk password` | Düzenleme parolası |
| `sudo nodesk agent add <ad>` / `list` / `remove <ad>` | Ajanlar |
| `sudo nodesk install` | Kurulumu onarır |
| `sudo nodesk uninstall` | Servisi ve web'i kaldırır; veri klasörü kalır |

## Veri klasörü

```
app/              bu depo (güncelleme yeniler)
config.toml       ileri ayarlar (çoğu şey artık haritadan)
data/
  settings.json   ayarlar: gruplar, erişim, renkler, bildirimler
  overrides.json  haritada yapılan düzenlemeler
  agents.json     ajanlar ve anahtarları; agents/ son raporlar
  passive*.json   pasif dinlemede ve router'larda duyulanlar
  state.json      ilk/son görülme; history.json son 7 gün
  auth.json       parola özeti ve oturumlar (yalnızca root)
www/              herkese açık harita verisi (harita gizliyse boş)
```

Her JSON dosyasının bir önceki sürümü `.bak` olarak durur. Bozuk bir dosya kenara alınır (`.bozuk-<zaman>`) ve yedekten devam edilir.

Çalışan parçalar:
- `nodesk.service`: root olarak, toplayıcı, pasif dinleyici ve API (yalnızca 127.0.0.1:8089).
- `nodesk-web`: nginx container'ı, 8088'de haritayı sunar ve `/api/`'yi iletir.

## Sorun giderme

- **Harita güncellenmiyor:** `sudo nodesk status`, `sudo nodesk logs 100`.
- **Router grubu gri:** Router ajanı rapor göndermiyor. Router'da `logread | grep nodesk-agent`, `/tmp/nodesk-install.log`.
- **Düzenle düğmesi yok:** Tailscale üzerinden bağlanmıyorsun. Ya Tailscale adresini kullan ya da `sudo nodesk password` ile parola belirleyip giriş yap.
- **Cihazlar adsız:** Telefonlar adını ağa yeniden bağlanırken söyler. Bir gün bekle ya da "N adsız" ekranından adlandır.

## Geliştirme

```bash
tests/run.sh              # birim + API + script + arayüz testleri (Chromium varsa)
tests/run.sh --preview    # + http://localhost:8099 üzerinde örnek verili önizleme
```

Haritanın öz-testi: adresin sonuna `#selftest` ekle. Kart çakışmalarını, çizgilerin kartlardan geçmesini ve JS hatalarını denetler. Sürüm yükseltirken `VERSION`'ı, router tarafı değiştiyse `router/topo-collect`'teki `TOPO_VERSION`'ı artır.
