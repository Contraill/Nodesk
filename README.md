# Nodesk

HomeNet için hafif bir ağ topolojisi haritası. Kapsadığı yerler: iki ev (F1611A + home-pi, H3600P + home-router), Oracle Cloud ve tailnet. Pi'de çalışır ve CasaOS'ta "Nodesk" olarak görünür.

**Port taraması yapmaz. Pi hiçbir cihaza bağlanmaz:** uzaktaki cihazlar (router, sunucular) kendi verilerini 5 dakikada bir Tailscale/LAN üzerinden Pi'ye gönderir. Ajanlar yeni sürümü de Pi'den kendileri alır. Bir ajan bir kez kurulduktan sonra o cihaza SSH ile girmek gerekmez.

| Kaynak | Ne verir |
|---|---|
| `tailscale status` (Pi) | Tüm tailnet cihazları, doğrudan/aktarıcı bağlantı, exit node, subnet route'lar |
| ARP taraması (Pi, eth0) | F1611A arkasındaki cihazlar (~256 ARP paketi) |
| Pasif dinleme (Pi, eth0) | Ağa paket göndermeden ARP/DHCP/mDNS/SSDP dinler. Uyuyan telefonları ve cihazların kendi adlarını bulur ("Galaxy-S24", "Salon TV") |
| Pi'nin komşu tablosu | Pi'nin yakın zamanda konuştuğu cihazlar |
| Docker API (Pi) | Container'lar, CasaOS uygulama adları; compose uygulamaları gruplanır (örn. Orbis → frontend + backend) |
| `ss` (Pi) | Docker dışı servisler: CasaOS, Samba, SSH, VNC… |
| Router ajanı | Ev 2: DHCP kiraları, ARP tablosu, WAN tarafında H3600P ağı, aktif exit node |
| Sunucu ajanları | Oracle sunucularındaki container'lar ve servisler |

## Haritada yapılabilenler

- **Servisler ayrı düğümlerdir:** her servis kendi ikonuyla, çalıştığı cihazdan dallanır.
  - Çok container'lı uygulamalar (örn. Orbis → frontend, backend) ve Pi'nin sistem servisleri (CasaOS, Samba, SSH, VNC) açılıp kapanan gruplardır.
  - Durum ışığı: yeşil çalışıyor, sarı kısmen yanıt veriyor, kırmızı yanıt vermiyor, gri durdu. Sağlık kontrolü sadece Pi'nin kendi servis portlarına, Pi'nin içinden bakar.
  - İkonlar CasaOS'tan ya da açık bir ikon kütüphanesinden gelir. Pi onları bir kez indirir, böylece haritayı açan cihazın internete çıkması gerekmez. Kendi ikonunu servisi düzenleyerek verebilirsin.
  - Araç çubuğundaki **Servisler** düğmesi hepsini gizler/gösterir.

- **Bir karta tıkla → Düzenle.** Ad, tür, bağlı olduğu cihaz, etiketler, not, gizleme ve elle servis eklenebilir. Değişiklikler MAC adresine bağlı saklanır, IP değişse de kalır.
- **Servisler** kartta uygulamaya göre gruplanır. Grup başlığına tıklayınca açılır/kapanır. Paneldeki ✎ ile uygulama adı değiştirilir.
- **Ayarlar:**
  - otomatik tarama açık/kapalı, sıklık (1–60 dk), kaynakları tek tek açma/kapama, **Şimdi tara**
  - ajan ekleme/silme ve kurulum komutları
  - **güncelleme**
- **Grup adları:** grubun başlığına (Ev 1, Ev 2, Oracle Cloud…) tıklayınca hem grubu hem üstteki kartı adlandırabilirsin.
- **Gezgin cihazlar:** Laptop ya da telefon evlerden birinin ağına bağlanınca o evin altında görünür, ayrılınca "Uzak / Mobil"e döner. Bunu Tailscale'in bildirdiği yerel IP'yi ağda canlı görerek anlar; cihaz iki kez görünmez.
- **Extender arkası:** Keenetic gibi MAC-NAT yapan bir extender'ın arkasındaki cihazlar, extender'ın altında ayrı ayrı görünür. Gerçek MAC'i cihaz ağa yeniden bağlanınca (DHCP) öğrenilir; o zamana kadar mDNS adıyla ya da IP'siyle gösterilir.
- **Filtre:** grup, tür, etiket ve durum. Eşleşmeyenler soluklaşır.
- Arama (ad, IP, MAC, servis), Tailnet katmanı, açık/koyu tema, yakınlaştırma.

## İlk kurulum (bir kez)

**1. Pi:** Deploy anahtarını üret. Pi bu özel depoyu bu anahtarla sadece okuyabilir.

```bash
command -v git >/dev/null || sudo apt install -y git
sudo mkdir -p /DATA/AppData/nodesk/keys && sudo chmod 700 /DATA/AppData/nodesk/keys
sudo ssh-keygen -q -t ed25519 -N "" -C nodesk-deploy@home-pi -f /DATA/AppData/nodesk/keys/deploy_ed25519
sudo cat /DATA/AppData/nodesk/keys/deploy_ed25519.pub
```

**2. GitHub:** Çıkan satırı depo → Settings → Deploy keys → Add deploy key bölümüne ekle. "Allow write access" **işaretsiz** kalsın.

**3. Pi:** Klonla ve kur.

```bash
sudo git -c core.sshCommand="ssh -i /DATA/AppData/nodesk/keys/deploy_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" \
  clone git@github.com:Contraill/Nodesk.git /DATA/AppData/nodesk/app
sudo /DATA/AppData/nodesk/app/bin/nodesk install
```

**4. Laptop:** Router ajanını kur. Bu tek bir komut ve tekrar çalıştırmak güvenli. Mevcut cron satırlarına ve SSH anahtarlarına dokunmaz. Bu, router'a SSH ile girmen gereken tek seferdir; sonraki sürümleri ajan Pi'den kendisi alır.

```bash
ssh pi@100.64.0.1 sudo nodesk router-script | ssh root@100.64.0.2 sh
```

**5. Sunucular (isteğe bağlı):** Oracle sunucuları için Ayarlar → Ajanlar → Ekle, ya da Pi'de `sudo nodesk agent add cloud-arm`. Çıkan `curl … | sudo sh` komutunu o sunucuda çalıştır.

Harita: **http://100.64.0.1:8088**

## Güncelleme

Harita yeni sürümü 6 saatte bir denetler ve üstte bildirir. İki yolu var:

- Ayarlar → **Güncelle**
- Pi'de:

  ```bash
  sudo nodesk update      # değişiklikleri gösterir, uygular, servisi ve web'i yeniler
  sudo nodesk rollback    # sorun çıkarsa bir önceki sürüme döner (0.2.0 ve sonrası)
  ```

`config.toml`, haritada yapılan düzenlemeler, geçmiş ve anahtarlar güncellemede korunur. Ajanlar (router dahil) yeni sürümü bir sonraki raporlarında Pi'den kendileri alır. Bu davranış Ayarlar → Ajanlar bölümünden kapatılabilir. Sadece 0.3.0'dan eski bir router ajanı kendini güncelleyemez; harita bunu bildirir ve 4. adımın bir kez daha çalıştırılması yeter.

## Komutlar

| Komut | Ne yapar |
|---|---|
| `sudo nodesk status` | Sürüm, servis, web, ajanlar ve son tarama |
| `sudo nodesk run` | Şimdi tara |
| `sudo nodesk logs 50` | Son günlük satırları |
| `sudo nodesk agent add <ad>` / `list` / `remove <ad>` | Sunucu ajanları |
| `sudo nodesk router-script` | Router ajanı kurulum scripti (4. adım) |
| `sudo nodesk install` | Kurulumu onarır (tekrar çalıştırmak güvenli) |
| `sudo nodesk uninstall` | Servisi ve web uygulamasını kaldırır; veri klasörünü silmez |

## Pi'deki klasör düzeni (`/DATA/AppData/nodesk`)

```
app/              bu depo (git). Elle değiştirme; güncelleme bunu yeniler
config.toml       temel ayarlar ve cihaz adları (güncellemede dokunulmaz)
data/
  overrides.json  haritada yapılan düzenlemeler (config.toml'u ezer)
  settings.json   tarama ayarları (haritadan değişir)
  agents.json     ajanlar ve anahtarları
  agents/         ajanların son raporları
  passive.json    pasif dinlemede öğrenilenler
  state.json      ilk/son görülme zamanları
keys/             deploy_ed25519 (GitHub, salt okunur)
www/              data.json (web arayüzü /live/ altından okur)
```

Çalışan parçalar şunlar:

- `nodesk.service`: root olarak çalışan Python servisi. Zamanlayıcı, toplayıcı ve pasif dinleyici bunun içinde. API sadece 127.0.0.1:8089'da dinler.
- `nodesk-web` container'ı: nginx (host ağı, 8088). Haritayı sunar ve `/api/` isteklerini servise iletir.

CasaOS uygulama kimliği bilerek `nodesk-web`. CasaOS'tan kaldırılsa bile veri klasörü silinmez.

## Geliştirme

```bash
tests/run.sh              # birim + API + script testleri (gerçek çıktılardan alınmış örneklerle)
tests/run.sh --preview    # + http://localhost:8099 üzerinde örnek verili önizleme
```

Sürüm yükseltirken `VERSION` dosyasını artır. Router scripti değiştiyse `router/topo-collect` içindeki `TOPO_VERSION` değerini de artır.
