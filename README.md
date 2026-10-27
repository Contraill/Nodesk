# Nodesk

HomeNet için hafif ağ topolojisi haritası: iki ev (F1611A + home-pi, H3600P + home-router), Oracle Cloud ve tailnet. Pi'de çalışır, CasaOS'ta "Nodesk" uygulaması olarak görünür. **Port taraması yapmaz.**

| Kaynak | Ne verir |
|---|---|
| `tailscale status --json` (Pi) | Tüm tailnet cihazları, doğrudan/aktarıcı bağlantı, exit node, subnet route'lar |
| `arp-scan` eth0 (Pi) | F1611A arkasındaki cihazlar (~256 ARP paketi) |
| `docker ps` (Pi) | Pi'deki servisler ve portları |
| `topo-collect` (router, salt okunur) | DHCP kiraları, ARP tablosu, WAN tarafından H3600P ağı, aktif exit node |

## İlk kurulum (bir kez)

**1. Pi:** Deploy anahtarını üret. Bu anahtar Pi'nin bu özel depoyu sadece okuyabilmesi için.

```bash
command -v git >/dev/null || sudo apt install -y git
sudo mkdir -p /DATA/AppData/nodesk/keys && sudo chmod 700 /DATA/AppData/nodesk/keys
sudo ssh-keygen -q -t ed25519 -N "" -C nodesk-deploy@home-pi -f /DATA/AppData/nodesk/keys/deploy_ed25519
sudo cat /DATA/AppData/nodesk/keys/deploy_ed25519.pub
```

**2. GitHub:** Çıkan satırı ekle: depo → Settings → Deploy keys → Add deploy key. "Allow write access" **işaretsiz** kalsın.

**3. Pi:** Klonla ve kur.

```bash
sudo git -c core.sshCommand="ssh -i /DATA/AppData/nodesk/keys/deploy_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" \
  clone git@github.com:Contraill/Nodesk.git /DATA/AppData/nodesk/app
sudo /DATA/AppData/nodesk/app/bin/nodesk install
```

**4. Laptop:** Router'ı ayarla. Tek komut; tekrar çalıştırmak güvenli. Mevcut anahtarlara dokunmaz, sadece bir satır ekler.

```bash
ssh pi@100.64.0.1 sudo nodesk router-script | ssh root@100.64.0.2 sh
```

**5. Pi:** `sudo nodesk run`, ardından haritayı aç: **http://100.64.0.1:8088**

## Güncelleme

Harita yeni sürüm olduğunda üstte bildirir (6 saatte bir kontrol eder). Güncellemek için:

```bash
sudo nodesk update      # değişiklikleri gösterir, uygular, gerekirse CasaOS uygulamasını yeniler
sudo nodesk rollback    # sorun çıkarsa bir önceki sürüme döner
```

`config.toml`, cihaz adları, geçmiş ve anahtarlar güncellemede korunur. Router scripti değişirse harita uyarır; o zaman 4. adımdaki komutu tekrar çalıştır.

## Komutlar

| Komut | Ne yapar |
|---|---|
| `sudo nodesk status` | Sürüm, zamanlayıcı, web, router ve son toplama durumu |
| `sudo nodesk run` | Şimdi topla |
| `sudo nodesk logs 50` | Son günlük satırları |
| `sudo nodesk install` | Kurulumu onarır (tekrar çalıştırmak güvenli) |
| `sudo nodesk uninstall` | Zamanlayıcıyı ve web uygulamasını kaldırır; veri klasörünü silmez |

## Pi'deki klasör düzeni (`/DATA/AppData/nodesk`)

```
app/          bu depo (git). Elle değiştirme; güncelleme bunu yeniler
config.toml   ayarlar ve cihaz adları (MAC'e göre). Güncellemede dokunulmaz
data/         state.json (son görülme), known_hosts, güncelleme bilgisi
keys/         deploy_ed25519 (GitHub, salt okunur), router_ed25519 (router, sadece topo-collect)
www/          data.json (web arayüzü /live/ altından okur)
```

CasaOS'taki uygulama kimliği bilerek `nodesk-web`. CasaOS'tan kaldırılsa bile bu klasör silinmez.

## Geliştirme

```bash
tests/run.sh            # toplayıcıyı gerçek çıktılardan alınmış örneklerle çalıştırır ve doğrular
tests/run.sh --serve    # + http://localhost:8099 önizleme
```

Sürüm yükseltirken `VERSION` dosyasını artır. Router scriptinde değişiklik varsa `router/topo-collect` içindeki `TOPO_VERSION` değerini de artır.
