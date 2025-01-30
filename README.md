# Subdomain Scanner - Gelişmiş Subdomain Keşif Aracı

Bu araç, hem aktif hem de pasif yöntemler kullanarak subdomain'leri keşfeder ve doğrular. Özellikle sızma testi (pentesting) ve güvenlik araştırmaları için faydalıdır. Kullanıcı dostu bir komut satırı arayüzü sunarak, hedef domain üzerinde hızlı bir şekilde subdomain keşfi yapmanızı sağlar.

## Özellikler

- **Aktif Tarama**: Verilen bir domain için potansiyel subdomain'leri kontrol eder.
- **Pasif Tarama**: Harici veri kaynakları (örneğin, crt.sh) kullanarak subdomain'leri keşfeder.
- **DNS Sorguları**: Farklı DNS kayıt türlerini (A, CNAME, MX, NS, TXT, SRV) sorgular.
- **Subdomain Doğrulama**: Keşfedilen subdomain'lerin geçerliliğini kontrol eder, IP adreslerini ve HTTP/SSL bilgilerini alır.
- **Çoklu DNS Sunucuları**: Google, Cloudflare, Quad9 gibi popüler DNS sunucularını kullanır.
- **Hızlı ve Verimli Tarama**: Tarama hızını kontrol etme imkanı sunar (1-5 arası).
- **Çıktı Formatları**: JSON ve CSV formatında çıktı alabilirsiniz.

## Kurulum

### Gereksinimler

Projenin çalışabilmesi için aşağıdaki Python paketlerinin yüklü olması gerekir:

- `aiohttp` - Asenkron HTTP istekleri için
- `requests` - HTTP istekleri için
- `tqdm` - İlerleme çubuğu için
- `beautifulsoup4` - HTML parse işlemleri için
- `dnspython` - DNS çözümlemeleri için

### Bağımlılıkları Yüklemek

Projenin bağımlılıklarını yüklemek için aşağıdaki komutu kullanabilirsiniz:


pip install -r requirements.txt
Wordlist
Aktif tarama için bir wordlist gereklidir. wordlist_path parametresi ile özel bir wordlist belirleyebilirsiniz. Örnek olarak, "wordlists/subdomains.txt" yolunda bir dosya kullanılır. Bu wordlist, potansiyel subdomain'leri içermelidir.

Başlatma
Tarama başlatmak için aşağıdaki komutları kullanabilirsiniz:

bash
Kopyala
Düzenle
python main.py hedef-domain.com -w wordlist.txt -o json -t 3
Parametreler
domain: Hedef domain (zorunlu)
-w / --wordlist: Kendi belirlediğiniz özel wordlist dosyası (isteğe bağlı)
-o / --output: Çıktı formatı (json veya csv, varsayılan: json)
-t / --threads: Tarama hızı (1-5 arası, varsayılan: 3)
Çıktı
Tarama sonuçları JSON veya CSV formatında kaydedilebilir. Çıktı, bulunan subdomain'ler, IP adresleri, HTTP yanıt durumu, sunucu bilgileri ve SSL sertifikası bilgileri içerir.

JSON Örneği:
json
Kopyala
Düzenle
[
  {
    "subdomain": "www.hedef-domain.com",
    "ip_addresses": ["93.184.216.34"],
    "http_status": 200,
    "server": "Apache",
    "title": "Hedef Domain",
    "ssl_valid": true,
    "ssl_issuer": "Let's Encrypt",
    "ssl_expiry": "2025-06-15"
  }
]
CSV Örneği:
vbnet
Kopyala
Düzenle
subdomain,ip_addresses,http_status,server,title,ssl_valid,ssl_issuer,ssl_expiry
www.hedef-domain.com,93.184.216.34,200,Apache,Hedef Domain,true,Let's Encrypt,2025-06-15
Nasıl Çalışır?
Pasif Tarama: crt.sh gibi açık kaynaklardan subdomain'leri keşfeder.
Aktif Tarama: Verilen wordlist'e dayalı olarak subdomain'leri doğrular.
DNS Sorguları: Çeşitli DNS sunucularını kullanarak domain bilgilerini toplar.
Doğrulama: Keşfedilen subdomain'lerin aktif olup olmadığını doğrular, IP adreslerini, HTTP durumu, sunucu bilgilerini ve SSL sertifikası bilgilerini toplar.
Kullanıcı Örnekleri
Basit Kullanım
Subdomain taraması başlatmak için:

bash
Kopyala
Düzenle
python main.py hedef-domain.com
Kendi Wordlist'inizi Kullanma
bash
Kopyala
Düzenle
python main.py hedef-domain.com -w /path/to/your/wordlist.txt
Sonuçları CSV Olarak Kaydetme
bash
Kopyala
Düzenle
python main.py hedef-domain.com -o csv
Katkıda Bulunma
Eğer projeye katkıda bulunmak isterseniz, lütfen aşağıdaki adımları izleyin:

Bu repoyu çatallayın (fork).
Yeni bir dal oluşturun (branch).
Yaptığınız değişiklikleri commit'leyin.
Pull request gönderin.
Lisans
Bu proje MIT Lisansı ile lisanslanmıştır. Detaylar için LICENSE dosyasına bakabilirsiniz.

Not: Bu araç yalnızca etik ve yasal amaçlarla kullanılmalıdır. Hedeflerinizi taramadan önce izin almanız gerekmektedir.

css
Kopyala
Düzenle

Bu içeriği, aracın kullanımını, özelliklerini, nasıl kurulacağını ve çalıştırılacağını açıkça
