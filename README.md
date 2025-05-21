# QR Link Shield

QR Link Shield, QR kodları ve URL'leri güvenlik açısından analiz eden bir API servisidir. Bu uygulama, kullanıcıların QR kodlarını ve URL'lerini güvenli bir şekilde kontrol etmelerini sağlar.

## Özellikler

- QR kod tarama ve analiz
- URL güvenlik kontrolü
- Çoklu güvenlik servisi entegrasyonu:
  - VirusTotal
  - Google Safe Browsing
  - PhishTank
  - AbuseIPDB
  - URLScan
  - URLhaus
  - ThreatFox
  - Spamhaus
  - Cisco Talos
- Zararlı URL'lerin veritabanında saklanması
- RESTful API endpoints

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/kullaniciadi/qrlinkshield.git
cd qrlinkshield
```

2. Sanal ortam oluşturun ve aktifleştirin:
```bash
python -m venv h_env
# Windows için:
h_env\Scripts\activate
# Linux/Mac için:
source h_env/bin/activate
```

3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

4. Uygulamayı çalıştırın:
```bash
uvicorn main:app --reload
```

## API Endpoints

### QR Kod Tarama
```
POST /scan-qr
```
QR kod içeren bir resim dosyası yükleyerek güvenlik analizi yapar.

### URL Tarama
```
POST /scan-url
```
URL'yi güvenlik açısından analiz eder.

### Hızlı Güvenlik Kontrolü
```
POST /fast-check
```
URL'nin hızlı bir güvenlik kontrolünü yapar.

### Zararlı URL Listesi
```
GET /malicious-urls
```
Veritabanında kayıtlı zararlı URL'lerin listesini döndürür.

## Güvenlik Özellikleri

- SSL sertifika kontrolü
- WHOIS bilgisi kontrolü
- Phishing kontrolü
- IP adresi kontrolü
- Kötüye kullanım skoru analizi
- Zararlı yazılım tespiti
- Spam kontrolü

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.
