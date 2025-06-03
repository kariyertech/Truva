<div align="center">

# 🏛️ Truva

**Modern Kubernetes Geliştirme ve İzleme Platformu**

[![Go Sürümü](https://img.shields.io/badge/Go-1.19+-00ADD8?style=for-the-badge&logo=go)](https://golang.org/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.20+-326CE5?style=for-the-badge&logo=kubernetes)](https://kubernetes.io/)
[![Lisans](https://img.shields.io/badge/Lisans-MIT-green?style=for-the-badge)](LICENSE)
[![Build Durumu](https://img.shields.io/badge/Build-Başarılı-brightgreen?style=for-the-badge)]()

[🇺🇸 English](./README.md) | [🇹🇷 Türkçe](./README.tr.md)

*Gerçek zamanlı dosya senkronizasyonu, süreç yönetimi ve kapsamlı izleme yetenekleri ile Kubernetes geliştirme iş akışınızı kolaylaştırın.*

</div>

---

## 🚀 Genel Bakış

Truva, modern Kubernetes geliştirme iş akışları için tasarlanmış güçlü, kurumsal düzeyde bir CLI aracı ve web platformudur. Geliştirici verimliliğini ve operasyonel görünürlüğü artıran sorunsuz dosya senkronizasyonu, akıllı süreç yönetimi ve gerçek zamanlı izleme yetenekleri sağlar.

### 🎯 Neden Truva?

- **🔄 Anında Geliştirme**: Konteyner yeniden oluşturmadan kod değişikliklerini çalışan pod'lara anında senkronize edin
- **📊 Gerçek Zamanlı İzleme**: Canlı log akışı ve metriklerle kapsamlı gözlemlenebilirlik
- **🛡️ Üretime Hazır**: Kurumsal düzeyde güvenlik, güvenilirlik ve performans
- **🎨 Modern Arayüz**: İzleme ve yönetim için güzel, duyarlı web arayüzü
- **⚡ Yüksek Performans**: Minimal ek yük ile büyük ölçekli dağıtımlar için optimize edilmiş

## ✨ Özellikler

### 🔧 Temel Yetenekler

- **🔄 Akıllı Dosya Senkronizasyonu**
  - Debounce mekanizmaları ile gerçek zamanlı dosya izleme
  - Optimal performans için toplu işleme
  - Desen eşleştirme ile seçici senkronizasyon
  - Çakışma çözümü ve geri alma yetenekleri

- **🔄 Süreç Yaşam Döngüsü Yönetimi**
  - Sıfır kesinti süresi ile zarif süreç yeniden başlatmaları
  - Sağlık kontrolleri ve otomatik kurtarma
  - Özel yeniden başlatma stratejileri ve politikaları
  - Kaynak kullanım optimizasyonu

- **📊 Gelişmiş İzleme ve Gözlemlenebilirlik**
  - WebSocket teknolojisi ile gerçek zamanlı log akışı
  - Çoklu pod log toplama ve filtreleme
  - Performans metrikleri ve kaynak izleme
  - Özel panolar ve uyarı sistemi

- **🛡️ Güvenlik ve Uyumluluk**
  - Tüm iletişimler için TLS/HTTPS şifreleme
  - Kubernetes ile RBAC entegrasyonu
  - Denetim günlüğü ve uyumluluk raporlama
  - Gizli bilgi yönetimi ve kimlik bilgisi işleme

- **🎨 Modern Web Arayüzü**
  - Masaüstü ve mobil için duyarlı tasarım
  - Koyu/açık tema desteği
  - Sayfa yenileme olmadan gerçek zamanlı güncellemeler
  - Özelleştirilebilir düzenler ve tercihler

### 🏗️ Mimari Bileşenler

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI İstemci   │────│  Truva Sunucu   │────│ Kubernetes API  │
│                 │    │                 │    │                 │
│ • Dosya İzleme  │    │ • Sync Motoru   │    │ • Pod Yönetimi  │
│ • Yerel Değişik.│    │ • Web Arayüzü   │    │ • Log Akışı     │
│ • Yapılandırma  │    │ • WebSocket Hub │    │ • Sağlık Kontrol│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### 📁 Proje Yapısı

- **`cmd/`** - CLI uygulama giriş noktaları ve komut tanımları
- **`internal/k8s/`** - Kubernetes istemci işlemleri ve kaynak yönetimi
- **`internal/sync/`** - Dosya senkronizasyon motoru ve süreç yönetimi
- **`internal/ui/`** - Web sunucu, WebSocket işleyicileri ve UI mantığı
- **`pkg/api/`** - REST API uç noktaları ve rota tanımları
- **`pkg/auth/`** - Kimlik doğrulama ve yetkilendirme ara yazılımı
- **`pkg/config/`** - Yapılandırma yönetimi ve özellik bayrakları
- **`pkg/memory/`** - Bellek izleme ve sızıntı tespiti
- **`pkg/utils/`** - Paylaşılan yardımcı programlar ve yardımcı işlevler
- **`security-tests/`** - Güvenlik tarama ve penetrasyon testleri
- **`deployments/`** - Kubernetes manifestleri ve Helm grafikleri

## 🛠️ Kurulum

### Ön Koşullar

- **Go 1.19+** - [İndir](https://golang.org/dl/)
- **Kubernetes 1.20+** - Yerel küme veya bulut sağlayıcısı
- **kubectl** - [Kurulum Kılavuzu](https://kubernetes.io/docs/tasks/tools/)
- **Docker** (isteğe bağlı) - Konteynerleştirilmiş dağıtım için

### Hızlı Başlangıç

#### 1. Kaynaktan Kurulum

```bash
# Depoyu klonlayın
git clone https://github.com/kariyertech/Truva.git
cd Truva

# Uygulamayı derleyin
go build -o truva cmd/main.go

# Çalıştırılabilir yapın
chmod +x truva

# PATH'e taşıyın (isteğe bağlı)
sudo mv truva /usr/local/bin/
```

#### 2. Docker Kullanarak

```bash
# En son imajı çekin
docker pull truva:latest

# Docker ile çalıştırın
docker run -it --rm \
  -v ~/.kube:/root/.kube \
  -v $(pwd):/workspace \
  truva:latest
```

#### 3. Helm Kullanarak

```bash
# Truva Helm deposunu ekleyin
helm repo add truva https://charts.truva.dev
helm repo update

# Truva'yı kurun
helm install truva truva/truva \
  --namespace truva-system \
  --create-namespace
```

## 🚀 Kullanım

### Temel Komutlar

```bash
# Dosya senkronizasyonu ile geliştirme modunu başlatın
truva up --namespace myapp \
         --target-type deployment \
         --target-name myapp-deployment \
         --local-path ./src \
         --container-path /app/src

# Gerçek zamanlı log izleme
truva logs --namespace myapp --follow

# Sağlık kontrolü
truva health --namespace myapp

# Yapılandırma yönetimi
truva config set sync.debounce-duration 2s
truva config get
```

### Gelişmiş Yapılandırma

```yaml
# config.yaml
api:
  port: 8080
  tls:
    enabled: true
    cert-file: "/etc/certs/tls.crt"
    key-file: "/etc/certs/tls.key"

sync:
  debounce-duration: "2s"
  batch-size: 100
  exclude-patterns:
    - "*.tmp"
    - ".git/*"
    - "node_modules/*"

monitoring:
  metrics-enabled: true
  log-level: "info"
  health-check-interval: "30s"

security:
  rbac-enabled: true
  audit-logging: true
```

### Web Arayüzü

Truva'yı başlattıktan sonra `https://localhost:8080` adresinden web arayüzüne erişin:

- **📊 Panel** - Tüm izlenen uygulamaların genel görünümü
- **📝 Loglar** - Filtreleme ile gerçek zamanlı log akışı
- **⚙️ Ayarlar** - Yapılandırma yönetimi
- **🔍 Metrikler** - Performans ve kaynak izleme

## 🧪 Geliştirme

### Testleri Çalıştırma

```bash
# Tüm testleri çalıştır
make test

# Belirli test paketlerini çalıştır
make test-unit
make test-integration
make test-e2e
make test-security

# Kapsam raporu oluştur
make coverage
```

### Derleme

```bash
# Mevcut platform için derle
make build

# Tüm platformlar için derle
make build-all

# Docker imajı oluştur
make docker-build

# Derle ve yayınla
make docker-push
```

### Katkıda Bulunma

Katkılarınızı memnuniyetle karşılıyoruz! Ayrıntılar için [Katkı Kılavuzumuza](CONTRIBUTING.md) bakın.

## 📊 Performans ve Ölçeklenebilirlik

- **🚀 Yüksek Verim**: Saniyede 1000+ dosya değişikliğini işler
- **📈 Ölçeklenebilir**: 100+ düğüm ve 1000+ pod'lu kümeleri destekler
- **💾 Bellek Verimli**: Örnek başına < 50MB bellek ayak izi
- **⚡ Düşük Gecikme**: Küçük dosyalar için < 100ms senkronizasyon gecikmesi

## 🛡️ Güvenlik

- **🔐 Uçtan Uca Şifreleme**: Tüm iletişimler TLS 1.3 ile şifrelenir
- **🎫 RBAC Entegrasyonu**: Yerel Kubernetes RBAC desteği
- **🔍 Güvenlik Tarama**: Otomatik güvenlik açığı değerlendirmeleri
- **📋 Uyumluluk**: SOC 2, GDPR ve HIPAA hazır

## 🗺️ Yol Haritası

### 🎯 Mevcut Odak (v1.0)
- [ ] Çoklu küme desteği
- [ ] Gelişmiş filtreleme ve arama
- [ ] Genişletilebilirlik için eklenti sistemi
- [ ] Performans optimizasyonları

### 🔮 Gelecek Planları (v2.0+)
- [ ] AI destekli anomali tespiti
- [ ] GitOps entegrasyonu
- [ ] Service mesh desteği
- [ ] Mobil uygulama
- [ ] Gelişmiş analitik ve raporlama
- [ ] Çok kiracılık desteği
- [ ] Felaket kurtarma özellikleri
- [ ] Maliyet optimizasyon öngörüleri

## 📚 Dokümantasyon

- [📖 Kullanıcı Kılavuzu](docs/README.md)
- [🏗️ Mimari](docs/ARCHITECTURE.md)
- [🔧 API Referansı](docs/API.md)
- [🛡️ Güvenlik Kılavuzu](docs/SECURITY.md)
- [🚀 Üretim Dağıtımı](docs/PRODUCTION.md)
- [🔍 Sorun Giderme](docs/TROUBLESHOOTING.md)

## 🤝 Topluluk ve Destek

- **💬 Tartışmalar**: [GitHub Tartışmaları](https://github.com/kariyertech/Truva/discussions)
- **🐛 Hata Raporları**: [GitHub Issues](https://github.com/kariyertech/Truva/issues)
- **📧 E-posta**: support@truva.dev
- **💼 Kurumsal**: enterprise@truva.dev

## 📄 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır - ayrıntılar için [LICENSE](LICENSE) dosyasına bakın.

## 🙏 Teşekkürler

- Harika ekosistem için Kubernetes topluluğu
- Mükemmel araçlar için Go topluluğu
- Bu projeyi mümkün kılan tüm katkıda bulunanlar

---

<div align="center">

**Truva Ekibi tarafından ❤️ ile yapıldı**

[⭐ GitHub'da yıldızlayın](https://github.com/kariyertech/Truva) | [🐦 Twitter'da takip edin](https://twitter.com/truvadev) | [💼 LinkedIn](https://linkedin.com/company/truva)

</div>
