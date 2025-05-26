[English](./README.md)

# Truva (Türkçe)

Truva, Kubernetes dağıtımlarını ve pod'larını yönetmek için tasarlanmış, günlükleri gerçek zamanlı olarak izlemek için yerleşik bir kullanıcı arayüzüne sahip bir CLI aracıdır. Araç, dosyaların yerel makineden Kubernetes pod'larına senkronize edilmesini, işlemlerin yeniden başlatılmasını ve tüm pod'ların günlüklerinin dinamik olarak bir web arayüzünde görüntülenmesini sağlar.

## Özellikler

- **Dosya Senkronizasyonu**: Yerel dosyaları hedef Kubernetes dağıtımına veya pod'una senkronize edin.
- **İşlem Yeniden Başlatma**: Dosya senkronizasyonundan sonra Kubernetes pod'larındaki işlemleri otomatik olarak yeniden başlatın.
- **Dinamik Günlük İzleme**: Her pod'un günlüklerini web tabanlı bir arayüz aracılığıyla gerçek zamanlı olarak izleyin.
- **WebSocket Entegrasyonu**: Günlükler, WebSocket bağlantıları kullanılarak gerçek zamanlı olarak yayınlanır.
- **Çoklu Pod Desteği**: Her pod'u ayrı ayrı izlemek için dinamik olarak düğmeler oluşturan çoklu pod'lu dağıtımları destekler.

### Ana Bileşenler:

- `cmd`: Ana uygulama mantığını ve CLI komutlarını içerir.
- `internal/k8s`: Dağıtımların yedeklenmesi, değiştirilmesi ve geri yüklenmesi gibi Kubernetes ile ilgili işlemleri yönetir.
- `internal/sync`: Dosyaların Kubernetes pod'larına senkronize edilmesinden ve işlemlerin yeniden başlatılmasından sorumludur.
- `internal/ui`: Gerçek zamanlı günlük akışı için web sunucusunu ve WebSocket mantığını yönetir.
- `pkg/api`: Senkronizasyon ve günlük yönetimi için API rotaları.
- `pkg/utils`: Dosya izleme ve günlük kaydı gibi yardımcı işlevler.
- `templates/index.html`: Pod günlüklerini görüntülemek için web arayüzünü çalıştıran HTML dosyası.

## Başlarken

### Ön Koşullar

- Kubernetes küme erişimi
- `kubectl` komut satırı aracının kurulu ve yapılandırılmış olması
- YQ ve JQ Araçları

## Örnek Kullanım

```bash
go run main.go up --namespace <ad_alanı> --targetType deployment --targetName <dağıtım_adı> --localPath <yerel_dosyaların_yolu> --containerPath <pod_içindeki_konteyner_yolu>
```
