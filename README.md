# UrlCrawler

Bu uygulama, verilen bir URL için çeşitli güvenlik tarama işlemlerini gerçekleştiren Go tabanlı bir web aracıdır. Aşağıdaki tarama türlerini entegre bir şekilde çalıştırır:

- **Nmap**: Belirli açık portlar üzerinde aktif tarama yapma.
- **Assetfinder**: Verilen alan adı için alt alan adlarını (subdomains) tarama.
- **Nuclei**: Nuclei tarama şablonlarını kullanarak zafiyet taraması gerçekleştirme.

---

## Proje Geçmişi / Background

Bu proje, yazarın staj döneminde (AI kod asistanlarının yaygınlaşmadığı bir dönemde) geliştirilmiştir. Web tabanlı bir arayüz üzerinden güvenlik araçlarını (Nmap, Nuclei, Assetfinder) yönetmeyi amaçlayan bu çalışma, daha sonra geliştirilen çok daha kapsamlı ve profesyonel bir External Attack Surface Management platformu olan **Mangudai ASM** projesinin ilk tohumlarını atmış ve temel ilham kaynağı olmuştur.

---

## Gereksinimler

Bu uygulamayı çalıştırmak için sisteminizde aşağıdaki yazılım ve araçların kurulu ve ortam değişkenlerinde (PATH) tanımlı olması gereklidir:

- Go Dil Ortamı (1.18+)
- **Nmap**: Port taraması için
- **Assetfinder**: Alt alan adlarını keşfetmek için
- **Nuclei**: Zafiyet taraması yapmak için

---

## Kullanım

Uygulamayı yerelinizde başlatmak için:

1. Bağımlılıkları yükleyin ve projeyi derleyin:
   ```bash
   go build -o UrlCrawler
   ```

2. Uygulamayı çalıştırın:
   ```bash
   ./UrlCrawler
   ```

3. Web tarayıcınızdan **`http://localhost:8000`** adresine giderek arayüz üzerinden taramaları başlatabilirsiniz.

---

## Katkıda Bulunma

Projeye katkıda bulunmak isterseniz, lütfen bir Pull Request gönderin veya Issue açın. Katkılarınızı memnuniyetle karşılıyoruz!

---

## İletişim

Sorularınız ve geri bildirimleriniz için:
- **E-posta**: bilge.oktay.944@gmail.com
- **GitHub**: [@oktaybilge1](https://github.com/oktaybilge1)
