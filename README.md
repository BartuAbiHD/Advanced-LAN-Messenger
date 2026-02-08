# 🚀 Advanced LAN Messenger

Modern ve özellik dolu bir yerel ağ mesajlaşma uygulaması.

## ✨ Özellikler

### 💬 Mesajlaşma
- Gerçek zamanlı metin mesajlaşması
- Emoji desteği
- Zaman damgası ile mesaj geçmişi
- Kullanıcı adı özelleştirme

### 🎵 Sesli Konuşma
- Gerçek zamanlı ses kaydı ve aktarımı
- Ses giriş/çıkış cihazı seçimi
- Ses seviyesi kontrolü
- Yüksek kaliteli ses aktarımı

### 🎨 Modern Arayüz
- Dark/Light tema desteği
- Responsive tasarım (her ekran çözünürlüğüne uyumlu)
- CustomTkinter ile modern görünüm
- Kullanıcı dostu arayüz

### 🌐 Ağ Özellikleri
- Sunucu/İstemci mimarisi
- Çoklu kullanıcı desteği
- Anlık bağlı kullanıcı listesi
- Otomatik IP adresi tespiti

### 📁 Dosya Paylaşımı
- Dosya gönderme/alma
- **Drag & Drop** (Sürükle ve Bırak) desteği
- İlerleme bildirimi
- Otomatik "Downloads" klasörüne kaydetme

### 🔒 Güvenlik
- **Uçtan Uca Şifreleme**: RSA + AES256 ile tam güvenlik
- Güvenli Handshake protokolü

## 🛠️ Kurulum

### Gereksinimler
- Python 3.7+
- Ses kartı (mikrofon ve hoparlör)

### Bağımlılıklar
```bash
pip install customtkinter
pip install pyaudio
pip install Pillow
pip install tkinterdnd2
```

### Çalıştırma
```bash
python LANMessenger.py
```

## 📖 Kullanım Kılavuzu

### 1. Sunucu Başlatma
1. **Kullanıcı Adı**: İstediğiniz kullanıcı adını girin
2. **IP Adresi**: Otomatik olarak yerel IP algılanır
3. **Port**: Varsayılan 3939 portu kullanılır
4. **"Sunucu Başlat"** butonuna tıklayın
5. Diğer kullanıcıların bağlanmasını bekleyin

### 2. Sunucuya Bağlanma
1. **Kullanıcı Adı**: İstediğiniz kullanıcı adını girin
2. **IP Adresi**: Sunucunun IP adresini girin
3. **Port**: Sunucunun portunu girin (varsayılan: 3939)
4. **"Bağlan"** butonuna tıklayın

### 3. Mesajlaşma
- Alt kısımdaki metin kutusuna mesajınızı yazın
- Enter tuşuna basın veya "Gönder" butonuna tıklayın
- Emoji eklemek için 😀 butonunu kullanın

### 4. Sesli Konuşma
1. **Ses Cihazları**: Sağ panelden mikrofon ve hoparlör seçin
2. **Ses Kaydı**: 🎤 butonuna basıp konuşun, tekrar basıp durdurun
3. **Ses Seviyesi**: Slider ile ses seviyesini ayarlayın

### 5. Tema Değiştirme
- Sağ panelden "dark" veya "light" tema seçebilirsiniz

## 🏗️ Teknik Detaylar

### Mimari
- **GUI Framework**: CustomTkinter (modern tkinter)
- **Ağ İletişimi**: TCP Socket programlama
- **Ses İşleme**: PyAudio
- **Çoklu İşlem**: Threading
- **Veri Formatı**: JSON

### Ses Özellikleri
- **Format**: 16-bit PCM
- **Örnekleme Hızı**: 44,100 Hz
- **Kanal**: Mono (tek kanal)
- **Buffer Boyutu**: 1024 frame

### Ağ Protokolü
```json
{
    "type": "text|voice|user_join|user_leave",
    "username": "kullanıcı_adı",
    "content": "mesaj_içeriği",
    "timestamp": "2025-08-24T10:30:00"
}
```

## 🔧 Yapılandırma

### Varsayılan Ayarlar
- **Port**: 3939
- **Ses Format**: 16-bit PCM, 44.1kHz, Mono
- **Buffer**: 1024 frame
- **Tema**: Dark
- **Ses Seviyesi**: %75

### Özelleştirme
Kod içerisinde şu parametreleri değiştirebilirsiniz:
- `self.rate = 44100` - Örnekleme hızı
- `self.chunk = 1024` - Buffer boyutu
- `self.channels = 1` - Kanal sayısı

## 🚨 Sorun Giderme

### Ses Sorunları
- **Mikrofon çalışmıyor**: Ses cihazlarını kontrol edin
- **Ses gelmiyor**: Hoparlör ayarlarını kontrol edin
- **Gecikme var**: Buffer boyutunu küçültün

### Bağlantı Sorunları
- **Sunucu başlatılamıyor**: Port kullanımda olabilir
- **Bağlantı kurulamıyor**: IP adresi ve port kontrolü
- **Güvenlik duvarı**: Windows Firewall ayarlarını kontrol edin

### Genel Sorunlar
- **Uygulama açılmıyor**: Python ve kütüphane kurulumlarını kontrol edin
- **Tema değişmiyor**: Uygulamayı yeniden başlatın

## 🔒 Güvenlik

- Uygulama sadece yerel ağda çalışır
- **Uçtan Uca Şifreleme** (End-to-End Encryption) mevcuttur
- Güvenlik duvarı ayarlarını kontrol edin

## 🎯 Gelecek Özellikler

- [x] Kullanıcı listesi
- [x] Dosya gönderme/alma
- [x] Sistem tepsisi desteği
- [x] Mesaj şifreleme
- [x] Grup sohbetleri
- [x] Profil fotoğrafları
- [x] Mesaj geçmişi kaydetme
- [x] Bildirim sistemi
- [x] Çoklu dil desteği

## 📝 Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Özgürce kullanabilir ve geliştirebilirsiniz.

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'i push edin (`git push origin feature/AmazingFeature`)
5. Pull Request açın

## 📞 İletişim

Sorularınız için GitHub Issues kullanabilirsiniz.

---

⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!
