import tkinter as tk
from tkinter import ttk, messagebox, filedialog, font
import customtkinter as ctk
from tkinterdnd2 import TkinterDnD, DND_FILES
import socket
import threading
import json
import datetime
try:
    import pyaudio
except ImportError:
    pyaudio = None
    print("Warning: The PyAudio module could not be found. Audio features will be disabled.")


import winsound
import wave
import io
import os
import winreg # Windows Registry
import sys
import base64
from PIL import Image, ImageTk, ImageDraw
import time
import locale
import struct
from pathlib import Path
import pystray
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import urllib.request
import subprocess

# Sürüm ve Güncelleme Sabitleri
VERSION = "1.0.0"
UPDATE_URL = "https://raw.githubusercontent.com/username/repo/main/version.txt" # GÜNCELLEYİN
EXE_URL = "https://github.com/username/repo/releases/latest/download/LANMessenger.exe" # GÜNCELLEYİN

# Modern tema ayarları
ctk.set_appearance_mode("dark")  # "light" veya "dark"
ctk.set_default_color_theme("blue")  # "blue", "green", "dark-blue"

class EncryptionManager:
    def __init__(self):
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.generate_rsa_keys()
        
    def generate_rsa_keys(self):
        """RSA anahtar çifti oluştur"""
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()
        
    def get_public_key_pem(self):
        """Public key'i PEM formatında al"""
        pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
        
    def decrypt_rsa(self, encrypted_data):
        """RSA ile şifre çöz"""
        return self.rsa_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
    def encrypt_rsa(self, public_key_pem, data):
        """Verilen public key ile şifrele"""
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
    def generate_aes_key(self):
        """AES (Fernet) anahtarı oluştur"""
        return Fernet.generate_key()
        
    def encrypt_aes(self, key, data):
        """AES (Fernet) ile şifrele"""
        f = Fernet(key)
        # Veri string ise bytes'a çevir
        if isinstance(data, str):
            data = data.encode('utf-8')
        return f.encrypt(data)
        
    def decrypt_aes(self, key, encrypted_data):
        """AES (Fernet) ile şifre çöz"""
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode('utf-8')

class LANMessenger(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self):
        # Ana pencere oluştur
        super().__init__()
        self.TkdndVersion = TkinterDnD._require(self)
        
        # Simgeyi ayarla
        if os.path.exists("icon.ico"):
            try:
                self.iconbitmap("icon.ico")
            except Exception as e:
                print(f"Icon configuration error: {e}")
        
        self.title("Advanced LAN Messenger")
        self.geometry("1200x800")
        self.minsize(800, 600)
        
        # Pencereyi ekran ortasında konumlandır
        self.center_window()
        
        # Appdata ayarları
        self.setup_appdata()
        
        # Drag & Drop Desteği
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.drop_file)
        
        # Şifreleme Yöneticisi
        self.encryption = EncryptionManager()
        self.session_keys = {}  # {socket_obj: aes_key}
        
        # Değişkenler
        self.server_socket = None
        self.client_socket = None
        self.is_server = False
        self.is_connected = False
        self.voice_recording = False
        self.voice_playing = False
        self.voice_streaming = False  # Anlık ses aktarımı için
        
        # Çeviriler
        self.init_translations()
        
        # Dili kayıt defterinden yükle
        self.lang_code = self.load_language_from_registry()
        
        # Güncelleme kontrolü (Sessiz mod)
        try:
            threading.Thread(target=self.check_for_updates, args=(True,), daemon=True).start()
        except Exception as e:
            print(f"Update check error: {e}")
        
        # Ses ayarları
        self.audio_format = pyaudio.paInt16
        self.channels = 1
        self.rate = 16000  # Daha uyumlu sample rate
        self.chunk = 256   # Daha küçük chunk boyutu
        try:
            self.audio = pyaudio.PyAudio()
        except:
            print("PyAudio could not be started!")
            self.audio = None
        
        # Anlık ses aktarımı için
        self.voice_input_stream = None
        self.voice_output_stream = None
        self.voice_clients = []  # Bağlı sesli kullanıcılar
        self.client_sockets = []  # Sunucuya bağlı istemci socket'leri
        
        # Kullanıcı bilgileri
        self.username = os.getenv('USERNAME', self.tr("username"))  # Windows kullanıcı adını al
        self.connected_users = {}
        
        # Sohbet grupları
        self.chat_widgets = {} # group_name -> textbox widget
        self.active_group = self.tr("general")
        
        # Dosya transferi değişkenleri
        self.incoming_files = {}  # {file_id: {filename, file_handle, total_size, current_size}}
        self.download_dir = None
        
        # Kaydedilen ayarları yükle
        self.load_settings()
        
        # Profil fotoğrafını yükle
        self.profile_photo_data = None
        self.profile_photo_image = None
        self.load_profile_photo()
        
        # GUI oluştur
        self.create_gui()
        
        # Sohbet geçmişini yükle
        self.load_chat_history()
        
        # System Tray icon
        self.tray_icon = None
        self.setup_tray_icon()
        
        # Pencere kapatma olayını yakala
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_tray_icon(self):
        """Sistem tepsisi ikonunu hazırla"""
        try:
            image = self.create_image()
            menu = pystray.Menu(
                pystray.MenuItem(self.tr("show_window"), self.show_window),
                pystray.MenuItem(self.tr("quit_app"), self.quit_app)
            )
            self.tray_icon = pystray.Icon("LANMessenger", image, "LAN Messenger", menu)
            
            # Tray icon'u ayrı bir thread'de çalıştır
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
        except Exception as e:
            print(f"Tray icon hatası: {e}")

    def create_image(self):
        """Tray için ikon oluştur (varsa dosyadan, yoksa çizerek)"""
        # İkon dosyası var mı kontrol et
        icon_path = "icon.ico" # Veya icon.png
        if os.path.exists(icon_path):
            return Image.open(icon_path)
            
        # Yoksa basit bir ikon çiz
        width = 64
        height = 64
        color1 = (60, 160, 240)
        color2 = (255, 255, 255)
        
        image = Image.new('RGB', (width, height), color1)
        dc = ImageDraw.Draw(image)
        dc.rectangle(
            (width // 4, height // 4, width * 3 // 4, height * 3 // 4),
            fill=color2
        )
        return image
        
    def show_window(self, icon=None, item=None):
        """Pencereyi göster"""
        self.after(0, self.deiconify)
        
    def quit_app(self, icon=None, item=None):
        """Uygulamayı tamamen kapat"""
        if self.tray_icon:
            self.tray_icon.stop()
            
        self.after(0, self.destroy_app)
        
    def destroy_app(self):
        """Kaynakları temizle ve kapat"""
        try:
            # Ayarları kaydet
            self.save_settings()
            
            # Bağlantıyı kes
            self.disconnect()
            
            # Ses kaynaklarını temizle
            if self.voice_input_stream:
                self.voice_input_stream.close()
            if self.voice_output_stream:
                self.voice_output_stream.close()
            
            if self.audio:
                self.audio.terminate()
                
            self.destroy()
            sys.exit(0)
        except:
            sys.exit(0)

    def on_closing(self):
        """Pencere kapatıldığında (Tray'e küçült)"""
        self.withdraw()  # Pencereyi gizle
        self.add_message(self.tr("system"), "ℹ️ Uygulama sistem tepsisine küçültüldü.")

    # ... (Diğer metodlar aynı kalacak) ...

        
    def setup_appdata(self):
        """Appdata klasörü ve ayar dosyalarını oluştur"""
        # Windows AppData Local yolu
        if sys.platform.startswith('win'):
            self.appdata_dir = Path(os.environ.get('LOCALAPPDATA', '')) / 'AdvancedLANMessenger'
        else:
            # Linux/Mac için
            self.appdata_dir = Path.home() / '.local' / 'share' / 'AdvancedLANMessenger'
        
        # Klasörü oluştur
        self.appdata_dir.mkdir(parents=True, exist_ok=True)
        
        # Ayar dosyası yolu
        self.settings_file = self.appdata_dir / 'settings.json'
        self.chat_history_file = self.appdata_dir / 'chat_history.json'
        
        # İndirilenler klasörü
        self.download_dir = self.appdata_dir / 'Downloads'
        self.download_dir.mkdir(parents=True, exist_ok=True)
        
    def load_settings(self):
        """Kaydedilen ayarları yükle"""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    
                    self.username = settings.get('username', os.getenv('USERNAME', self.tr('username')))
                    self.last_ip = settings.get('last_ip', self.get_local_ip())
                    self.last_port = settings.get('last_port', '3939')
                    self.theme = settings.get('theme', 'dark')
                    self.volume = settings.get('volume', 75)
                    self.notifications_enabled = settings.get('notifications_enabled', True)
                    self.input_device = settings.get('input_device', 0)
                    self.output_device = settings.get('output_device', 0)
                    
                    # Tema uygula
                    ctk.set_appearance_mode(self.theme)
            else:
                # Varsayılan ayarlar
                self.last_ip = self.get_local_ip()
                self.last_port = '3939'
                self.theme = 'dark'
                self.volume = 75
                self.notifications_enabled = True
                self.input_device = 0
                self.output_device = 0
                
        except Exception as e:
            print(f"Ayar yükleme hatası: {e}")
            # Varsayılan ayarlar
            self.last_ip = self.get_local_ip()
            self.last_port = '3939'
            self.theme = 'dark'
            self.volume = 75
            self.notifications_enabled = True
            self.input_device = 0
            self.output_device = 0
            
    def save_settings(self):
        """Ayarları kaydet"""
        try:
            settings = {
                'username': self.username,
                'last_ip': self.ip_entry.get() if hasattr(self, 'ip_entry') else self.last_ip,
                'last_port': self.port_entry.get() if hasattr(self, 'port_entry') else self.last_port,
                'theme': self.theme,
                'volume': self.volume,
                'notifications_enabled': self.notifications_enabled,
                'input_device': self.input_device,
                'output_device': self.output_device
            }
            
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"Ayar kaydetme hatası: {e}")
            
    def save_chat_message(self, username, message, timestamp=None, group=None):
        if group is None:
            group = self.tr("general")
        """Sohbet mesajını dosyaya kaydet"""
        try:
            if timestamp is None:
                timestamp = datetime.datetime.now().isoformat()
                
            chat_entry = {
                'username': username,
                'message': message,
                'timestamp': timestamp,
                'group': group
            }
            
            # Mevcut geçmişi yükle
            chat_history = []
            if self.chat_history_file.exists():
                with open(self.chat_history_file, 'r', encoding='utf-8') as f:
                    chat_history = json.load(f)
            
            # Yeni mesajı ekle
            chat_history.append(chat_entry)
            
            # Son 1000 mesajı tut
            if len(chat_history) > 1000:
                chat_history = chat_history[-1000:]
            
            # Dosyaya kaydet
            with open(self.chat_history_file, 'w', encoding='utf-8') as f:
                json.dump(chat_history, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"Sohbet geçmişi kaydetme hatası: {e}")
            
    def center_window(self):
        """Pencereyi ekran ortasında konumlandır"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def init_translations(self):
        """Çeviri sözlüğünü başlat"""
        self.translations = {
            "tr": {
                "app_title": "Advanced LAN Messenger",
                "chat_title": "💬 Sohbet",
                "settings_title": "⚙️ Ayarlar",
                "general": "Genel",
                "username": "Kullanıcı",
                "user_name": "Kullanıcı Adı:",
                "users_title": "👥 Çevrimiçi Kullanıcılar",
                "send_btn": "Gönder",
                "file_btn": "Dosya",
                "photo_btn": "Fotoğrafı Değiştir",
                "photo_file_types": "Resim Dosyaları",
                "photo_error": "Fotoğraf ayarlanamadı",
                "profile_photo_updated": "Profil fotoğrafı güncellendi",
                "system": "SISTEM",
                "error": "Hata",
                "profile_photo_error": "Profil fotoğrafı ayarlanamadı",
                "new_group_btn": "+ Yeni Grup",
                "delete_group_btn": "- Grubu Sil",
                "notifications_chk": "Bildirimleri Aç",
                "theme_label": "🎨 Tema",
                "volume_label": "Ses Seviyesi:",
                "mic_label": "Mikrofon:",
                "speaker_label": "Hoparlör:",
                "lang_label": "Dil / Language:",
                "welcome_msg": "🎉 Advanced LAN Messenger'a Hoş Geldiniz!\n📅 {date}\n" + "━" * 50 + "\n\n",
                "hist_old": "\n--- Geçmiş Mesajlar ---\n\n",
                "hist_new": "\n--- Yeni Mesajlar ---\n\n",
                "sys_hist_cleared": "Tüm sohbet geçmişi temizlendi!",
                "sys_group_deleted": "{group} grubu silindi.",
                "msg_join": "👋 {user} sohbete katıldı!",
                "msg_photo_changed": "🖼️ {user} profil fotoğrafını güncelledi.",
                "warn_no_pyaudio": "Uyarı: PyAudio modülü bulunamadı. Sesli özellikler devre dışı bırakılacak.",
                "warn_general_delete": "'Genel' grubu silinemez!",
                "confirm_delete_group": "'{group}' grubunu ve tüm geçmişini silmek istediğinizden emin misiniz?",
                "confirm_clear_hist": "Bu grubun sohbet geçmişini silmek istediğinizden emin misiniz?",
                "confirm_restart": "Dil değişikliğinin uygulanması için uygulamanın yeniden başlatılması gerekiyor. Şimdi kapatılsın mı?",
                "input_group_name": "Grup Adı:",
                "title_new_group": "Yeni Grup Oluştur",
                "err_hist_delete": "Sohbet geçmişi silinemedi: {error}",
                "err_notification": "Bildirim hatası: {error}",
                "err_folder_send": "Klasör gönderimi desteklenmiyor: {folder}",
                "approval": "Onay",
                "warning": "Uyarı",
                "info": "Bilgi",
                "about_text": "🚀 Advanced LAN Messenger v1.0.0\n\n✨ Özellikler:\n• Modern ve responsive arayüz\n• Gerçek zamanlı mesajlaşma\n• Sesli konuşma desteği\n• Ses cihazı seçimi\n• Tema değiştirme\n• Emoji desteği\n• Kullanıcı listesi\n• Dosya gönderme/alma\n• Profil fotoğrafları\n• Sistem tepsisi desteği\n• Mesaj şifreleme\n• Grup sohbetleri\n• Mesaj geçmişi kaydetme\n• Bildirim sistemi\n• Çoklu dil desteği\n\n👨‍💻 Geliştirici: Bartu Civaş\n📅 Tarih: 2026\n🔧 Python + CustomTkinter",
                "settings_reset": "Ayarlar Sıfırlandı",
                "confirm_reset_settings": "Tüm ayarları varsayılan değerlere döndürmek istediğinizden emin misiniz?",
                "notif_new_msg": "Yeni Mesaj: {user}",
                "clear_hist_btn": "Geçmişi Temizle",
                "reset_btn": "⚙️ Ayarları Sıfırla",
                "about_btn": "ℹ️ Hakkında",
                "show_window": "Göster",
                "quit_app": "Çıkış",
                "ip_address": "IP Adresi:",
                "start_server": "Sunucu Başlat",
                "disconnected": "Bağlantı Yok",
                "connected": "Bağlantı Eklendi",
                "connect": "Bağlan",
                "disconnect": "Bağlantıyı Kes",
                "connect_first": "Önce bir bağlantı kurmalısınız!",
                "audio_settings": "🎵 Ses Ayarları",
                "check_update_btn": "🔄 Güncelle",
                "update_available_title": "Güncelleme Mevcut",
                "update_available_msg": "Yeni bir sürüm ({version}) mevcut! Şimdi indirip güncellemek istiyor musunuz?",
                "update_not_found": "Uygulama güncel!",
                "update_error": "Güncelleme hatası"
            },
            "en": {
                "app_title": "Advanced LAN Messenger",
                "chat_title": "💬 Chat",
                "settings_title": "⚙️ Settings",
                "general": "General",
                "username": "Username",
                "user_name": "Username:",
                "users_title": "👥 Online Users",
                "send_btn": "Send",
                "file_btn": "File",
                "photo_btn": "Change Photo",
                "photo_file_types": "Image Files",
                "photo_error": "Photo Error",
                "profile_photo_updated": "Profile Photo Updated",
                "system": "SYSTEM",
                "error": "Error",
                "profile_photo_error": "Profile Photo Error",
                "new_group_btn": "+ New Group",
                "delete_group_btn": "- Delete Group",
                "notifications_chk": "Enable Notifications",
                "theme_label": "🎨 Theme",
                "volume_label": "Volume:",
                "mic_label": "Microphone:",
                "speaker_label": "Speaker:",
                "lang_label": "Dil / Language:",
                "welcome_msg": "🎉 Welcome to Advanced LAN Messenger!\n📅 {date}\n" + "━" * 50 + "\n\n",
                "hist_old": "\n--- Past Messages ---\n\n",
                "hist_new": "\n--- New Messages ---\n\n",
                "sys_hist_cleared": "Chat history cleared!",
                "sys_group_deleted": "{group} group deleted.",
                "msg_join": "👋 {user} joined the chat!",
                "msg_photo_changed": "🖼️ {user} updated profile photo.",
                "warn_no_pyaudio": "Warning: PyAudio module not found. Voice features disabled.",
                "warn_general_delete": "'General' group cannot be deleted!",
                "confirm_delete_group": "Are you sure you want to delete '{group}' group and its history?",
                "confirm_clear_hist": "Are you sure you want to delete chat history for this group?",
                "confirm_restart": "Application needs to be restarted to apply language changes. Close now?",
                "input_group_name": "Group Name:",
                "title_new_group": "Create New Group",
                "err_hist_delete": "Could not delete chat history: {error}",
                "err_notification": "Notification error: {error}",
                "err_folder_send": "Folder sending is not supported: {folder}",
                "approval": "Approval",
                "warning": "Warning",
                "info": "Information",
                "about_text": "🚀 Advanced LAN Messenger v1.0.0\n\n✨ Features:\n• Modern and responsive interface\n• Real-time messaging\n• Voice chat support\n• Audio device selection\n• Theme switching\n• Emoji support\n• User list\n• File sending/receiving\n• Profile photos\n• System tray support\n• Message encryption\n• Group chats\n• Message history saving\n• Notification system\n• Multi-language support\n\n👨‍💻 Developer: Bartu Civas\n📅 Date: 2026\n🔧 Python + CustomTkinter",
                "settings_reset": "Settings Reset",
                "confirm_reset_settings": "Are you sure you want to reset all settings to default values?",
                "notif_new_msg": "New Message: {user}",
                "clear_hist_btn": "Clear History",
                "reset_btn": "⚙️ Reset Settings",
                "about_btn": "ℹ️ About",
                "show_window": "Show",
                "quit_app": "Quit",
                "ip_address": "IP Address:",
                "start_server": "Start Server",
                "disconnected": "Disconnected",
                "connected": "Connected",
                "connect": "Connect",
                "disconnect": "Disconnect",
                "connect_first": "First, you need to establish a connection!",
                "audio_settings": "🎵 Audio Settings",
                "check_update_btn": "🔄 Check Updates",
                "update_available_title": "Update Available",
                "update_available_msg": "A new version ({version}) is available! Do you want to download and update now?",
                "update_not_found": "You are up to date!",
                "update_error": "Update error"
            }
        }

    def tr(self, key, **kwargs):
        """Çeviri yardımcı fonksiyonu"""
        try:
            text = self.translations.get(self.lang_code, self.translations["tr"]).get(key, key)
            if kwargs:
                return text.format(**kwargs)
            return text
        except:
            return key

    def load_language_from_registry(self):
        """Kayıt defterinden dil ayarını oku"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\AdvancedLANMessenger", 0, winreg.KEY_READ)
            lang, _ = winreg.QueryValueEx(key, "Language")
            winreg.CloseKey(key)
            
            # Dil kodunu dönüştür
            if lang == "Turkish": return "tr"
            if lang == "English": return "en"
            
            # Eski format desteği
            return lang if lang in ["tr", "en"] else "tr"
        except:
            return "tr" # Varsayılan

    def save_language_to_registry(self, lang_code):
        """Dil ayarını kayıt defterine kaydet"""
        try:
            # Kayıt için dönüştür
            lang_map = {"tr": "Turkish", "en": "English"}
            lang_val = lang_map.get(lang_code, "Turkish")
            
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\AdvancedLANMessenger")
            winreg.SetValueEx(key, "Language", 0, winreg.REG_SZ, lang_val)
            winreg.CloseKey(key)
        except Exception as e:
            print(f"Registry kayıt hatası: {e}")
            
    def set_language(self, choice):
        """Dil değiştirme"""
        lang_map = {"Türkçe": "tr", "English": "en"}
        new_lang = lang_map.get(choice, "tr")
        
        if new_lang != self.lang_code:
            self.save_language_to_registry(new_lang)
            if messagebox.askyesno("Restart", self.tr("confirm_restart")):
                self.destroy()
        
    def load_profile_photo(self):
        """Profil fotoğrafını yükle"""
        photo_path = self.appdata_dir / "profile_photo.png"
        
        if photo_path.exists():
            try:
                # Dosyadan oku ve base64'e çevir (göndermek için)
                with open(photo_path, "rb") as f:
                    file_data = f.read()
                    self.profile_photo_data = base64.b64encode(file_data).decode('ascii')
                    
                # Görüntülemek için yükle
                image = Image.open(photo_path)
                self.profile_photo_image = ctk.CTkImage(light_image=image, dark_image=image, size=(40, 40))
            except Exception as e:
                print(f"Fotoğraf yükleme hatası: {e}")
                self.profile_photo_image = None
                self.profile_photo_data = None
        
        # Varsayılan fotoğraf
        if self.profile_photo_image is None:
            self.create_default_profile_photo()
            
    def create_default_profile_photo(self):
        """Varsayılan profil fotoğrafı oluştur"""
        img = Image.new('RGB', (64, 64), color=(60, 160, 240))
        d = ImageDraw.Draw(img)
        # Basit bir yüz çizimi veya harf
        d.rectangle((16, 16, 48, 48), fill=(255, 255, 255))
        
        self.profile_photo_image = ctk.CTkImage(light_image=img, dark_image=img, size=(40, 40))
        # Default fotoğrafı base64 olarak saklamıyoruz, göndermezsek karşı taraf kendi default'unu kullanır
        
    def select_profile_photo(self):
        """Profil fotoğrafı seç"""
        file_path = filedialog.askopenfilename(
            title=self.tr("photo_select_btn"),
            filetypes=[(self.tr("photo_file_types"), "*.png;*.jpg;*.jpeg;*.gif")]
        )
        
        if file_path:
            try:
                # Resmi aç ve yeniden boyutlandır
                img = Image.open(file_path)
                img = img.resize((64, 64), Image.Resampling.LANCZOS)
                
                # Kaydet
                save_path = self.appdata_dir / "profile_photo.png"
                img.save(save_path, "PNG")
                
                # Yükle ve güncelle
                self.load_profile_photo()
                
                # Listeyi güncelle (kendi fotomuzu görmek için)
                if self.username in self.connected_users:
                    # Sunucuysak veya listedeysek güncelle
                     user_data = self.connected_users[self.username]
                     if isinstance(user_data, dict):
                         user_data["photo"] = self.profile_photo_data
                     self.update_user_list()
                     
                self.add_message(self.tr("system"), "✨ " + self.tr("profile_photo_updated"))
                
                # GUI'deki önizlemeyi güncelle (Sidebar'da varsa)
                if hasattr(self, 'profile_photo_btn'):
                    self.profile_photo_btn.configure(image=self.profile_photo_image)
                    
            except Exception as e:
                messagebox.showerror(self.tr("error"), f"{self.tr("profile_photo_error")}: {e}")
        
        
    def create_gui(self):
        """Ana GUI oluştur"""
        # Ana konteyner
        self.main_container = ctk.CTkFrame(self)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Üst panel - Bağlantı ayarları
        self.create_connection_panel()
        
        # Orta panel - Sohbet alanı
        self.create_chat_panel()
        
        # Alt panel - Mesaj gönderme ve ses kontrolleri
        self.create_message_panel()
        
        # Sağ panel - Kullanıcı listesi ve ayarlar
        self.create_sidebar()
        
    def create_connection_panel(self):
        """Bağlantı ayarları paneli"""
        self.connection_frame = ctk.CTkFrame(self.main_container)
        self.connection_frame.pack(fill="x", padx=5, pady=5)
        
        # Kullanıcı adı
        ctk.CTkLabel(self.connection_frame, text=self.tr("user_name"), font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = ctk.CTkEntry(self.connection_frame, width=150)
        self.username_entry.insert(0, self.username)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.bind('<FocusOut>', self.on_username_change)
        
        # IP Adresi
        ctk.CTkLabel(self.connection_frame, text=self.tr("ip_address"), font=("Arial", 12)).grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.ip_entry = ctk.CTkEntry(self.connection_frame, width=150)
        self.ip_entry.insert(0, self.last_ip)
        self.ip_entry.grid(row=0, column=3, padx=5, pady=5)
        self.ip_entry.bind('<FocusOut>', lambda event: self.save_settings())
        
        # Port
        ctk.CTkLabel(self.connection_frame, text="Port:", font=("Arial", 12)).grid(row=0, column=4, padx=5, pady=5, sticky="w")
        self.port_entry = ctk.CTkEntry(self.connection_frame, width=80)
        self.port_entry.insert(0, self.last_port)
        self.port_entry.grid(row=0, column=5, padx=5, pady=5)
        self.port_entry.bind('<FocusOut>', lambda event: self.save_settings())
        
        # Bağlantı butonları
        self.start_server_btn = ctk.CTkButton(self.connection_frame, text=self.tr("start_server"), command=self.start_server, width=120)
        self.start_server_btn.grid(row=0, column=6, padx=5, pady=5)
        
        self.connect_btn = ctk.CTkButton(self.connection_frame, text=self.tr("connect"), command=self.connect_to_server, width=100)
        self.connect_btn.grid(row=0, column=7, padx=5, pady=5)
        
        self.disconnect_btn = ctk.CTkButton(self.connection_frame, text=self.tr("disconnect"), command=self.disconnect, width=120, state="disabled")
        self.disconnect_btn.grid(row=0, column=8, padx=5, pady=5)
        
        # Durum etiketi
        self.status_label = ctk.CTkLabel(self.connection_frame, text=self.tr("disconnected"), font=("Arial", 12, "bold"))
        self.status_label.grid(row=1, column=0, columnspan=9, pady=5)
        
    def on_username_change(self, event=None):
        """Kullanıcı adı değiştiğinde"""
        self.username = self.username_entry.get()
        self.save_settings()
        
    def create_chat_panel(self):
        """Sohbet alanı paneli"""
        # Ana sohbet konteyneri
        self.chat_container = ctk.CTkFrame(self.main_container)
        self.chat_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Sohbet alanı çerçevesi
        self.chat_frame = ctk.CTkFrame(self.chat_container)
        self.chat_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        
        # Sohbet başlığı ve grup butonları
        header_frame = ctk.CTkFrame(self.chat_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=5, pady=5)
        
        self.chat_title = ctk.CTkLabel(header_frame, text=self.tr("chat_title"), font=("Arial", 16, "bold"))
        self.chat_title.pack(side="left", padx=5)
        
        # Yeni Grup Butonu
        self.new_group_btn = ctk.CTkButton(
            header_frame, 
            text=self.tr("new_group_btn"), 
            width=80, 
            height=25,
            command=self.add_new_group
        )
        self.new_group_btn.pack(side="right", padx=5)
        
        # Grubu Sil Butonu
        self.delete_group_btn = ctk.CTkButton(
            header_frame, 
            text=self.tr("delete_group_btn"), 
            width=80, 
            height=25,
            fg_color="#D32F2F",
            hover_color="#B71C1C",
            command=self.delete_current_group
        )
        self.delete_group_btn.pack(side="right", padx=5)
        
        # Tab View (Sekmeli Yapı)
        self.chat_tabs = ctk.CTkTabview(self.chat_frame)
        self.chat_tabs.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Genel grubunu oluştur
        self.create_group_tab(self.tr("general"))
        
    def create_group_tab(self, group_name):
        """Yeni bir grup sekmesi oluştur"""
        if group_name in self.chat_widgets:
            self.chat_tabs.set(group_name)
            return

        # Yeni sekme ekle
        self.chat_tabs.add(group_name)
        
        # Sekme içine textbox ekle
        textbox = ctk.CTkTextbox(self.chat_tabs.tab(group_name), font=("Arial", 11), state="disabled")
        textbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Widget'ı kaydet
        self.chat_widgets[group_name] = textbox
        
        # Karşılama mesajı
        if group_name == self.tr("general"):
            welcome_msg = self.tr("welcome_msg", date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            textbox.configure(state="normal")
            textbox.insert("end", welcome_msg)
            textbox.configure(state="disabled")
            
    def add_new_group(self):
        """Kullanıcıdan isim alarak yeni grup oluştur"""
        dialog = ctk.CTkInputDialog(text=self.tr("input_group_name"), title=self.tr("title_new_group"))
        group_name = dialog.get_input()
        
        if group_name:
            group_name = group_name.strip()
            if group_name:
                self.create_group_tab(group_name)
                self.chat_tabs.set(group_name) # Yeni sekmeye geç

    def delete_current_group(self):
        """Aktif grubu sil"""
        group_name = self.chat_tabs.get()
        
        if group_name == self.tr("general"):
            messagebox.showwarning(self.tr("warning"), self.tr("warn_general_delete"))
            return
            
        if messagebox.askyesno(self.tr("approval"), self.tr("confirm_delete_group", group=group_name)):
            try:
                # 1. Widget'ı ve sekmeyi kaldır
                del self.chat_widgets[group_name]
                self.chat_tabs.delete(group_name)
                
                # 2. Geçmişten temizle
                if self.chat_history_file.exists():
                    try:
                        with open(self.chat_history_file, 'r', encoding='utf-8') as f:
                            history = json.load(f)
                        
                        # Bu gruba ait olmayan mesajları filtrele
                        new_history = [msg for msg in history if msg.get('group', self.tr('general')) != group_name]
                        
                        # Dosyayı güncelle
                        with open(self.chat_history_file, 'w', encoding='utf-8') as f:
                            json.dump(new_history, f, ensure_ascii=False, indent=4)
                            
                    except Exception as e:
                        print(f"Geçmiş temizleme hatası: {e}")
                
            except Exception as e:
                messagebox.showerror("Hata", f"Grup silinemedi: {e}")
        
    def create_message_panel(self):
        """Mesaj gönderme paneli"""
        self.message_frame = ctk.CTkFrame(self.main_container)
        self.message_frame.pack(fill="x", padx=5, pady=5)
        
        # Mesaj girişi
        self.message_entry = ctk.CTkEntry(self.message_frame, placeholder_text="Mesajınızı yazın...", font=("Arial", 12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        self.message_entry.bind("<Return>", self.send_message)
        
        # Emoji butonu
        self.emoji_btn = ctk.CTkButton(self.message_frame, text="😀", width=40, command=self.show_emoji_panel)
        self.emoji_btn.pack(side="left", padx=2, pady=5)
        
        # Butonlar
        self.send_btn = ctk.CTkButton(self.message_frame, text=self.tr("send_btn"), width=80, command=self.send_message)
        self.send_btn.pack(side="right", padx=5)
        
        self.file_btn = ctk.CTkButton(self.message_frame, text=self.tr("file_btn"), width=80, fg_color="gray", command=self.send_file)
        self.file_btn.pack(side="right", padx=5)
        
        # Anlık sesli sohbet kontrolleri
        self.voice_frame = ctk.CTkFrame(self.message_frame)
        self.voice_frame.pack(side="right", padx=5, pady=5)
        
        # Anlık sesli sohbet butonu
        self.voice_chat_btn = ctk.CTkButton(
            self.voice_frame, 
            text="[MIC] Sesli Sohbet", 
            width=120, 
            command=self.toggle_voice_chat,
            fg_color="gray"
        )
        self.voice_chat_btn.pack(side="left", padx=2)
        
        # Push-to-talk butonu
        self.ptt_btn = ctk.CTkButton(
            self.voice_frame, 
            text=">> Konuş", 
            width=80, 
            command=self.toggle_push_to_talk,
            state="disabled"
        )
        self.ptt_btn.pack(side="left", padx=2)
        
        # Ses durumu etiketi
        self.voice_status_label = ctk.CTkLabel(self.voice_frame, text="[X] Sesli sohbet kapalı", font=("Arial", 10))
        self.voice_status_label.pack(side="left", padx=5)
        
    def create_sidebar(self):
        """Kenar çubuğu - kullanıcı listesi ve ayarlar"""
        self.sidebar = ctk.CTkFrame(self.chat_container, width=250)
        self.sidebar.pack(side="right", fill="y", padx=5, pady=5)
        self.sidebar.pack_propagate(False)
        
        # Bağlı kullanıcılar
        self.users_label = ctk.CTkLabel(self.sidebar, text=self.tr("users_title"), font=("Arial", 14, "bold"))
        self.users_label.pack(pady=10)
        
        # Kullanıcı listesi (Scrollable Frame)
        self.users_list_frame = ctk.CTkScrollableFrame(self.sidebar, height=200)
        self.users_list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Profil Fotoğrafı Değiştirme Butonu
        self.profile_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.profile_frame.pack(fill="x", padx=5, pady=10)
        
        self.profile_photo_btn = ctk.CTkButton(
            self.profile_frame, 
            text=self.tr("photo_btn"), 
            image=self.profile_photo_image, 
            compound="left",
            command=self.select_profile_photo,
            height=40
        )
        self.profile_photo_btn.pack(fill="x")
        
        # Ses ayarları
        self.audio_label = ctk.CTkLabel(self.sidebar, text=self.tr("audio_settings"), font=("Arial", 14, "bold"))
        self.audio_label.pack(pady=(20, 10))
        
        # Ses giriş cihazı
        ctk.CTkLabel(self.sidebar, text=self.tr("mic_label"), font=("Arial", 11)).pack(anchor="w", padx=10)
        input_devices = self.get_audio_devices("input")
        self.input_device_combo = ctk.CTkComboBox(self.sidebar, values=input_devices, width=220, command=self.on_input_device_change)
        if self.input_device < len(input_devices):
            self.input_device_combo.set(input_devices[self.input_device])
        self.input_device_combo.pack(padx=10, pady=2)
        
        # Ses çıkış cihazı
        ctk.CTkLabel(self.sidebar, text=self.tr("speaker_label"), font=("Arial", 11)).pack(anchor="w", padx=10, pady=(10, 0))
        output_devices = self.get_audio_devices("output")
        self.output_device_combo = ctk.CTkComboBox(self.sidebar, values=output_devices, width=220, command=self.on_output_device_change)
        if self.output_device < len(output_devices):
            self.output_device_combo.set(output_devices[self.output_device])
        self.output_device_combo.pack(padx=10, pady=2)
        
        # Ses seviyesi
        ctk.CTkLabel(self.sidebar, text=self.tr("volume_label"), font=("Arial", 11)).pack(anchor="w", padx=10, pady=(10, 0))
        self.volume_slider = ctk.CTkSlider(self.sidebar, from_=0, to=100, number_of_steps=100, width=220, command=self.on_volume_change)
        self.volume_slider.set(self.volume)
        self.volume_slider.pack(padx=10, pady=2)
        
        # Bildirimler
        self.notification_var = ctk.BooleanVar(value=self.notifications_enabled)
        self.notification_cb = ctk.CTkCheckBox(
            self.sidebar, 
            text=self.tr("notifications_chk"), 
            variable=self.notification_var,
            command=self.on_notification_change,
            font=("Arial", 11)
        )
        self.notification_cb.pack(padx=10, pady=(15, 5), anchor="w")
        
        # Dil Seçimi
        ctk.CTkLabel(self.sidebar, text=self.tr("lang_label"), font=("Arial", 11)).pack(anchor="w", padx=10, pady=(10, 0))
        self.lang_combo = ctk.CTkComboBox(self.sidebar, values=["Türkçe", "English"], width=220, command=self.set_language)
        self.lang_combo.set("Türkçe" if self.lang_code == "tr" else "English")
        self.lang_combo.pack(padx=10, pady=2)

        # Tema değiştirici
        self.theme_label = ctk.CTkLabel(self.sidebar, text=self.tr("theme_label"), font=("Arial", 14, "bold"))
        self.theme_label.pack(pady=(20, 10))
        
        self.theme_combo = ctk.CTkComboBox(self.sidebar, values=["dark", "light"], command=self.change_theme, width=220)
        self.theme_combo.set(self.theme)
        self.theme_combo.pack(padx=10, pady=2)
        
        # Ayar butonları
        self.settings_frame = ctk.CTkFrame(self.sidebar)
        self.settings_frame.pack(fill="x", padx=10, pady=10)
        
        # Sohbet geçmişini temizle
        self.clear_chat_btn = ctk.CTkButton(self.settings_frame, text=self.tr("clear_hist_btn"), command=self.clear_chat_history, width=100, height=30)
        self.clear_chat_btn.pack(pady=2)
        
        # Ayarları sıfırla
        self.reset_settings_btn = ctk.CTkButton(self.settings_frame, text=self.tr("reset_btn"), command=self.reset_settings, width=100, height=30)
        self.reset_settings_btn.pack(pady=2)
        
        # Güncelleme Kontrol Butonu
        self.update_btn = ctk.CTkButton(self.settings_frame, text=self.tr("check_update_btn"), command=lambda: threading.Thread(target=self.check_for_updates, args=(False,), daemon=True).start(), width=100, height=30)
        self.update_btn.pack(pady=2)
        
        # Hakkında butonu
        self.about_btn = ctk.CTkButton(self.sidebar, text=self.tr("about_btn"), command=self.show_about, width=220)
        self.about_btn.pack(padx=10, pady=20)
        
    def on_input_device_change(self, selection):
        """Giriş cihazı değiştiğinde"""
        try:
            self.input_device = int(selection.split(":")[0])
            self.save_settings()
        except:
            self.input_device = 0
            
    def on_output_device_change(self, selection):
        """Çıkış cihazı değiştiğinde"""
        try:
            self.output_device = int(selection.split(":")[0])
            self.save_settings()
        except:
            self.output_device = 0
            
    def on_volume_change(self, value):
        """Ses seviyesi değiştiğinde"""
        self.volume = int(value)
        self.save_settings()
        
    def on_notification_change(self):
        """Bildirim ayarı değiştiğinde"""
        self.notifications_enabled = self.notification_var.get()
        self.save_settings()
    
    def show_notification(self, title, message):
        """Bildirim göster"""
        if not self.notifications_enabled:
            return
            
        try:
            # Ses çal
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
            
            # Tray icon bildirimi
            if self.tray_icon:
                self.tray_icon.notify(message, title)
        except Exception as e:
            print(f"Bildirim hatası: {e}")
        
    def clear_chat_history(self):
        """Sohbet geçmişini temizle (Aktif sekme)"""
        if messagebox.askyesno(self.tr("approval"), self.tr("confirm_clear_hist")):
            try:
                # Sadece dosya silme mantığı genel geçmiş için geçerli
                # Şimdilik dosyayı silip tüm sekmeleri temizleyelim mi?
                # Veya sadece aktif sekmeyi mi?
                # Kullanıcı beklentisi: "Geçmişi Temizle" tüm geçmişi siler.
                
                if self.chat_history_file.exists():
                    self.chat_history_file.unlink()
                
                # Tüm sekmeleri temizle
                for group_name, textbox in self.chat_widgets.items():
                    textbox.configure(state="normal")
                    textbox.delete("1.0", "end")
                    
                    if group_name == self.tr("general"):
                        welcome_msg = self.tr("welcome_msg", date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                        textbox.insert("end", welcome_msg)
                        
                    textbox.configure(state="disabled")
                
                self.add_message(self.tr("system"), self.tr("sys_hist_cleared"), group=self.tr("general"))
            except Exception as e:
                messagebox.showerror(self.tr("error"), self.tr("err_hist_delete", error=e))
                
    def reset_settings(self):
        """Ayarları varsayılana döndür"""
        if messagebox.askyesno(self.tr("approval"), self.tr("confirm_reset_settings")):
            try:
                if self.settings_file.exists():
                    self.settings_file.unlink()
                messagebox.showinfo(self.tr("info"), self.tr("settings_reset"))
                self.root.quit()
            except Exception as e:
                messagebox.showerror(self.tr("error"), f"Ayarlar sıfırlanamadı: {e}")
        
    def drop_file(self, event):
        """Sürüklenen dosyayı işler"""
        try:
            files = self.splitlist(event.data)
            for f in files:
                if os.path.isfile(f):
                    threading.Thread(target=self.process_file_send, args=(f,), daemon=True).start()
                else:
                    self.add_message(self.tr("system"), self.tr("err_folder_send", folder=f))
        except Exception as e:
            print(f"Drop hatası: {e}")
        
    def get_local_ip(self):
        """Yerel IP adresini al"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
            
    def get_audio_devices(self, device_type):
        """Ses cihazlarını listele - Türkçe karakter desteği ile"""
        devices = []
        try:
            for i in range(self.audio.get_device_count()):
                try:
                    device_info = self.audio.get_device_info_by_index(i)
                    device_name = device_info['name']
                    
                    # Türkçe karakter sorunu çözümü
                    try:
                        # Encoding sorunlarını çöz
                        if isinstance(device_name, bytes):
                            device_name = device_name.decode('utf-8', errors='replace')
                        elif isinstance(device_name, str):
                            # Windows'ta bazen cp1252 encoding ile gelir
                            try:
                                device_name = device_name.encode('cp1252').decode('utf-8', errors='replace')
                            except:
                                pass
                    except:
                        device_name = f"Cihaz {i}"
                    
                    # Çok uzun isimleri kısalt
                    if len(device_name) > 50:
                        device_name = device_name[:47] + "..."
                    
                    if device_type == "input" and device_info['maxInputChannels'] > 0:
                        devices.append(f"{i}: {device_name}")
                    elif device_type == "output" and device_info['maxOutputChannels'] > 0:
                        devices.append(f"{i}: {device_name}")
                        
                except Exception as e:
                    # Sorunlu cihazı atla
                    devices.append(f"{i}: Bilinmeyen Cihaz")
                    continue
                    
        except Exception as e:
            print(f"Ses cihazı listeleme hatası: {e}")
            devices = ["0: Varsayılan Cihaz"]
            
        return devices if devices else ["0: Cihaz Bulunamadı"]
        
    def start_server(self):
        """Sunucu başlat"""
        try:
            self.username = self.username_entry.get() or "Sunucu"
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((ip, port))
            self.server_socket.listen(5)
            
            self.is_server = True
            self.is_connected = True
            
            # Sunucu kullanıcısını listeye ekle
            self.connected_users[self.username] = {
                "address": f"{ip}:{port} (Sunucu)",
                "photo": self.profile_photo_data
            }
            self.update_user_list()
            
            # GUI güncelle
            self.start_server_btn.configure(state="disabled")
            self.connect_btn.configure(state="disabled")
            self.disconnect_btn.configure(state="normal")
            self.status_label.configure(text=f"🟢 Sunucu Aktif - {ip}:{port}", text_color="green")
            
            # Mesaj ekle
            self.add_message(self.tr("system"), f"🔴 Sunucu {ip}:{port} adresinde başlatıldı!")
            self.add_message(self.tr("system"), "📡 İstemci bağlantıları bekleniyor...")
            
            # Bağlantıları dinle
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sunucu başlatılamadı: {str(e)}")
            
    def accept_connections(self):
        """İstemci bağlantılarını kabul et"""
        while self.is_connected and self.is_server:
            try:
                client_socket, address = self.server_socket.accept()
                self.add_message(self.tr("system"), f"🟢 Yeni bağlantı: {address[0]}:{address[1]}")
                
                # İstemci socket'ini listeye ekle
                self.client_sockets.append(client_socket)
                
                # --- HANDSHAKE: ADIM 1 ---
                # Sunucu public key'ini gönder
                public_key = self.encryption.get_public_key_pem()
                handshake_msg = {
                    "type": "handshake_pub_key",
                    "key": public_key
                }
                # Handshake mesajını ŞİFRESİZ gönder (çünkü henüz ortak anahtar yok)
                client_socket.send(json.dumps(handshake_msg).encode('utf-8'))
                
                # İstemci iletişimi için thread başlat
                threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()
                
            except:
                break
                
    def handle_client(self, client_socket, address):
        """İstemci iletişimini yönet"""
        buffer = ""
        try:
            while self.is_connected:
                data = client_socket.recv(8192)
                if not data:
                    break
                
                # Veri şifreli mi, değil mi?
                # Eğer session key varsa şifreli olduğunu varsayacağız.
                # Ancak handshake sırasında bazı mesajlar şifresiz gelebilir mi?
                # Protokolümüz: Handshake tamamlanana kadar özel mesaj tipleri var.
                
                # Şifreli veriyi çözmeyi dene (Eğer session key varsa)
                if client_socket in self.session_keys:
                    try:
                        # Fernet şifreli veri base64 encoded gelir, bu yüzden direkt decode('utf-8') yapamayız
                        # Ancak bizim protokolde json içinde "data" alanında şifreli veri taşıyabiliriz
                        # Veya direkt raw şifreli veri gönderebiliriz.
                        # Basitlik için: Tüm haberleşme JSON string olarak kalsın, 
                        # eğer şifreleme aktifse, gönderilen ve alınan veri direkt Fernet token'ıdır (bytes).
                        
                        # Gelen veri bytes formatında. Fernet decode et.
                        try:
                            decrypted_data = self.encryption.decrypt_aes(self.session_keys[client_socket], data)
                            buffer += decrypted_data
                        except:
                             # Belki de bu bir handshake mesajıdır ve şifresizdir?
                             # Veya buffer parçalanmıştır.
                             # Gelen veri JSON formatında bir handshake mesajı olabilir.
                             buffer += data.decode('utf-8')
                    except:
                        buffer += data.decode('utf-8')
                else:
                    # Session key yok, veri plaintext (handshake için)
                    buffer += data.decode('utf-8')
                
                # JSON mesajlarını ayır
                while True:
                    try:
                        message, buffer = self.extract_json_message(buffer)
                        if message is None:
                            break
                        
                        # Handshake mesajlarını işle
                        msg_type = message.get("type")
                        
                        if msg_type == "handshake_aes_key":
                            # --- HANDSHAKE: ADIM 3 (Sunucu Tarafı) ---
                            # İstemciden şifreli AES anahtarı geldi
                            encrypted_aes_key_hex = message.get("key")
                            # Hex string'i bytes'a çevir
                            encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
                            
                            # RSA ile çöz
                            aes_key = self.encryption.decrypt_rsa(encrypted_aes_key)
                            
                            # Bu istemci için session key'i kaydet
                            self.session_keys[client_socket] = aes_key
                            self.add_message(self.tr("system"), f"🔒 {address[0]} ile güvenli bağlantı kuruldu.")
                            continue # Bu mesajı işledik, sonrakine geç
                            
                        self.process_received_message(message, address)
                        
                        # Sunucu ise mesajı diğer istemcilere yayınla
                        if self.is_server:
                            self.broadcast_message_to_clients(message, client_socket)
                    except Exception as e:
                        # JSON decode hatası veya eksik paket
                        break
                
        except Exception as e:
            print(f"İstemci iletişim hatası: {e}")
        finally:
            if client_socket in self.client_sockets:
                self.client_sockets.remove(client_socket)
            if client_socket in self.session_keys:
                del self.session_keys[client_socket]
            client_socket.close()
            self.add_message(self.tr("system"), f"🔴 Bağlantı kesildi: {address[0]}:{address[1]}")

    # ... extract_json_message ve broadcast metodları ...
    
    def extract_json_message(self, buffer):
        """Buffer'dan tam JSON mesajını çıkar"""
        try:
            decoder = json.JSONDecoder()
            message, end_idx = decoder.raw_decode(buffer)
            remaining_buffer = buffer[end_idx:].lstrip()
            return message, remaining_buffer
        except json.JSONDecodeError:
            return None, buffer
            
    def broadcast_message_to_clients(self, message, sender_socket):
        """Mesajı tüm istemcilere yayınla (gönderen hariç)"""
        try:
            # Mesajı JSON string yap
            json_str = json.dumps(message)
            
            disconnected_clients = []
            
            for client_socket in self.client_sockets:
                if client_socket != sender_socket:
                    try:
                        # Eğer bu istemci ile şifreli konuşuyorsak şifrele
                        if client_socket in self.session_keys:
                            aes_key = self.session_keys[client_socket]
                            encrypted_data = self.encryption.encrypt_aes(aes_key, json_str)
                            client_socket.send(encrypted_data)
                        else:
                            # Şifresiz gönder (muhtemelen handshake tamamlanmadı ama yine de gönderelim mi? Hayır güvenli değil)
                            # Handshake tamamlanmamışsa main veriyi gönderme
                            pass
                    except:
                        disconnected_clients.append(client_socket)
            
            for client in disconnected_clients:
                if client in self.client_sockets:
                    self.client_sockets.remove(client)
        except Exception as e:
            print(f"Broadcast hatası: {e}")

    def connect_to_server(self):
        """Sunucuya bağlan"""
        try:
            self.username = self.username_entry.get() or "İstemci"
            ip = self.ip_entry.get()
            port = int(self.port_entry.get())
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))
            
            self.is_connected = True
            
            # GUI güncelle
            self.start_server_btn.configure(state="disabled")
            self.connect_btn.configure(state="disabled")
            self.disconnect_btn.configure(state="normal")
            self.status_label.configure(text=f"🟢 Bağlandı - {ip}:{port}", text_color="green")
            
            # Mesaj dinleme thread'i başlat
            threading.Thread(target=self.listen_messages, daemon=True).start()
            
            self.add_message(self.tr("system"), f"🟢 {ip}:{port} adresine bağlanıldı! Güvenli bağlantı kuruluyor...")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Bağlantı kurulamadı: {str(e)}")
            
    def listen_messages(self):
        """Gelen mesajları dinle (Client Side)"""
        buffer = ""
        try:
            while self.is_connected:
                data = self.client_socket.recv(8192)
                if not data:
                    break
                
                # Şifre çözme denemesi (Eğer session key varsa)
                if self.session_keys.get(self.client_socket):
                    try:
                        decrypted_data = self.encryption.decrypt_aes(self.session_keys[self.client_socket], data)
                        buffer += decrypted_data
                    except:
                        # Belki şifresiz bir parçadır? Fernet her zaman valid token ister.
                        # Eğer decrypt edemezsek muhtemelen şifresiz veridir (handshake başı).
                        buffer += data.decode('utf-8')
                else:
                    buffer += data.decode('utf-8')
                
                # JSON mesajlarını ayır
                while True:
                    try:
                        message, buffer = self.extract_json_message(buffer)
                        if message is None:
                            break
                        
                        msg_type = message.get("type")
                        
                        if msg_type == "handshake_pub_key":
                            # --- HANDSHAKE: ADIM 2 (İstemci Tarafı) ---
                            # Sunucudan public key geldi
                            server_pub_key = message.get("key")
                            
                            # 1. AES Anahtarı oluştur
                            aes_key = self.encryption.generate_aes_key()
                            self.session_keys[self.client_socket] = aes_key
                            
                            # 2. RSA ile şifrele
                            encrypted_aes_key = self.encryption.encrypt_rsa(server_pub_key, aes_key)
                            
                            # 3. Sunucuya gönder
                            response = {
                                "type": "handshake_aes_key",
                                "key": encrypted_aes_key.hex() # Bytes json'a girmez, hex yap
                            }
                            # Bu mesajı ŞİFRESİZ gönder (çünkü sunucu henüz anahtarı bilmiyor)
                            # Özel bir send fonksiyonu kullanmadan direkt socket'e yazıyoruz
                            self.client_socket.send(json.dumps(response).encode('utf-8'))
                            
                            self.add_message(self.tr("system"), "🔒 Sunucu ile güvenli anahtar değişimi tamamlandı.")
                            
                            # Handshake bittiğine göre şimdi "Katıldım" mesajını GÜVENLİ yoldan atabiliriz
                            welcome_msg = {
                                "type": "user_join",
                                "username": self.username,
                                "photo": self.profile_photo_data,
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                            self.send_data(welcome_msg)
                            continue
                        
                        self.process_received_message(message)
                    except:
                        break
                
        except Exception as e:
            print(f"Listen error: {e}")
            pass

    def process_received_message(self, message, address=None):
        """Gelen mesajı işle"""
        try:
            msg_type = message.get("type", "text")
            username = message.get("username", "Bilinmeyen")
            timestamp = message.get("timestamp", datetime.datetime.now().isoformat())
            
            if msg_type == "text":
                content = message.get("content", "")
                group_name = message.get("group", self.tr("general"))
                self.add_message(username, content, timestamp, group=group_name)
                
                # Bildirim göster (kendi mesajımız değilse)
                if username != self.username:
                     # Hangi gruptan geldiğini de gösterelim
                    notification_title = self.tr("notif_new_msg", user=username)
                    if group_name != self.tr("general"):
                        notification_title += f" ({group_name})"
                    self.show_notification(notification_title, content)
                
            elif msg_type == "user_join":
                self.add_message(self.tr("system"), self.tr("msg_join", user=username))
                
                # Sunucu tarafından görülen gerçek IP'yi kullan
                if address:
                    address_str = f"{address[0]}:{address[1]}"
                else:
                    address_str = "Bilinmeyen"
                    
                self.connected_users[username] = {
                    "address": address_str,
                    "photo": message.get("photo")
                }
                self.update_user_list()
                
                # Sunucu ise mevcut kullanıcı listesini tüm istemcilere gönder
                if self.is_server:
                    # Sunucu kullanıcısını da ekle (eğer yoksa)
                    # Sunucu kullanıcısını da ekle (eğer yoksa)
                    if self.username not in self.connected_users:
                        self.connected_users[self.username] = {
                            "address": f"{self.ip_entry.get()}:{self.port_entry.get()} (Sunucu)",
                            "photo": self.profile_photo_data
                        }
                        
                    user_list_msg = {
                        "type": "user_list_update",
                        "users": self.connected_users,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    self.send_data(user_list_msg)
                
            elif msg_type == "user_leave":
                self.add_message(self.tr("system"), f"👋 {username} sohbetten ayrıldı!")
                if username in self.connected_users:
                    del self.connected_users[username]
                self.update_user_list()
                
            elif msg_type == "user_list_update":
                # Kullanıcı listesi güncellemesi al
                users = message.get("users", {})
                self.connected_users = users  # Tam listeyi güncelle
                self.update_user_list()
                
            elif msg_type == "voice_chat_start":
                self.add_message(self.tr("system"), f"🎙️ {username} sesli sohbeti başlattı!")
                
            elif msg_type == "voice_chat_stop":
                self.add_message(self.tr("system"), f"🔇 {username} sesli sohbeti durdurdu!")
                
            elif msg_type == "voice_stream":
                # Anlık ses verisini oynat (kendi sesimiz değilse)
                if username != self.username:
                    data_b64 = message.get("data", "")
                    if data_b64:
                        try:
                            audio_data = base64.b64decode(data_b64.encode('ascii'))
                            self.play_received_voice_stream(audio_data)
                        except Exception as e:
                            print(f"Ses stream işleme hatası: {e}")
                
            elif msg_type == "voice":
                # Eski ses mesajı formatı - geriye uyumluluk
                self.add_message(self.tr("system"), f"🎵 {username} ses mesajı gönderdi (eski format)")
            
            # --- DOSYA TRANSFER PROTOKOLÜ ---
            elif msg_type == "file_header":
                file_id = message.get("file_id")
                filename = message.get("filename")
                filesize = message.get("filesize", 0)
                
                if file_id and filename:
                    save_path = self.download_dir / filename
                    # Dosya adı çakışmasını önle
                    base, ext = os.path.splitext(filename)
                    counter = 1
                    while save_path.exists():
                        save_path = self.download_dir / f"{base}_{counter}{ext}"
                        counter += 1
                        
                    try:
                        f = open(save_path, "wb")
                        self.incoming_files[file_id] = {
                            "filename": filename,
                            "save_path": str(save_path),
                            "file_handle": f,
                            "total_size": filesize,
                            "current_size": 0,
                            "start_time": time.time()
                        }
                        self.add_message(self.tr("system"), f"⬇️ Dosya alınıyor: {filename} ({self.format_size(filesize)}) gönderen: {username}")
                    except Exception as e:
                        print(f"Dosya oluşturma hatası: {e}")
                        
            elif msg_type == "file_chunk":
                file_id = message.get("file_id")
                data_b64 = message.get("data")
                
                if file_id in self.incoming_files and data_b64:
                    try:
                        file_data = self.incoming_files[file_id]
                        chunk_data = base64.b64decode(data_b64)
                        file_data["file_handle"].write(chunk_data)
                        file_data["current_size"] += len(chunk_data)
                        
                        # İlerleme durumu (opsiyonel olarak GUI güncellemesi yapılabilir)
                        # progress = (file_data["current_size"] / file_data["total_size"]) * 100
                    except Exception as e:
                        print(f"Dosya yazma hatası: {e}")
                        
            elif msg_type == "file_end":
                file_id = message.get("file_id")
                if file_id in self.incoming_files:
                    try:
                        file_data = self.incoming_files[file_id]
                        file_data["file_handle"].close()
                        save_path = file_data["save_path"]
                        
                        duration = time.time() - file_data["start_time"]
                        speed = file_data["total_size"] / duration if duration > 0 else 0
                        
                        self.add_message(self.tr("system"), f"✅ Dosya tamamlandı: {file_data['filename']}")
                        self.add_message(self.tr("system"), f"💾 Kaydedildi: {save_path}")
                        
                        del self.incoming_files[file_id]
                    except Exception as e:
                        print(f"Dosya kapatma hatası: {e}")
                
        except Exception as e:
            print(f"Mesaj işleme hatası: {e}")
            
    def send_message(self, event=None):
        """Mesaj gönder"""
        if not self.is_connected:
            messagebox.showwarning(self.tr("warning"), "Önce bir bağlantı kurmalısınız!")
            return
            
        message_text = self.message_entry.get().strip()
        if not message_text:
            return
            
        # Aktif grubu al
        current_group = self.chat_tabs.get()
        
        # Mesaj objesi oluştur
        message = {
            "type": "text",
            "username": self.username,
            "content": message_text,
            "timestamp": datetime.datetime.now().isoformat(),
            "group": current_group
        }
        
        # Mesajı gönder
        self.send_data(message)
        
        # Kendi mesajımızı da göster
        self.add_message(self.username, message_text, group=current_group)
        
        # Mesaj girişini temizle
        self.message_entry.delete(0, "end")

    def send_data(self, data):
        """Veri gönder"""
        try:
            json_str = json.dumps(data)
            
            if self.is_server:
                # Sunucu ise tüm istemcilere gönder
                disconnected_clients = []
                for client in self.client_sockets:
                    try:
                        # Session key varsa şifrele
                        if client in self.session_keys:
                            aes_key = self.session_keys[client]
                            encrypted_data = self.encryption.encrypt_aes(aes_key, json_str)
                            client.send(encrypted_data)
                        else:
                            # Handshake tamamlanmamış
                            pass
                    except:
                        disconnected_clients.append(client)
                
                for client in disconnected_clients:
                    if client in self.client_sockets:
                        self.client_sockets.remove(client)
                        
            elif self.client_socket:
                # İstemci ise sunucuya gönder
                if self.client_socket in self.session_keys:
                    aes_key = self.session_keys[self.client_socket]
                    encrypted_data = self.encryption.encrypt_aes(aes_key, json_str)
                    self.client_socket.send(encrypted_data)
                else:
                    # Handshake yoksa gönderme (Handshake adımları hariç, onlar manuel send kullanıyor)
                    print("Handshake tamamlanmadı, veri gönderilemiyor.")
                    
        except Exception as e:
            print(f"Veri gönderme hatası: {e}")
            
    def add_message(self, username, message, timestamp=None, save=True, group=None):
        if group is None:
            group = self.tr("general")
        """Sohbet alanına mesaj ekle"""
        if timestamp is None:
            timestamp = datetime.datetime.now().isoformat()
            
        # Grup sekmesi yoksa oluştur
        if group not in self.chat_widgets:
            self.create_group_tab(group)
            
        # Zaman damgasını formatla
        try:
            dt = datetime.datetime.fromisoformat(timestamp)
            time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        # Mesaj formatı
        if username == self.tr("system"):
            formatted_message = f"[{time_str}] {message}\n"
        else:
            formatted_message = f"[{time_str}] {username}: {message}\n"
            
        # Mesajı ilgili sohbet alanına ekle
        textbox = self.chat_widgets[group]
        textbox.configure(state="normal")
        textbox.insert("end", formatted_message)
        textbox.see("end")
        textbox.configure(state="disabled")
        
        # Sohbet geçmişine kaydet (sadece normal mesajlar için ve save=True ise)
        if save and username != self.tr("system"):
            self.save_chat_message(username, message, timestamp, group)

    def load_chat_history(self):
        """Sohbet geçmişini yükle"""
        if self.chat_history_file.exists():
            try:
                with open(self.chat_history_file, 'r', encoding='utf-8') as f:
                    history = json.load(f)
                    
                if history:
                    # Tüm açık sekmelere "Geçmiş Mesajlar" ayracı ekle
                    # Ancak henüz sekmeler oluşmamış olabilir.
                    # Geçmişi yüklerken gereken sekmeleri oluşturacağız.
                    
                    # Geçici olarak hangi gruplara mesaj yüklediğimizi takip edelim
                    loaded_groups = set()
                    
                    for entry in history:
                        group = entry.get('group', self.tr('general'))
                        loaded_groups.add(group)
                        
                        if group not in self.chat_widgets:
                            self.create_group_tab(group)
                            
                    # Ayracı ekle
                    for group in loaded_groups:
                        if group in self.chat_widgets:
                            tb = self.chat_widgets[group]
                            tb.configure(state="normal")
                            tb.insert("end", self.tr("hist_old"))
                            tb.configure(state="disabled")
                            
                    # Mesajları yükle
                    for entry in history:
                        group = entry.get('group', self.tr('general'))
                        self.add_message(
                            entry.get('username', 'Bilinmeyen'), 
                            entry.get('message', ''), 
                            entry.get('timestamp'),
                            save=False,
                            group=group
                        )
                    
                    # Ayraç (Yeni Mesajlar)
                    for group in loaded_groups:
                        if group in self.chat_widgets:
                            tb = self.chat_widgets[group]
                            tb.configure(state="normal")
                            tb.insert("end", self.tr("hist_new"))
                            tb.see("end")
                            tb.configure(state="disabled")
            except Exception as e:
                print(f"Geçmiş yükleme hatası: {e}")
        
    def update_user_list(self):
        """Kullanıcı listesini güncelle"""
        # Mevcut widget'ları temizle
        for widget in self.users_list_frame.winfo_children():
            widget.destroy()
            
        # Başlık
        ctk.CTkLabel(
            self.users_list_frame, 
            text=f"📊 Toplam: {len(self.connected_users)}", 
            font=("Arial", 12, "bold")
        ).pack(pady=(0, 5))
        
        for username, data in self.connected_users.items():
            # Veri formatını kontrol et (dict mi str mi)
            if isinstance(data, dict):
                address = data.get("address", "???")
                photo_b64 = data.get("photo")
            else:
                address = str(data)
                photo_b64 = None
                
            # Kart oluştur
            card = ctk.CTkFrame(self.users_list_frame)
            card.pack(fill="x", padx=2, pady=2)
            
            # Fotoğrafı hazırla
            img = self.profile_photo_image # Varsayılan olarak bizimki mi? Hayır varsayılan oluşturmalıyız
            
            if photo_b64:
                try:
                    img_data = base64.b64decode(photo_b64)
                    pil_img = Image.open(io.BytesIO(img_data))
                    img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(30, 30))
                except:
                    # Hata varsa varsayılanı kullan (aşağıda)
                    photo_b64 = None
                    
            if not photo_b64:
                # Varsayılan ikon
                default_img = Image.new('RGB', (64, 64), color=(150, 150, 150))
                d = ImageDraw.Draw(default_img)
                d.text((25, 20), username[0].upper() if username else "?", fill="white")
                img = ctk.CTkImage(light_image=default_img, dark_image=default_img, size=(30, 30))
            
            # İkon
            ctk.CTkLabel(card, text="", image=img).pack(side="left", padx=5, pady=5)
            
            # Bilgiler
            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True)
            
            ctk.CTkLabel(info_frame, text=username, font=("Arial", 12, "bold")).pack(anchor="w")
            ctk.CTkLabel(info_frame, text=address, font=("Arial", 10), text_color="gray").pack(anchor="w")
        
    def toggle_voice_chat(self):
        """Anlık sesli sohbeti başlat/durdur"""
        if not self.is_connected:
            messagebox.showwarning(self.tr("warning"), "Önce bir bağlantı kurmalısınız!")
            return
            
        if not self.voice_streaming:
            self.start_voice_chat()
        else:
            self.stop_voice_chat()
            
    def start_voice_chat(self):
        """Anlık sesli sohbeti başlat"""
        try:
            self.voice_streaming = True
            
            # Ses cihazlarını kontrol et
            input_device = self.get_selected_input_device()
            output_device = self.get_selected_output_device()
            
            # Önce desteklenen sample rate'i bul
            supported_rates = [16000, 22050, 44100, 48000]
            working_rate = self.rate
            
            for rate in supported_rates:
                try:
                    # Test mikrofon
                    test_input = self.audio.open(
                        format=self.audio_format,
                        channels=self.channels,
                        rate=rate,
                        input=True,
                        input_device_index=input_device,
                        frames_per_buffer=self.chunk
                    )
                    test_input.close()
                    
                    # Test hoparlör
                    test_output = self.audio.open(
                        format=self.audio_format,
                        channels=self.channels,
                        rate=rate,
                        output=True,
                        output_device_index=output_device,
                        frames_per_buffer=self.chunk
                    )
                    test_output.close()
                    
                    working_rate = rate
                    break
                except:
                    continue
            
            # Ses giriş stream'i başlat
            try:
                self.voice_input_stream = self.audio.open(
                    format=self.audio_format,
                    channels=self.channels,
                    rate=working_rate,
                    input=True,
                    input_device_index=input_device,
                    frames_per_buffer=self.chunk
                )
            except Exception as e:
                print(f"Mikrofon açma hatası: {e}")
                # Varsayılan cihazı dene
                self.voice_input_stream = self.audio.open(
                    format=self.audio_format,
                    channels=self.channels,
                    rate=working_rate,
                    input=True,
                    frames_per_buffer=self.chunk
                )
            
            # Ses çıkış stream'i başlat
            try:
                self.voice_output_stream = self.audio.open(
                    format=self.audio_format,
                    channels=self.channels,
                    rate=working_rate,
                    output=True,
                    output_device_index=output_device,
                    frames_per_buffer=self.chunk
                )
            except Exception as e:
                print(f"Hoparlör açma hatası: {e}")
                # Varsayılan cihazı dene
                self.voice_output_stream = self.audio.open(
                    format=self.audio_format,
                    channels=self.channels,
                    rate=working_rate,
                    output=True,
                    frames_per_buffer=self.chunk
                )
            
            # Çalışan rate'i güncelle
            self.rate = working_rate
            
            # GUI güncelle
            self.voice_chat_btn.configure(text="[STOP] Sesli Sohbeti Durdur", fg_color="red")
            self.ptt_btn.configure(state="normal")
            self.voice_status_label.configure(text="[ON] Sesli sohbet açık")
            
            # Ses alma thread'i başlat
            threading.Thread(target=self.voice_receive_loop, daemon=True).start()
            
            self.add_message(self.tr("system"), "🎙️ Sesli sohbet başlatıldı! Konuşmak için 'Konuş' butonuna basın.")
            
            # Sesli sohbet bilgisini gönder
            voice_msg = {
                "type": "voice_chat_start",
                "username": self.username,
                "timestamp": datetime.datetime.now().isoformat()
            }
            self.send_data(voice_msg)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sesli sohbet başlatılamadı: {str(e)}")
            self.voice_streaming = False
            
    def stop_voice_chat(self):
        """Anlık sesli sohbeti durdur"""
        try:
            self.voice_streaming = False
            
            # Stream'leri kapat
            if self.voice_input_stream:
                self.voice_input_stream.stop_stream()
                self.voice_input_stream.close()
                self.voice_input_stream = None
                
            if self.voice_output_stream:
                self.voice_output_stream.stop_stream()
                self.voice_output_stream.close()
                self.voice_output_stream = None
            
            # GUI güncelle
            self.voice_chat_btn.configure(text="[MIC] Sesli Sohbet", fg_color="gray")
            self.ptt_btn.configure(state="disabled", text=">> Konuş", fg_color=["#3B8ED0", "#1F6AA5"])
            self.voice_status_label.configure(text="[X] Sesli sohbet kapalı")
            
            self.add_message(self.tr("system"), "🔇 Sesli sohbet durduruldu!")
            
            # Sesli sohbet bitiş bilgisini gönder
            voice_msg = {
                "type": "voice_chat_stop",
                "username": self.username,
                "timestamp": datetime.datetime.now().isoformat()
            }
            self.send_data(voice_msg)
            
        except Exception as e:
            print(f"Sesli sohbet durdurma hatası: {e}")
            
    def toggle_push_to_talk(self):
        """Push-to-talk'ı aç/kapat"""
        if not self.voice_recording:
            self.start_push_to_talk()
        else:
            self.stop_push_to_talk()
            
    def start_push_to_talk(self):
        """Push-to-talk başlat"""
        if not self.voice_streaming:
            return
            
        self.voice_recording = True
        self.ptt_btn.configure(text="[STOP] Konuşmayı Bırak", fg_color="green")
        
        # Ses gönderme thread'i başlat
        threading.Thread(target=self.voice_send_loop, daemon=True).start()
        
    def stop_push_to_talk(self):
        """Push-to-talk durdur"""
        self.voice_recording = False
        self.ptt_btn.configure(text=">> Konuş", fg_color=["#3B8ED0", "#1F6AA5"])
        
    def voice_send_loop(self):
        """Ses gönderme döngüsü"""
        try:
            while self.voice_recording and self.voice_streaming:
                if self.voice_input_stream:
                    data = self.voice_input_stream.read(self.chunk, exception_on_overflow=False)
                    
                    # Ses verisini base64 ile encode et
                    voice_data = {
                        "type": "voice_stream",
                        "username": self.username,
                        "data": base64.b64encode(data).decode('ascii'),
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    self.send_data(voice_data)
                    
                # Küçük bir gecikme ekle
                time.sleep(0.01)  # Biraz daha fazla gecikme
                    
        except Exception as e:
            print(f"Ses gönderme hatası: {e}")
            # Hata durumunda buton durumunu sıfırla
            self.voice_recording = False
            self.ptt_btn.configure(text=">> Konuş", fg_color=["#3B8ED0", "#1F6AA5"])
            
    def voice_receive_loop(self):
        """Ses alma döngüsü"""
        try:
            while self.voice_streaming:
                time.sleep(0.01)  # CPU kullanımını azalt
                
        except Exception as e:
            print(f"Ses alma hatası: {e}")
            
    def play_received_voice_stream(self, audio_data):
        """Gelen ses stream'ini oynat"""
        try:
            if self.voice_output_stream and self.voice_streaming:
                # Ses seviyesini uygula
                volume_factor = self.volume / 100.0
                
                # Ses verisini numpy array'e çevir ve ses seviyesini uygula
                audio_array = struct.unpack(f'{len(audio_data)//2}h', audio_data)
                scaled_audio = [int(sample * volume_factor) for sample in audio_array]
                scaled_data = struct.pack(f'{len(scaled_audio)}h', *scaled_audio)
                
                self.voice_output_stream.write(scaled_data)
                
        except Exception as e:
            print(f"Ses stream oynatma hatası: {e}")
            
    def toggle_voice_recording(self):
        """Eski ses kaydı fonksiyonu - geriye uyumluluk için"""
        messagebox.showinfo("Bilgi", "Artık anlık sesli sohbet özelliğini kullanın!")
        
    def record_voice(self):
        """Eski ses kayıt fonksiyonu - geriye uyumluluk için"""
        pass
        
    def receive_voice_data(self, hex_data):
        """Eski ses veri alma fonksiyonu - geriye uyumluluk için"""
        pass
        
    def play_received_voice(self, audio_data):
        """Eski ses oynatma fonksiyonu - geriye uyumluluk için"""
        pass
        
    def get_selected_input_device(self):
        """Seçili giriş cihazını al"""
        try:
            if hasattr(self, 'input_device_combo'):
                device_str = self.input_device_combo.get()
                return int(device_str.split(":")[0])
            else:
                return self.input_device if hasattr(self, 'input_device') else 0
        except:
            return 0  # Varsayılan cihaz
            
    def get_selected_output_device(self):
        """Seçili çıkış cihazını al"""
        try:
            if hasattr(self, 'output_device_combo'):
                device_str = self.output_device_combo.get()
                return int(device_str.split(":")[0])
            else:
                return self.output_device if hasattr(self, 'output_device') else 0
        except:
            return 0  # Varsayılan cihaz
        
    def send_file(self):
        """Dosya gönder"""
        if not self.is_connected:
            messagebox.showwarning(self.tr("warning"), self.tr("connect_first"))
            return
            
        filename = filedialog.askopenfilename(
            title="Gönderilecek dosyayı seçin",
            filetypes=[("Tüm Dosyalar", "*.*")]
        )
        
        if filename:
            threading.Thread(target=self.process_file_send, args=(filename,), daemon=True).start()

    def process_file_send(self, filepath):
        """Dosya gönderme işlemini arka planda yap"""
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            file_id = str(time.time()) + "_" + self.username  # Basit unique ID
            
            self.add_message(self.tr("system"), f"⬆️ Dosya gönderiliyor: {filename} ({self.format_size(filesize)})...")
            
            # 1. Header gönder
            header = {
                "type": "file_header",
                "username": self.username,
                "file_id": file_id,
                "filename": filename,
                "filesize": filesize,
                "timestamp": datetime.datetime.now().isoformat()
            }
            self.send_data(header)
            
            # 2. Chunk'lar halinde gönder
            chunk_size = 8192 # 8KB chunks (Base64 sonrası ~11KB olur)
            sent_bytes = 0
            
            with open(filepath, "rb") as f:
                chunk_index = 0
                while True:
                    data = f.read(chunk_size)
                    if not data:
                        break
                        
                    chunk_data = {
                        "type": "file_chunk",
                        "file_id": file_id,
                        "chunk_index": chunk_index,
                        "data": base64.b64encode(data).decode('ascii')
                    }
                    self.send_data(chunk_data)
                    
                    sent_bytes += len(data)
                    chunk_index += 1
                    
                    # Ağ tıkanıklığını önlemek için minik bekleme
                    time.sleep(0.005)
            
            # 3. Bitiş sinyali gönder
            end_msg = {
                "type": "file_end",
                "file_id": file_id,
                "username": self.username,
                "timestamp": datetime.datetime.now().isoformat()
            }
            self.send_data(end_msg)
            
            self.add_message(self.tr("system"), f"✅ Dosya gönderimi tamamlandı: {filename}")
            
        except Exception as e:
            self.add_message(self.tr("system"), f"❌ Dosya gönderme hatası: {str(e)}")
            print(f"File send error: {e}")

    def format_size(self, size):
        """Dosya boyutunu formatla"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
            
    def show_emoji_panel(self):
        """Emoji paneli göster"""
        emoji_window = ctk.CTkToplevel(self)
        emoji_window.title("Emoji Seç")
        emoji_window.geometry("300x200")
        emoji_window.resizable(False, False)
        
        emojis = ["😀", "😂", "😍", "🤔", "😢", "😡", "👍", "👎", "❤️", "💔", "🔥", "⭐", "💯", "🎉", "👋", "🙏"]
        
        for i, emoji in enumerate(emojis):
            row = i // 4
            col = i % 4
            btn = ctk.CTkButton(
                emoji_window,
                text=emoji,
                width=50,
                height=50,
                command=lambda e=emoji: self.add_emoji(e, emoji_window)
            )
            btn.grid(row=row, column=col, padx=5, pady=5)
            
    def add_emoji(self, emoji, window):
        """Emoji ekle"""
        current_text = self.message_entry.get()
        self.message_entry.delete(0, "end")
        self.message_entry.insert(0, current_text + emoji)
        window.destroy()
        
    def change_theme(self, theme):
        """Tema değiştir"""
        self.theme = theme
        ctk.set_appearance_mode(theme)
        self.save_settings()
        self.add_message(self.tr("system"), f"🎨 Tema '{theme}' olarak değiştirildi!")
        
    def show_about(self):
        """Hakkında penceresi"""
        about_text = self.tr("about_text")
        
        messagebox.showinfo("About", about_text)
        
    def disconnect(self):
        """Bağlantıyı kes"""
        try:
            # Sesli sohbeti durdur
            if self.voice_streaming:
                self.stop_voice_chat()
            
            # Ayrılma mesajı gönder
            if self.is_connected:
                leave_msg = {
                    "type": "user_leave",
                    "username": self.username,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                self.send_data(leave_msg)
                
            self.is_connected = False
            
            # Socket'leri kapat
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
                
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
                
            # İstemci socket'leri temizle
            for client in self.client_sockets:
                try:
                    client.close()
                except:
                    pass
            self.client_sockets.clear()
                
            self.is_server = False
            
            # GUI güncelle
            self.start_server_btn.configure(state="normal")
            self.connect_btn.configure(state="normal")
            self.disconnect_btn.configure(state="disabled")
            self.status_label.configure(text="🔴 Bağlantı Yok", text_color="red")
            
            # Kullanıcı listesini temizle
            self.connected_users.clear()
            self.update_user_list()
            
            self.add_message(self.tr("system"), "🔴 Bağlantı kesildi!")
            
        except Exception as e:
            print(f"Bağlantı kesme hatası: {e}")

    def check_for_updates(self, silent=False):
        """Güncellemeleri kontrol et"""
        try:
            print("Güncellemeler kontrol ediliyor...")
            with urllib.request.urlopen(UPDATE_URL, timeout=5) as response:
                remote_version = response.read().decode('utf-8').strip()
                
            print(f"Mevcut sürüm: {VERSION}, Sunucu sürümü: {remote_version}")
            
            if remote_version != VERSION:
                # Basit bir sürüm karşılaştırması (string olarak farklıysa güncelle)
                # Daha gelişmişi için semantic versioning parse edilebilir
                if messagebox.askyesno(self.tr("update_available_title"), self.tr("update_available_msg", version=remote_version)):
                    self.perform_update()
            elif not silent:
                messagebox.showinfo(self.tr("info"), self.tr("update_not_found"))
                
        except Exception as e:
            print(f"Güncelleme kontrol hatası: {e}")
            if not silent:
                messagebox.showerror(self.tr("error"), f"{self.tr('update_error')}: {e}")

    def perform_update(self):
        """Güncellemeyi indir ve kur"""
        try:
            # 1. Yeni dosyayı indir
            import tempfile
            temp_dir = tempfile.gettempdir()
            new_exe_path = os.path.join(temp_dir, "LANMessenger_new.exe")
            
            self.add_message(self.tr("system"), "⬇️ Güncelleme indiriliyor, lütfen bekleyin...")
            
            urllib.request.urlretrieve(EXE_URL, new_exe_path)
            
            self.add_message(self.tr("system"), "✅ İndirme tamamlandı. Uygulama yeniden başlatılıyor...")
            
            # 2. Çalışan exe'nin yolu
            current_exe = sys.executable
            
            # 3. Updater script oluştur (Batch file)
            # Bu script:
            # - Uygulamanın kapanmasını bekler
            # - Eski exe'yi siler
            # - Yeni exe'yi eski exe'nin yerine taşır
            # - Yeni exe'yi başlatır
            # - Kendini siler
            
            updater_bat = os.path.join(temp_dir, "updater.bat")
            
            with open(updater_bat, "w") as f:
                f.write(f"""
@echo off
timeout /t 2 /nobreak >nul
del "{current_exe}"
move "{new_exe_path}" "{current_exe}"
start "" "{current_exe}"
del "%~f0"
""")
            
            # 4. Scripti çalıştır ve çık
            subprocess.Popen(updater_bat, shell=True)
            self.root.quit()
            
        except Exception as e:
            messagebox.showerror(self.tr("error"), f"Güncelleme hatası: {e}")
            
    def on_closing(self):
        """Pencere kapatılırken"""
        try:
            # Ayarları kaydet
            self.save_settings()
            
            # Bağlantıyı kes
            self.disconnect()
            
            # Ses kaynaklarını temizle
            if self.voice_input_stream:
                self.voice_input_stream.close()
            if self.voice_output_stream:
                self.voice_output_stream.close()
            
            self.audio.terminate()
            self.destroy()
        except:
            self.destroy()
            
    def run(self):
        """Uygulamayı çalıştır"""
        self.mainloop()

if __name__ == "__main__":
    try:
        # Uygulama başlat
        app = LANMessenger()
        app.run()
    except Exception as e:
        print(f"Uygulama başlatma hatası: {e}")
        input("Devam etmek için Enter'a basın...")
