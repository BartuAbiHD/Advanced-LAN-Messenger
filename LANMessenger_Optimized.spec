# -*- mode: python ; coding: utf-8 -*-
# Optimized PyInstaller spec file for Advanced LAN Messenger
# Bu dosya LAN Messenger uygulaması için özelleştirilmiştir

# Önemli Notlar:
# 1. CustomTkinter için hidden imports eklendi
# 2. PyAudio ses desteği için gerekli modüller dahil edildi  
# 3. PIL/Pillow görüntü işleme desteği eklendi
# 4. Gereksiz modüller hariç tutularak boyut optimizasyonu yapıldı
# 5. UPX sıkıştırması etkinleştirildi

import os
import sys

a = Analysis(
    ['LANMessenger.py'],
    pathex=[],
    binaries=[],
    datas=[
        # CustomTkinter tema dosyaları gerektiğinde otomatik eklenir
        ('icon.ico', '.')
    ],
    hiddenimports=[
        # CustomTkinter için gerekli modüller
        'customtkinter',
        'customtkinter.windows',
        'customtkinter.windows.widgets',
        'customtkinter.widgets',
        'customtkinter.widgets.ctk_button',
        'customtkinter.widgets.ctk_frame',
        'customtkinter.widgets.ctk_label',
        'customtkinter.widgets.ctk_entry',
        'customtkinter.widgets.ctk_textbox',
        'customtkinter.widgets.ctk_slider',
        'customtkinter.widgets.ctk_combobox',
        'customtkinter.widgets.ctk_toplevel',
        
        # PyAudio ses kütüphanesi
        'pyaudio',
        '_cffi_backend',
        
        # PIL/Pillow görüntü işleme
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        
        # Tkinter GUI modülleri
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.filedialog',
        'tkinter.font',
        
        # Standart Python modülleri
        'socket',
        'threading',
        'json',
        'datetime',
        'wave',
        'io',
        'os',
        'sys',
        'time',
        
        # Yeni eklenen modüller
        'winreg',
        'pystray',
        'cryptography',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.fernet',
        'tkinterdnd2',
        'base64',
        'struct',
        'pathlib',
        'locale',
        'winsound',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Gereksiz büyük modüller (boyut optimizasyonu)
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'jupyter',
        'notebook',
        'IPython',
        'pytest',
        'test',
        'tests',
        'unittest',
        'doctest',
        'email',
        'http',
        'urllib3',
        'certifi',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Advanced LAN Messenger',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # Dosya boyutunu küçültmek için UPX sıkıştırması
    upx_exclude=[
        # Ses kütüphanelerini UPX'den hariç tut (uyumluluk için)
        '*.pyd',
        '*pyaudio*',
        '*cffi*',
        '*tkinter*',
    ],
    runtime_tmpdir=None,
    console=False,  # GUI uygulaması (konsol penceresi açılmaz)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    
    # İsteğe bağlı - icon ve version dosyası ekleyebilirsiniz
    icon='icon.ico',  # Uygulamanın icon dosyası
    # version='version.txt',  # Sürüm bilgisi dosyası
)
