@echo off
echo Advanced LAN Messenger Kurulum Scripti
echo =====================================
echo.

echo Python ve pip kontrol ediliyor...
python --version >nul 2>&1
if errorlevel 1 (
    echo HATA: Python bulunamadi! Lutfen Python'u kurun.
    pause
    exit /b 1
)

echo.
echo Gerekli kutuphaneler kuruluyor...
echo.

#pip install customtkinter
#pip install pyaudio
#pip install Pillow

pip install -r requirements.txt

echo.
echo Kurulum tamamlandi!
echo.
echo Uygulamayi calistirmak icin: python LANMessenger.spec
echo.
pause
