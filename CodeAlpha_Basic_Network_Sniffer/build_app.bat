@echo off
echo ========================================
echo Building Network Sniffer Application
echo ========================================
echo.

echo Step 1: Installing dependencies...
pip install -r requirements.txt
echo.

echo Step 2: Creating executable...
python -m PyInstaller --onefile --name "NetworkSniffer" --icon=NONE network_sniffer.py
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Your application is ready at:
echo dist\NetworkSniffer.exe
echo.
echo To run: Right-click NetworkSniffer.exe and "Run as Administrator"
echo.
pause
