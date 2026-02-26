@echo off
echo ========================================
echo   NETWORK SNIFFER - WEB APPLICATION
echo ========================================
echo.
echo Installing Flask...
pip install flask
echo.
echo Starting web server...
echo.
echo Open your browser and go to:
echo http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo ========================================
echo.
python web_sniffer.py
pause
