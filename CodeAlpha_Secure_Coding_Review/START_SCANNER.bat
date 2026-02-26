@echo off
title Secure Code Scanner
color 0A
echo.
echo ========================================
echo   SECURE CODE SCANNER
echo ========================================
echo.
echo Starting application...
echo.
python SecureScanner.py
if errorlevel 1 (
    echo.
    echo ERROR: Failed to start!
    echo Make sure Python is installed.
    pause
)
