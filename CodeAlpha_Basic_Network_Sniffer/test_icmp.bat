@echo off
echo ========================================
echo   ICMP Traffic Generator (Ping Test)
echo ========================================
echo.
echo This will generate ICMP packets for testing
echo Make sure your sniffer is running!
echo.
echo Pinging Google (8.8.8.8)...
ping 8.8.8.8 -n 10
echo.
echo Pinging Cloudflare (1.1.1.1)...
ping 1.1.1.1 -n 10
echo.
echo Done! Check your sniffer for ICMP packets.
pause
