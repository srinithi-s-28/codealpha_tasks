# Build Standalone Application

## Quick Build (Easiest Method)

1. Double-click `build_app.bat`
2. Wait for build to complete
3. Find your app in `dist\NetworkSniffer.exe`
4. Right-click `NetworkSniffer.exe` and select "Run as Administrator"

---

## Manual Build

```powershell
# Step 1: Install dependencies
pip install -r requirements.txt

# Step 2: Build executable
pyinstaller --onefile --name "NetworkSniffer" network_sniffer.py

# Step 3: Run the app
cd dist
# Right-click NetworkSniffer.exe and Run as Administrator
```

---

## Output

- NetworkSniffer.exe - Standalone application (no Python installation required)
- Location: `dist\NetworkSniffer.exe`
- Size: Approximately 15-20 MB
- Portable: Can be copied to any Windows PC

---

## Important Notes

1. Must run as Administrator (required for packet capture)
2. Install Npcap first: https://npcap.com/#download
3. Antivirus software may flag the executable (packet sniffers commonly trigger security alerts)

---

## Distribution

You can share `NetworkSniffer.exe` with others. Requirements:
- Windows Operating System
- Npcap installed
- Administrator privileges to run

No Python installation required for end users.
