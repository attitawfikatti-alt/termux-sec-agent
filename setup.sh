#!/data/data/com.termux/files/usr/bin/bash
echo "[*] Installing dependencies..."
pkg update -y && pkg install -y python git android-tools termux-api
chmod +x agent.py
mkdir -p logs reports
echo "[+] Ready. Run: python agent.py --help"
