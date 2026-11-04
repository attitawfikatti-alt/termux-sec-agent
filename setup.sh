#!/data/data/com.termux/files/usr/bin/bash

echo "[*] Updating repositories..."
pkg update -y

echo "[*] Installing dependencies..."
pkg install -y python git android-tools termux-api

echo "[*] Setting execution permissions..."
chmod +x sec_agent.py

echo "[*] Creating required directories..."
mkdir -p logs reports

echo "[+] Ready! Run: python sec_agent.py"
