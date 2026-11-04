#!/usr/bin/env python3
import subprocess
import re
import os
import sys

BASE_DIR = os.path.expanduser("~/termux-sec-agent")
TRUSTED_FILE = os.path.join(BASE_DIR, "trusted_macs.txt")
AUDIT_LOG = os.path.join(BASE_DIR, "network_audit.log")

SENSITIVE_PORTS = {
    5555: "ADB تصحيح لاسلكي",
    23: "Telnet غير مشفر",
    22: "SSH",
    80: "HTTP Web"
}

def send_alert(title, msg):
    try:
        subprocess.run(["termux-notification", "--title", title, "--content", msg], check=True)
    except Exception:
        print(f"[{title}] {msg}")

def load_trusted_macs():
    if not os.path.exists(TRUSTED_FILE):
        return set()
    with open(TRUSTED_FILE, "r") as f:
        return set(line.strip().upper() for line in f if line.strip() and not line.startswith("#"))

def scan_network_layer2():
    # إنعاش جدول ARP بشكل سريع ومتوازي
    subprocess.run("for i in $(seq 1 254); do ping -c 1 -W 1 192.168.8.$i >/dev/null 2>&1 & done; sleep 2", shell=True)
    
    # قراءة جدول الجيران
    devices = {}
    try:
        out = subprocess.check_output("ip neigh show", shell=True).decode()
        for line in out.splitlines():
            # استخراج IP و MAC
            m = re.search(r"([\d\.]+)\s+dev\s+\w+\s+lladdr\s+([a-fA-F0-9:]{17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).upper()
                devices[mac] = ip
    except Exception as e:
        print(f"[!] خطأ في قراءة جدول الجيران: {e}")
    return devices

def check_ports(ip):
    open_ports = []
    cmd = f"nmap -sT -p 22,23,80,5555 -T4 --open {ip}"
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=30).decode()
        for line in out.splitlines():
            pm = re.search(r"^(\d+)/tcp\s+open", line)
            if pm:
                open_ports.append(int(pm.group(1)))
    except Exception:
        pass
    return open_ports

def run_guard():
    print("[+] بدء تدقيق الشبكة...")
    active_devices = scan_network_layer2()
    trusted_macs = load_trusted_macs()

    new_intruders = []
    ports_alert = []

    report_lines = [f"إجمالي الأجهزة النشطة: {len(active_devices)}"]

    for mac, ip in active_devices.items():
        is_known = mac in trusted_macs
        status_tag = "موثوق" if is_known else "⚠️ دخيل/غير معروف"
        
        if not is_known:
            new_intruders.append(f"{ip} ({mac})")

        # فحص منافذ الجهاز
        ports = check_ports(ip)
        port_desc = [SENSITIVE_PORTS.get(p, f"Port {p}") for p in ports]
        
        if ports:
            ports_alert.append(f"{ip} [{', '.join(port_desc)}]")

        report_lines.append(f"  - IP: {ip:<15} MAC: {mac} [{status_tag}]")

    print("\n--- تقرير الفحص المحدث ---")
    full_report = "\n".join(report_lines)
    print(full_report)

    # حفظ في السجل
    with open(AUDIT_LOG, "a") as f:
        f.write(f"\n--- فحص بتاريخ جديد ---\n{full_report}\n")

    # إرسال التنبيهات
    if new_intruders:
        send_alert("🚨 تنبيه: جهاز جديد بالشبكة!", f"تم رصد: {new_intruders[0]}")
    elif ports_alert:
        send_alert("⚠️ منافذ مفتوحة مرصودة", f"{ports_alert[0]}")
    else:
        send_alert("حارس الشبكة", f"الشبكة آمنة: {len(active_devices)} أجهزة متصلة وموثوقة.")

if __name__ == "__main__":
    run_guard()
