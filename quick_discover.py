#!/usr/bin/env python3
import subprocess
import re

def get_connected_hosts():
    # 1. إرسال Ping سريع لإنعاش جدول ARP
    subnet_base = "192.168.8."
    print("[+] جاري إرسال نداءات استكشاف خفيفة لتحديث جدول الشبكة...")
    subprocess.run(f"for i in $(seq 1 254); do ping -c 1 -W 1 {subnet_base}$i >/dev/null 2>&1 & done; sleep 2", shell=True)

    # 2. قراءة جدول الجيران (IP + MAC)
    try:
        output = subprocess.check_output("ip neigh show", shell=True).decode()
    except Exception:
        output = ""

    hosts = []
    for line in output.splitlines():
        # صيغة السطر: 192.168.8.x dev wlan0 lladdr xx:xx:xx:xx:xx:xx REACHABLE/STALE
        match = re.search(r"([\d\.]+)\s+dev\s+\w+\s+lladdr\s+([a-fA-F0-9:]{17})", line)
        if match:
            ip, mac = match.groups()
            hosts.append((ip, mac.upper()))

    return hosts

if __name__ == "__main__":
    devices = get_connected_hosts()
    print(f"\n--- الأجهزة المرصودة عبر جدول ARP ({len(devices)}) ---")
    for ip, mac in devices:
        print(f"IP: {ip:<15} | MAC: {mac}")
