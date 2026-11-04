#!/usr/bin/env python3
import subprocess
import re
import os
import json

BASE_DIR = os.path.expanduser("~/termux-sec-agent")
TRUSTED_FILE = os.path.join(BASE_DIR, "trusted_macs.txt")
AUDIT_LOG = os.path.join(BASE_DIR, "network_audit.log")
TRACKER_FILE = os.path.join(BASE_DIR, "missing_tracker.json")

# عنوان بوابة الراوتر الافتراضية
ROUTER_IP = "192.168.8.1"
MISSING_THRESHOLD = 3

TARGET_PORTS = {
    5555: "ADB Wireless Debugging",
    22: "SSH Server",
    23: "Telnet",
    80: "HTTP Web Management",
    8080: "HTTP Proxy/Alternative Web"
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

def load_tracker():
    if os.path.exists(TRACKER_FILE):
        try:
            with open(TRACKER_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_tracker(tracker):
    with open(TRACKER_FILE, "w") as f:
        json.dump(tracker, f)

def scan_network_layer2():
    subprocess.run("for i in $(seq 1 254); do ping -c 1 -W 1 192.168.8.$i >/dev/null 2>&1 & done; sleep 2", shell=True)
    devices = {}
    try:
        out = subprocess.check_output("ip neigh show", shell=True).decode()
        for line in out.splitlines():
            m = re.search(r"([\d\.]+)\s+dev\s+\w+\s+lladdr\s+([a-fA-F0-9:]{17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).upper()
                devices[mac] = ip
    except Exception as e:
        print(f"[!] خطأ في فحص جدول الجيران: {e}")
    return devices

def audit_target_ports(ip):
    open_found = {}
    ports_str = ",".join(str(p) for p in TARGET_PORTS.keys())
    cmd = f"nmap -sT -p {ports_str} -T4 --open {ip}"
    try:
        out = subprocess.check_output(cmd, shell=True, timeout=25).decode()
        for line in out.splitlines():
            pm = re.search(r"^(\d+)/tcp\s+open", line)
            if pm:
                p_num = int(pm.group(1))
                open_found[p_num] = TARGET_PORTS.get(p_num, "خدمة غير معروفة")
    except Exception:
        pass
    return open_found

def run_guard():
    print("[+] بدء تدقيق أمان الشبكة والمنافذ الحساسة...")
    active_devices = scan_network_layer2()
    trusted_macs = load_trusted_macs()
    tracker = load_tracker()

    active_macs = set(active_devices.keys())
    new_intruders = []
    adb_foreign_vulnerable = []
    confirmed_missing = []

    report_lines = [f"إجمالي الأجهزة النشطة: {len(active_devices)}"]

    for mac, ip in active_devices.items():
        is_known = mac in trusted_macs
        status_tag = "موثوق" if is_known else "⚠️ دخيل/غير معروف"
        
        if mac in tracker:
            del tracker[mac]

        if not is_known:
            new_intruders.append(f"{ip} ({mac})")

        open_ports = audit_target_ports(ip)
        port_notes = []
        if open_ports:
            for p, desc in open_ports.items():
                port_notes.append(f"Port {p} ({desc})")
                # رصد ADB الخطر فقط إذا كان على جهاز طرفي وليس الراوتر المعروف
                if p == 5555 and ip != ROUTER_IP:
                    adb_foreign_vulnerable.append(f"{ip} ({mac})")

        extra_info = f" -> [منافذ مفتوحة: {', '.join(port_notes)}]" if port_notes else ""
        report_lines.append(f"  - IP: {ip:<15} MAC: {mac} [{status_tag}]{extra_info}")

    missing_now = trusted_macs - active_macs
    for mm in missing_now:
        tracker[mm] = tracker.get(mm, 0) + 1
        count = tracker[mm]
        if count >= MISSING_THRESHOLD:
            confirmed_missing.append(mm)
            report_lines.append(f"  - ⚠️ غياب مؤكد ({count} دورات): MAC {mm}")
        else:
            report_lines.append(f"  - ⏳ في وضع خمول مؤقت ({count}/{MISSING_THRESHOLD}): MAC {mm}")

    save_tracker(tracker)

    full_report = "\n".join(report_lines)
    print("\n--- تقرير الفحص والتدقيق ---")
    print(full_report)

    with open(AUDIT_LOG, "a") as f:
        f.write(f"\n--- فحص تدقيق أمني ---\n{full_report}\n")

    # توجيه التنبيهات
    if adb_foreign_vulnerable:
        send_alert("🚨 ثغرة أمنية حرجة!", f"جهاز طرفي يفتح ADB: {adb_foreign_vulnerable[0]}")
    elif new_intruders:
        send_alert("🚨 جهاز غريب بالشبكة!", f"تم رصد: {new_intruders[0]}")
    elif confirmed_missing:
        send_alert("⚠️ انقطاع مؤكد لجهاز موثوق!", f"انقطع اتصال {len(confirmed_missing)} أجهزة مسجلة")
    else:
        print("[✓] الوضع مستقر ولا توجد تهديدات طارئة.")

if __name__ == "__main__":
    run_guard()
