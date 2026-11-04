#!/usr/bin/env python3
import time
import subprocess
import psutil
import os

# خريطة العمليات وأوامر تشغيلها التلقائي عند التوقف
# المفتاح: المعرّف المكتشف، القيمة: أمر الإطلاق
SERVICES = {
    "sshd": "sshd",
    "net_guardian.py": "nohup python3 ~/termux-sec-agent/net_guardian.py > /dev/null 2>&1 &",
    "net_radar.py": "nohup python3 ~/termux-sec-agent/net_radar.py > /dev/null 2>&1 &"
}

CPU_THRESHOLD = 85.0
RAM_THRESHOLD = 75.0
CHECK_INTERVAL = 15

def send_alert(title, msg):
    try:
        subprocess.run(["termux-notification", "--title", title, "--content", msg], check=True)
    except Exception:
        print(f"[{title}] {msg}")

def restart_service(target):
    cmd = SERVICES.get(target)
    if cmd:
        try:
            os.system(cmd)
            send_alert("إعادة تشغيل", f"تمت محاولة إعادة تشغيل {target} تلقائياً.")
        except Exception as e:
            send_alert("فشل التشغيل", f"تعذر تشغيل {target}: {e}")

def monitor():
    send_alert("Watchdog", "بدأت المراقبة الذكية بنجاح مع ميزة إعادة التشغيل.")
    print("Watchdog with auto-restart is running... Press Ctrl+C to stop.")
    down = set()

    while True:
        try:
            procs = {}
            for p in psutil.process_iter(['name', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    cmd = " ".join(p.info['cmdline'] or [])
                    name = p.info['name']
                    for t in SERVICES.keys():
                        if t == name or (cmd and t in cmd):
                            procs.setdefault(t, []).append(p)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            for t in SERVICES.keys():
                if t not in procs:
                    if t not in down:
                        send_alert("توقف خدمة", f"الخدمة {t} متوقفة! جاري إعادة التشغيل...")
                        restart_service(t)
                        down.add(t)
                else:
                    if t in down:
                        send_alert("استعادة خدمة", f"عادت {t} للعمل بنجاح.")
                        down.remove(t)
                    
                    for p in procs[t]:
                        try:
                            if p.cpu_percent() > CPU_THRESHOLD:
                                send_alert("ضغط معالج", f"{t} تجاوزت الحد المسموح.")
                            if p.memory_percent() > RAM_THRESHOLD:
                                send_alert("ضغط ذاكرة", f"{t} تجاوزت حد الرام.")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            print("\nتم إيقاف المراقبة.")
            break

if __name__ == "__main__":
    monitor()
