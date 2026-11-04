#!/usr/bin/env python3
import time
import subprocess
import os

SERVICES = {
    "sshd": "sshd",
    "net_guardian.py": "nohup python3 ~/termux-sec-agent/net_guardian.py > /dev/null 2>&1 &",
    "net_radar.py": "nohup python3 ~/termux-sec-agent/net_radar.py > /dev/null 2>&1 &"
}

CHECK_INTERVAL = 15

def is_running(service_name):
    try:
        res = subprocess.run(["pgrep", "-f", service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        my_pid = str(os.getpid())
        pids = [p for p in res.stdout.strip().split() if p and p != my_pid]
        return len(pids) > 0
    except Exception:
        return False

def send_alert(title, msg):
    try:
        subprocess.run(["termux-notification", "--title", title, "--content", msg], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [ALERT: {title}] {msg}", flush=True)

def restart_service(target):
    cmd = SERVICES.get(target)
    if cmd:
        try:
            os.system(cmd)
            send_alert("إعادة تشغيل", f"تمت محاولة إعادة تشغيل {target} تلقائياً.")
        except Exception as e:
            send_alert("خطأ تشغيل", f"فشل تشغيل {target}: {e}")

def monitor():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [✓] بدء تشغيل منظومة المراقبة Watchdog بنجاح.", flush=True)
    down = set()
    while True:
        try:
            for s in SERVICES:
                running = is_running(s)
                if not running:
                    if s not in down:
                        send_alert("توقف خدمة", f"الخدمة {s} متوقفة! جاري إعادة التشغيل...")
                        restart_service(s)
                        down.add(s)
                else:
                    if s in down:
                        send_alert("استعادة خدمة", f"عادت {s} للعمل بنجاح.")
                        down.remove(s)

            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [✓] فحص دوري سليم - كافة الخدمات نشطة ومراقبة.", flush=True)
            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] [!] تم إيقاف المراقبة.", flush=True)
            break

if __name__ == "__main__":
    monitor()
