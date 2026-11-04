#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

class TermuxSecAgent:
    def __init__(self, subnet="192.168.8", adb_port=5555, max_threads=25):
        self.subnet = subnet
        self.adb_port = int(adb_port)
        self.max_threads = max_threads
        self.report_dir = "reports"
        self.log_dir = "logs"
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def log(self, msg: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(os.path.join(self.log_dir, "agent.log"), "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")

    def notify(self, title: str, text: str):
        """إرسال إشعار للنظام عبر حزمة termux-api إذا كانت متوفرة"""
        try:
            subprocess.run([
                "termux-notification",
                "--title", title,
                "--content", text,
                "--priority", "high"
            ], capture_output=True, timeout=5, check=False)
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

    def run_cmd(self, cmd_list, timeout=12):
        """تنفيذ أوامر النظام بشكل آمن ومعالجة الاستثناءات"""
        try:
            res = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return {
                "success": res.returncode == 0,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
                "returncode": res.returncode
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stdout": "", "stderr": f"Timeout ({timeout}s)", "returncode": -1}
        except FileNotFoundError:
            return {"success": False, "stdout": "", "stderr": f"Tool '{cmd_list[0]}' missing", "returncode": -2}

    def check_port(self, ip: str, timeout=1.0) -> bool:
        """فحص سريع للمنفذ عبر socket"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, self.adb_port)) == 0
        except (socket.timeout, socket.gaierror, OSError):
            return False

    def fingerprint_device(self, ip: str) -> dict:
        """الاتصال بـ ADB وسحب خصائص النظام الأساسية"""
        target = f"{ip}:{self.adb_port}"
        info = {"connected": False, "model": "Unknown", "android_version": "Unknown", "device_name": "Unknown"}

        conn = self.run_cmd(["adb", "connect", target], timeout=8)
        if conn["success"] and "connected" in conn["stdout"].lower():
            info["connected"] = True
            
            # جلب تفاصيل النظام
            model = self.run_cmd(["adb", "-s", target, "shell", "getprop", "ro.product.model"])
            if model["success"]:
                info["model"] = model["stdout"]

            version = self.run_cmd(["adb", "-s", target, "shell", "getprop", "ro.build.version.release"])
            if version["success"]:
                info["android_version"] = version["stdout"]

            name = self.run_cmd(["adb", "-s", target, "shell", "getprop", "net.hostname"])
            if name["success"]:
                info["device_name"] = name["stdout"]

            # قطع الاتصال بعد جلب المعلومات لعدم إبقاء الجلسة معلقة
            self.run_cmd(["adb", "disconnect", target], timeout=5)

        return info

    def scan_subnet(self):
        """فحص النطاق الفرعي بالكامل باستخدام الخيوط المتزامنة (Threads)"""
        print(f"[*] Starting audit on subnet: {self.subnet}.0/24 (Target Port: {self.adb_port})")
        self.log(f"Subnet scan initiated for {self.subnet}.0/24")

        start_time = datetime.now()
        discovered_targets = []

        def probe(last_octet):
            target_ip = f"{self.subnet}.{last_octet}"
            if self.check_port(target_ip):
                print(f"[!] Vulnerable/Open Port: {target_ip}:{self.adb_port}")
                discovered_targets.append(target_ip)

        # فحص جميع عناوين الشبكة من 1 إلى 254 بالتوازي
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(probe, range(1, 255))

        print(f"\n[*] Found {len(discovered_targets)} hosts with open port {self.adb_port}.")

        # جمع البصمات لكل جهاز تم اكتشافه
        detailed_findings = []
        for host in discovered_targets:
            print(f"[*] Fingerprinting host: {host}...")
            meta = self.fingerprint_device(host)
            finding = {
                "ip": host,
                "port": self.adb_port,
                "fingerprint": meta
            }
            detailed_findings.append(finding)
            self.notify("TermuxSecAgent Alert", f"Discovered open host: {host} ({meta['model']})")

        # إنشاء وحفظ التقرير الشامل
        duration = (datetime.now() - start_time).total_seconds()
        report = {
            "subnet": f"{self.subnet}.0/24",
            "port": self.adb_port,
            "scan_duration_seconds": round(duration, 2),
            "timestamp": start_time.isoformat(),
            "targets_found_count": len(detailed_findings),
            "findings": detailed_findings
        }

        report_file = os.path.join(
            self.report_dir,
            f"subnet_audit_{self.subnet.replace('.', '_')}_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        print(f"[+] Audit completed in {duration:.2f}s")
        print(f"[+] Full JSON Report: {report_file}")
        self.log(f"Subnet audit complete. Found {len(detailed_findings)} hosts.")

if __name__ == "__main__":
    # تمرير السابنت والمنفذ كمدخلات اختيارية: python agent.py 192.168.8 5555
    target_subnet = sys.argv[1] if len(sys.argv) > 1 else "192.168.8"
    port_to_scan = int(sys.argv[2]) if len(sys.argv) > 2 else 5555

    agent = TermuxSecAgent(subnet=target_subnet, adb_port=port_to_scan)
    agent.scan_subnet()
