#!/usr/bin/env python3
import json
import os
import socket
import subprocess
import sys
from datetime import datetime

class TermuxSecAgent:
    def __init__(self, target_ip="192.168.8.1", adb_port=5555):
        self.target_ip = target_ip
        self.adb_port = adb_port
        self.target_str = f"{self.target_ip}:{self.adb_port}"
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def run_cmd(self, cmd_list, timeout=15):
        try:
            result = subprocess.run(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            return "ERROR_TIMEOUT", -1
        except FileNotFoundError:
            return f"ERROR_TOOL_NOT_FOUND: {cmd_list[0]}", -2

    def check_socket_port(self, host, port, timeout=2):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0

    def scan_ports(self, ports=[21, 22, 23, 80, 5555, 8080]):
        print(f"[*] جاري فحص المنافذ على المضيف: {self.target_ip}...")
        open_ports = []
        for port in ports:
            is_open = self.check_socket_port(self.target_ip, port)
            if is_open:
                open_ports.append(port)
                print(f" [+] منفذ مفتوح: {port}")
        return open_ports

    def ensure_adb_connection(self):
        print(f"[*] التحقق من اتصال ADB مع {self.target_str}...")
        stdout, _ = self.run_cmd(["adb", "devices"])

        if self.target_str in stdout and "device" in stdout:
            print("[+] الجهاز متصل وجاهز لتنفيذ الأوامر.")
            return True

        if "unauthorized" in stdout:
            print("[!] الجهاز يرفض الاتصال (unauthorized). يرجى تأكيد إذن التصحيح على شاشة الهدف.")
            return False

        print(f"[*] محاولة الاتصال بـ {self.target_str}...")
        stdout, _ = self.run_cmd(["adb", "connect", self.target_str])

        if "connected to" in stdout.lower() and "already" not in stdout.lower():
            print("[+] تم إنشاء الاتصال بنجاح.")
            return True
        elif "already connected" in stdout.lower():
            return True
        else:
            print(f"[-] فشل الاتصال: {stdout}")
            return False

    def execute_adb_shell(self, command):
        stdout, code = self.run_cmd(["adb", "-s", self.target_str, "shell", command])
        return stdout if code == 0 else ""

    def audit_target(self):
        print("[*] جاري جمع المؤشرات الأمنية عبر ADB Shell...")
        audit_data = {}

        id_output = self.execute_adb_shell("id")
        audit_data["root_privileges"] = "uid=0(root)" in id_output

        audit_data["device_model"] = self.execute_adb_shell("getprop ro.product.model")
        audit_data["android_version"] = self.execute_adb_shell("getprop ro.build.version.release")

        pkg_output = self.execute_adb_shell("pm list packages -3")
        audit_data["third_party_packages"] = [
            line.replace("package:", "").strip()
            for line in pkg_output.splitlines() if line
        ]

        netstat_output = self.execute_adb_shell("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null")
        audit_data["internal_listening_ports"] = [
            line.strip() for line in netstat_output.splitlines() if "LISTEN" in line
        ]

        return audit_data

    def run(self):
        start_time = datetime.now()
        report = {
            "target": self.target_ip,
            "timestamp": start_time.isoformat(),
            "open_network_ports": [],
            "adb_connected": False,
            "system_audit": {}
        }

        report["open_network_ports"] = self.scan_ports()

        if self.adb_port in report["open_network_ports"]:
            if self.ensure_adb_connection():
                report["adb_connected"] = True
                report["system_audit"] = self.audit_target()
        else:
            print(f"[-] المنفذ {self.adb_port} غير مفتوح. تم تجاوز فحص ADB.")

        filename = f"{self.report_dir}/audit_{self.target_ip}_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(f"\n[✓] اكتمل الفحص. تم حفظ التقرير في: {filename}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.8.1"
    agent = TermuxSecAgent(target_ip=target)
    agent.run()
