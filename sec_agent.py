#!/usr/bin/env python3
import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

OUI_DATABASE = {
    "00:1E:10": "Huawei", "B0:D5:9D": "Huawei Technologies", "F4:C7:14": "Huawei", "D8:24:BD": "Huawei",
    "00:1A:11": "Google", "D4:F5:47": "Google",
    "AC:5F:3E": "Samsung", "34:42:62": "Samsung", "E4:7E:66": "Samsung",
    "64:A2:F9": "Xiaomi", "78:11:DC": "Xiaomi",
    "B4:60:77": "Apple", "F0:99:B6": "Apple",
    "24:0A:C4": "Espressif (ESP32/ESP8266)", "30:AE:A4": "Espressif",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
    "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
    "FC:EC:DA": "Ubiquiti", "00:27:22": "Ubiquiti",
    "00:0C:43": "Ralink Technology", "10:7B:44": "TP-Link", "50:D4:F7": "TP-Link"
}

def send_notification(title: str, content: str):
    """إرسال إشعار للنظام عبر termux-api"""
    try:
        subprocess.run([
            "termux-notification",
            "--title", title,
            "--content", content,
            "--priority", "high"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def load_known_hosts(filepath: str) -> set:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_known_hosts(filepath: str, hosts: set):
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sorted(list(hosts)), f, indent=4)
    except Exception:
        pass

def get_mac_address(ip: str) -> str:
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3].upper()
                        if mac != "00:00:00:00:00:00":
                            return mac
        res = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2)
        if res.returncode == 0 and "lladdr" in res.stdout:
            parts = res.stdout.strip().split()
            idx = parts.index("lladdr")
            return parts[idx + 1].upper()
    except Exception:
        pass
    return "Unknown"

def lookup_vendor(mac: str) -> str:
    if not mac or mac == "Unknown":
        return "Unknown"
    oui = ":".join(mac.split(":")[:3]).upper()
    return OUI_DATABASE.get(oui, "Generic / Unregistered Vendor")

def get_local_subnet() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return ".".join(s.getsockname()[0].split(".")[:3])
    except Exception:
        return "192.168.8"

def assess_risk(port_open: bool, meta: dict) -> tuple:
    if not port_open:
        return "LOW", "#10b981"
    if meta.get("model") != "Unknown":
        return "CRITICAL", "#ef4444"
    return "HIGH", "#f97316"

def export_html_report(report_data: dict, output_path: str):
    findings_rows = ""
    for item in report_data.get("findings", []):
        ip = item.get("ip", "N/A")
        mac = item.get("mac", "Unknown")
        vendor = item.get("vendor", "Unknown")
        port = item.get("port", "N/A")
        meta = item.get("fingerprint", {})
        model = meta.get("model", "Unknown")
        android = meta.get("android_version", "Unknown")
        risk_level = item.get("risk_level", "UNKNOWN")
        risk_color = item.get("risk_color", "#94a3b8")

        findings_rows += f"""
        <tr>
            <td>{ip}</td>
            <td><code>{mac}</code></td>
            <td>{vendor}</td>
            <td>{port}</td>
            <td><span class="badge" style="background-color: {risk_color}; color: #fff;">{risk_level}</span></td>
            <td>{model}</td>
            <td>{android}</td>
        </tr>
        """

    if not findings_rows:
        findings_rows = "<tr><td colspan='7' style='text-align:center;'>No open targets discovered.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Report - {report_data.get('subnet')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .card {{ max-width: 1000px; margin: auto; background: #1e293b; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ color: #38bdf8; margin-top: 0; font-size: 1.5rem; }}
        .meta {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #cbd5e1; }}
        code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>TermuxSecAgent Audit Report</h1>
        <div class="meta">
            Target: <strong>{report_data.get('subnet')}</strong> | 
            Port: <strong>{report_data.get('port')}</strong> | 
            Generated: {report_data.get('timestamp')} | 
            Duration: {report_data.get('scan_duration_seconds')}s
        </div>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Vendor</th>
                    <th>Port</th>
                    <th>Risk Level</th>
                    <th>Device Model</th>
                    <th>Android Version</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

class TermuxSecAgent:
    def __init__(self, subnet=None, adb_port=5555, max_threads=25, out_dir="reports"):
        if not subnet or subnet.lower() == "auto":
            self.subnet = get_local_subnet()
            print(f"[*] Auto-detected local subnet: {self.subnet}.0/24")
        else:
            self.subnet = subnet

        self.adb_port = int(adb_port)
        self.max_threads = max_threads
        self.report_dir = out_dir
        self.log_dir = "logs"
        self.state_file = os.path.join(self.log_dir, "known_hosts.json")
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def log(self, msg: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(os.path.join(self.log_dir, "agent.log"), "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")

    def run_cmd(self, cmd_list, timeout=10):
        try:
            res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout, check=False)
            return {"success": res.returncode == 0, "stdout": res.stdout.strip(), "stderr": res.stderr.strip()}
        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e)}

    def check_port(self, ip: str, timeout=1.0) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, self.adb_port)) == 0
        except Exception:
            return False

    def fingerprint_device(self, ip: str) -> dict:
        target = f"{ip}:{self.adb_port}"
        info = {"model": "Unknown", "android_version": "Unknown"}
        conn = self.run_cmd(["adb", "connect", target], timeout=6)
        if conn["success"] and "connected" in conn["stdout"].lower():
            m = self.run_cmd(["adb", "-s", target, "shell", "getprop", "ro.product.model"])
            if m["success"]:
                info["model"] = m["stdout"]
            v = self.run_cmd(["adb", "-s", target, "shell", "getprop", "ro.build.version.release"])
            if v["success"]:
                info["android_version"] = v["stdout"]
            self.run_cmd(["adb", "disconnect", target], timeout=3)
        return info

    def scan_subnet(self, stealth_mode=False, output_format="json", silent_progress=False) -> list:
        if not silent_progress:
            print(f"[*] Scanning Subnet: {self.subnet}.0/24 | Target Port: {self.adb_port}")
        workers = 1 if stealth_mode else self.max_threads
        discovered_targets = []
        start_time = datetime.now()

        scanned_count = 0
        def probe(last_octet):
            nonlocal scanned_count
            target_ip = f"{self.subnet}.{last_octet}"
            if stealth_mode:
                time.sleep(random.uniform(0.1, 0.4))
            if self.check_port(target_ip):
                if not silent_progress:
                    sys.stdout.write(f"\r[!] Discovered: {target_ip}:{self.adb_port}           \n")
                    sys.stdout.flush()
                discovered_targets.append(target_ip)
            scanned_count += 1
            if not silent_progress:
                sys.stdout.write(f"\r[*] Scanning progress: [{scanned_count}/254] hosts...")
                sys.stdout.flush()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            executor.map(probe, range(1, 255))
        if not silent_progress:
            print()

        findings = []
        for host in discovered_targets:
            meta = self.fingerprint_device(host)
            mac = get_mac_address(host)
            vendor = lookup_vendor(mac)
            risk_label, risk_color = assess_risk(True, meta)

            findings.append({
                "ip": host,
                "mac": mac,
                "vendor": vendor,
                "port": self.adb_port,
                "risk_level": risk_label,
                "risk_color": risk_color,
                "fingerprint": meta
            })

        duration = (datetime.now() - start_time).total_seconds()
        report_data = {
            "subnet": f"{self.subnet}.0/24",
            "port": self.adb_port,
            "stealth": stealth_mode,
            "scan_duration_seconds": round(duration, 2),
            "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings
        }

        base_name = f"audit_{self.subnet.replace('.', '_')}_{start_time.strftime('%Y%m%d_%H%M%S')}"

        if output_format in ["json", "both"]:
            json_path = os.path.join(self.report_dir, f"{base_name}.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)
            if not silent_progress:
                print(f"[+] JSON report saved: {json_path}")

        if output_format in ["html", "both"]:
            html_path = os.path.join(self.report_dir, f"{base_name}.html")
            export_html_report(report_data, html_path)
            if not silent_progress:
                print(f"[+] HTML report saved: {html_path}")

        return findings

    def run_daemon(self, interval_seconds=300, stealth=False, output_format="json"):
        print(f"[+] Daemon mode active. Monitoring every {interval_seconds}s (Press Ctrl+C to stop)...")
        known = load_known_hosts(self.state_file)
        self.log(f"Daemon started. Known hosts count: {len(known)}")

        try:
            while True:
                current_time = datetime.now().strftime("%H:%M:%S")
                print(f"[{current_time}] Running scheduled network check...")
                
                # فحص الشبكة
                findings = self.scan_subnet(stealth_mode=stealth, output_format=output_format, silent_progress=True)
                current_hosts = {f["ip"] for f in findings}
                
                # كشف الأجهزة الجديدة
                new_hosts = current_hosts - known
                if new_hosts:
                    for new_ip in new_hosts:
                        alert_msg = f"New target detected: {new_ip}:{self.adb_port}"
                        print(f"[ALERT] {alert_msg}")
                        self.log(alert_msg)
                        send_notification("Security Alert - New Target", alert_msg)
                    
                    # تحديث السجل المحفوظ
                    known.update(new_hosts)
                    save_known_hosts(self.state_file, known)
                else:
                    print(f"[{current_time}] No new targets detected. Sleeping for {interval_seconds}s.")

                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n[*] Stopping daemon mode cleanly.")
            self.log("Daemon stopped by user.")

def parse_args():
    parser = argparse.ArgumentParser(description="TermuxSecAgent CLI")
    parser.add_argument("-s", "--subnet", default="auto", help="Subnet (default: auto)")
    parser.add_argument("-p", "--port", type=int, default=5555, help="Port (default: 5555)")
    parser.add_argument("--stealth", action="store_true", help="Slow single-thread scan")
    parser.add_argument("-o", "--format", choices=["json", "html", "both"], default="json")
    parser.add_argument("--out-dir", default="reports", help="Reports directory")
    parser.add_argument("--daemon", action="store_true", help="Run in periodic background daemon mode")
    parser.add_argument("--interval", type=int, default=300, help="Interval in seconds for daemon checks (default: 300)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    agent = TermuxSecAgent(subnet=args.subnet, adb_port=args.port, out_dir=args.out_dir)
    
    if args.daemon:
        agent.run_daemon(interval_seconds=args.interval, stealth=args.stealth, output_format=args.format)
    else:
        agent.scan_subnet(stealth_mode=args.stealth, output_format=args.format)
