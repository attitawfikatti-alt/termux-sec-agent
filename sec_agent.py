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

def export_html_report(report_data: dict, output_path: str):
    """توليد ملف HTML منسق يعرض نتائج الفحص"""
    findings_rows = ""
    for item in report_data.get("findings", []):
        ip = item.get("ip", "N/A")
        port = item.get("port", "N/A")
        meta = item.get("fingerprint", {})
        model = meta.get("model", "Unknown")
        android = meta.get("android_version", "Unknown")

        findings_rows += f"""
        <tr>
            <td>{ip}</td>
            <td>{port}</td>
            <td><span class="badge open">OPEN</span></td>
            <td>{model}</td>
            <td>{android}</td>
        </tr>
        """

    if not findings_rows:
        findings_rows = "<tr><td colspan='5' style='text-align:center;'>No open targets discovered.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Report - {report_data.get('subnet')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .card {{ max-width: 900px; margin: auto; background: #1e293b; border-radius: 8px; padding: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        h1 {{ color: #38bdf8; margin-top: 0; font-size: 1.5rem; }}
        .meta {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #cbd5e1; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; }}
        .open {{ background: #ef4444; color: white; }}
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
                    <th>Port</th>
                    <th>Status</th>
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
    def __init__(self, subnet="192.168.8", adb_port=5555, max_threads=25, out_dir="reports"):
        self.subnet = subnet
        self.adb_port = int(adb_port)
        self.max_threads = max_threads
        self.report_dir = out_dir
        self.log_dir = "logs"
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def log(self, msg: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(os.path.join(self.log_dir, "agent.log"), "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")

    def run_cmd(self, cmd_list, timeout=10):
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
                "stderr": res.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "stdout": "", "stderr": "Timeout"}
        except FileNotFoundError:
            return {"success": False, "stdout": "", "stderr": f"Tool '{cmd_list[0]}' missing"}

    def check_port(self, ip: str, timeout=1.0) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, self.adb_port)) == 0
        except (socket.timeout, socket.gaierror, OSError):
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

    def scan_subnet(self, stealth_mode=False, output_format="json"):
        print(f"[*] Subnet: {self.subnet}.0/24 | Target Port: {self.adb_port}")
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
                sys.stdout.write(f"\r[!] Discovered: {target_ip}:{self.adb_port}           \n")
                sys.stdout.flush()
                discovered_targets.append(target_ip)
            scanned_count += 1
            sys.stdout.write(f"\r[*] Scanning progress: [{scanned_count}/254] hosts...")
            sys.stdout.flush()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            executor.map(probe, range(1, 255))
        print()

        findings = []
        for host in discovered_targets:
            meta = self.fingerprint_device(host)
            findings.append({"ip": host, "port": self.adb_port, "fingerprint": meta})

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
            print(f"[+] JSON report saved: {json_path}")

        if output_format in ["html", "both"]:
            html_path = os.path.join(self.report_dir, f"{base_name}.html")
            export_html_report(report_data, html_path)
            print(f"[+] HTML report saved: {html_path}")

def parse_args():
    parser = argparse.ArgumentParser(description="TermuxSecAgent CLI")
    parser.add_argument("-s", "--subnet", default="192.168.8", help="Subnet (default: 192.168.8)")
    parser.add_argument("-p", "--port", type=int, default=5555, help="Port (default: 5555)")
    parser.add_argument("--stealth", action="store_true", help="Slow single-thread scan")
    parser.add_argument("-o", "--format", choices=["json", "html", "both"], default="json")
    parser.add_argument("--out-dir", default="reports", help="Reports directory")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    agent = TermuxSecAgent(
        subnet=args.subnet,
        adb_port=args.port,
        out_dir=args.out_dir
    )
    agent.scan_subnet(stealth_mode=args.stealth, output_format=args.format)
