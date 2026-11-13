#!/usr/bin/env python3
import argparse, json, os, random, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

VERSION = "1.1.0"
FALLBACK_OUI = {"00:1E:10": "Huawei", "AC:5F:3E": "Samsung", "64:A2:F9": "Xiaomi", "B4:60:77": "Apple", "10:7B:44": "TP-Link", "44:5E:F3": "Hisense / VIDAA Smart TV"}
COMMON_AUDIT_PORTS = {
    22: ("SSH", "Enforce key-based auth and disable password login."),
    23: ("Telnet", "CRITICAL: Unencrypted legacy protocol. Disable Telnet immediately."),
    53: ("DNS", "Verify local DNS resolver is not exposed externally."),
    80: ("HTTP Admin", "Check router/device web panel uses strong credentials."),
    443: ("HTTPS Admin", "Verify TLS certificate and admin access controls."),
    5555: ("Wireless ADB", "CRITICAL: Disable Wireless ADB when not actively debugging."),
    8008: ("Smart Cast/TV", "Smart TV / Chromecast local control endpoint active."),
    8080: ("HTTP Alt", "Review web service running on alternate port 8080.")
}

def load_oui_database(filepath="oui_vendors.json") -> dict:
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return FALLBACK_OUI

OUI_DATABASE = load_oui_database()

def load_trusted_macs(filepath="trusted_macs.txt") -> set:
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath)
    trusted = set()
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    c = line.strip().split("#")[0].strip().upper()
                    if len(c) == 17:
                        trusted.add(c)
        except Exception:
            pass
    return trusted

def send_notification(title: str, content: str):
    try:
        subprocess.run(["termux-notification", "--title", title, "--content", content, "--priority", "high"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception: pass

def load_known_hosts(filepath: str) -> set:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f: return set(json.load(f))
        except Exception: return set()
    return set()

def save_known_hosts(filepath: str, hosts: set):
    try:
        with open(filepath, "w", encoding="utf-8") as f: json.dump(sorted(list(hosts)), f, indent=4)
    except Exception: pass

def get_mac_address(ip: str) -> str:
    try:
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                        return parts[3].upper()
        res = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2)
        if res.returncode == 0 and "lladdr" in res.stdout:
            parts = res.stdout.strip().split()
            return parts[parts.index("lladdr") + 1].upper()
    except Exception: pass
    return "Unknown"

def lookup_vendor(mac: str) -> str:
    if not mac or mac == "Unknown": return "Unknown"
    return OUI_DATABASE.get(":".join(mac.split(":")[:3]).upper(), "Generic / Unregistered Vendor")

def get_local_subnet() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return ".".join(s.getsockname()[0].split(".")[:3])
    except Exception: return "192.168.8"

def assess_risk(open_ports: list, meta: dict, is_trusted: bool) -> tuple:
    if 5555 in open_ports or 23 in open_ports:
        if meta.get("model") != "Unknown":
            return "CRITICAL", "#ef4444", "Exposed Wireless ADB. Disable ADB over network immediately."
        return "HIGH", "#f97316", "Sensitive management port (ADB/Telnet) open on LAN."
    if not is_trusted:
        return "MEDIUM", "#eab308", "Unrecognized MAC address. Verify device ownership."
    if open_ports:
        return "LOW", "#38bdf8", "Trusted device with standard local services."
    return "SAFE", "#10b981", "No exposed management ports detected."

def export_html_report(report_data: dict, output_path: str):
    rows = ""
    for item in report_data.get("findings", []):
        trust = "<span class='badge' style='background:#10b981;'>TRUSTED</span>" if item.get("trusted") else "<span class='badge' style='background:#64748b;'>UNVERIFIED</span>"
        ports = ", ".join(map(str, item.get("open_ports", []))) or "None"
        model = item.get("fingerprint", {}).get("model", "Unknown")
        rows += f"<tr><td><strong>{item.get('ip')}</strong></td><td><code>{item.get('mac')}</code><br>{trust}</td><td>{item.get('vendor')}</td><td><code>{ports}</code></td><td><span class='badge' style='background:{item.get('risk_color')};'>{item.get('risk_level')}</span></td><td>{model}</td><td style='font-size:0.85rem;color:#cbd5e1;'>{item.get('remediation')}</td></tr>"
    if not rows:
        rows = "<tr><td colspan='7' style='text-align:center;'>No active targets or open ports discovered.</td></tr>"
    css = "body{font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:20px}.card{max-width:1150px;margin:auto;background:#1e293b;border-radius:10px;padding:24px}h1{color:#38bdf8;margin-top:0}table{width:100%;border-collapse:collapse;margin-top:15px}th,td{padding:12px;text-align:left;border-bottom:1px solid #334155}th{background:#0f172a}.badge{display:inline-block;margin-top:4px;padding:3px 8px;border-radius:4px;font-weight:bold;font-size:0.75rem;color:#fff}code{background:#0f172a;padding:2px 6px;border-radius:4px;color:#38bdf8}"
    html = f"<!DOCTYPE html><html><head><meta charset='UTF-8'><title>TermuxSecAgent v{VERSION}</title><style>{css}</style></head><body><div class='card'><h1>TermuxSecAgent v{VERSION} Audit Report</h1><p style='color:#94a3b8'>Target: <b>{report_data.get('subnet')}</b> | Mode: <b>{report_data.get('scan_mode')}</b> | {report_data.get('timestamp')} ({report_data.get('scan_duration_seconds')}s)</p><table><thead><tr><th>IP</th><th>MAC & Trust</th><th>Vendor</th><th>Open Ports</th><th>Risk</th><th>Device</th><th>Remediation</th></tr></thead><tbody>{rows}</tbody></table></div></body></html>"
    with open(output_path, "w", encoding="utf-8") as f: f.write(html)

class TermuxSecAgent:
    def __init__(self, subnet=None, adb_port=5555, max_threads=25, out_dir="reports"):
        self.subnet = get_local_subnet() if (not subnet or subnet.lower() == "auto") else subnet
        if not subnet or subnet.lower() == "auto": print(f"[*] Auto-detected local subnet: {self.subnet}.0/24")
        self.adb_port, self.max_threads, self.report_dir, self.log_dir = int(adb_port), max_threads, out_dir, "logs"
        self.state_file = os.path.join(self.log_dir, "known_hosts.json")
        self.trusted_macs = load_trusted_macs()
        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def log(self, msg: str):
        with open(os.path.join(self.log_dir, "agent.log"), "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")

    def run_cmd(self, cmd_list, timeout=10):
        try:
            res = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout, check=False)
            return {"success": res.returncode == 0, "stdout": res.stdout.strip(), "stderr": res.stderr.strip()}
        except Exception as e: return {"success": False, "stdout": "", "stderr": str(e)}

    def check_port(self, ip: str, port: int, timeout=0.8) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception: return False

    def fingerprint_device(self, ip: str, port: int) -> dict:
        target, info = f"{ip}:{port}", {"model": "Unknown", "android_version": "Unknown"}
        if port != 5555: return info
        conn = self.run_cmd(["adb", "connect", target], timeout=5)
        if conn["success"] and "connected" in conn["stdout"].lower():
            m = self.run_cmd(["adb", "-s", target, "shell", "getprop", "ro.product.model"])
            if m["success"] and m["stdout"]: info["model"] = m["stdout"]
            v = self.run_cmd(["adb", "-s", target, "shell", "getprop", "ro.build.version.release"])
            if v["success"] and v["stdout"]: info["android_version"] = v["stdout"]
            self.run_cmd(["adb", "disconnect", target], timeout=3)
        return info

    def scan_subnet(self, stealth_mode=False, audit_ports=False, output_format="json", silent_progress=False) -> list:
        ports_to_check = sorted(list(COMMON_AUDIT_PORTS.keys())) if audit_ports else [self.adb_port]
        mode_label = f"Multi-Port Audit ({len(ports_to_check)} ports)" if audit_ports else f"Single Port ({self.adb_port})"
        if not silent_progress:
            print(f"[*] TermuxSecAgent v{VERSION} | Subnet: {self.subnet}.0/24 | Mode: {mode_label}")
        workers = 1 if stealth_mode else self.max_threads
        discovered_map, start_time, scanned_count = {}, datetime.now(), 0

        def probe(last_octet):
            nonlocal scanned_count
            target_ip = f"{self.subnet}.{last_octet}"
            open_for_host = []
            for p in ports_to_check:
                if stealth_mode: time.sleep(random.uniform(0.08, 0.25))
                if self.check_port(target_ip, p): open_for_host.append(p)
            if open_for_host:
                discovered_map[target_ip] = open_for_host
                if not silent_progress:
                    sys.stdout.write(f"\r[!] Active Host: {target_ip} -> Open Ports: {open_for_host}      \n")
                    sys.stdout.flush()
            scanned_count += 1
            if not silent_progress:
                sys.stdout.write(f"\r[*] Scanning progress: [{scanned_count}/254] hosts...")
                sys.stdout.flush()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            executor.map(probe, range(1, 255))
        if not silent_progress: print()

        findings = []
        for host, open_ports in sorted(discovered_map.items()):
            meta = self.fingerprint_device(host, 5555) if 5555 in open_ports else {"model": "Unknown", "android_version": "Unknown"}
            mac = get_mac_address(host)
            vendor = lookup_vendor(mac)
            is_trusted = (mac in self.trusted_macs) if mac != "Unknown" else False
            risk_label, risk_color, remediation = assess_risk(open_ports, meta, is_trusted)
            services = [f"{p}/{COMMON_AUDIT_PORTS[p][0]}" if p in COMMON_AUDIT_PORTS else str(p) for p in open_ports]

            findings.append({
                "ip": host, "mac": mac, "trusted": is_trusted, "vendor": vendor,
                "port": open_ports[0], "open_ports": open_ports, "services": services,
                "risk_level": risk_label, "risk_color": risk_color,
                "remediation": remediation, "fingerprint": meta
            })

        duration = (datetime.now() - start_time).total_seconds()
        report_data = {
            "version": VERSION, "subnet": f"{self.subnet}.0/24", "scan_mode": mode_label,
            "port": self.adb_port, "stealth": stealth_mode,
            "scan_duration_seconds": round(duration, 2),
            "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings
        }

        base_name = f"audit_{self.subnet.replace('.', '_')}_{start_time.strftime('%Y%m%d_%H%M%S')}"
        if output_format in ["json", "both"]:
            json_path = os.path.join(self.report_dir, f"{base_name}.json")
            with open(json_path, "w", encoding="utf-8") as f: json.dump(report_data, f, indent=4)
            if not silent_progress: print(f"[+] JSON report saved: {json_path}")
        if output_format in ["html", "both"]:
            html_path = os.path.join(self.report_dir, f"{base_name}.html")
            export_html_report(report_data, html_path)
            if not silent_progress: print(f"[+] HTML report saved: {html_path}")
        return findings

    def run_daemon(self, interval_seconds=300, stealth=False, audit_ports=False, output_format="json"):
        print(f"[+] Daemon v{VERSION} active. Monitoring every {interval_seconds}s (Press Ctrl+C to stop)...")
        known = load_known_hosts(self.state_file)
        self.log(f"Daemon v{VERSION} started. Known hosts: {len(known)} | Trusted MACs: {len(self.trusted_macs)}")

        try:
            while True:
                current_time = datetime.now().strftime("%H:%M:%S")
                print(f"[{current_time}] Running scheduled defensive audit...")
                findings = self.scan_subnet(stealth_mode=stealth, audit_ports=audit_ports, output_format=output_format, silent_progress=True)
                current_hosts = {f["ip"] for f in findings}

                new_hosts = current_hosts - known
                if new_hosts:
                    for item in findings:
                        if item["ip"] in new_hosts:
                            trust_tag = "TRUSTED" if item["trusted"] else "UNVERIFIED"
                            alert_msg = f"New host {item['ip']} ({item['vendor']} | {trust_tag}) Ports: {item['open_ports']}"
                            print(f"[ALERT] {alert_msg}")
                            self.log(alert_msg)
                            send_notification("TermuxSecAgent Alert", alert_msg)

                    known.update(new_hosts)
                    save_known_hosts(self.state_file, known)
                else:
                    print(f"[{current_time}] No new hosts detected. Sleeping for {interval_seconds}s.")

                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n[*] Stopping daemon mode cleanly.")
            self.log("Daemon stopped by user.")

def parse_args():
    parser = argparse.ArgumentParser(description=f"TermuxSecAgent v{VERSION} — Defensive Mobile LAN Auditor")
    parser.add_argument("-v", "--version", action="version", version=f"TermuxSecAgent {VERSION}")
    parser.add_argument("-s", "--subnet", default="auto", help="Subnet (default: auto)")
    parser.add_argument("-p", "--port", type=int, default=5555, help="Single target port (default: 5555)")
    parser.add_argument("--audit-ports", action="store_true", help="Audit common sensitive LAN ports (22,23,53,80,443,5555,8008,8080)")
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
        agent.run_daemon(interval_seconds=args.interval, stealth=args.stealth, audit_ports=args.audit_ports, output_format=args.format)
    else:
        agent.scan_subnet(stealth_mode=args.stealth, audit_ports=args.audit_ports, output_format=args.format)
