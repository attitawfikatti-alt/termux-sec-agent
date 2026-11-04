import socket
import struct
import ipaddress
import datetime
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

TARGET_PORTS = {
    80: "HTTP Web",
    443: "HTTPS",
    22: "SSH",
    53: "DNS",
    5555: "ADB Wireless",
    8080: "HTTP Proxy/Alt",
    445: "SMB/Windows",
    8008: "Chromecast/SmartTV"
}

REPORTS_DIR = os.path.expanduser("~/reports")


def get_default_gateway_and_subnet():
    try:
        with open("/proc/net/arp") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] == '00000000':
                    gw_hex = fields[2]
                    gateway_ip = socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
                    network = ipaddress.ip_network(f"{gateway_ip}/24", strict=False)
                    return str(network), gateway_ip
    except Exception as e:
        console.print(f"[bold red]تعذر تحديد البوابة تلقائياً: {e}[/]")
    return None, None


def check_port(ip, port, timeout=0.3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        s.close()
    return None


def get_hostname(ip):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, socket.timeout):
        return "غير معروف"


def scan_single_host(ip_str):
    open_ports = []
    for port, name in TARGET_PORTS.items():
        if check_port(ip_str, port):
            open_ports.append(f"{port} ({name})")
    
    if open_ports:
        hostname = get_hostname(ip_str)
        return {
            "ip": ip_str,
            "hostname": hostname,
            "ports": open_ports
        }
    return None


def save_report(active_devices, network_target):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORTS_DIR, f"radar_report_{timestamp}.md")

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# تقرير فحص الشبكة المحلية\n\n")
        f.write(f"- **النطاق المستهدف:** `{network_target}`\n")
        f.write(f"- **تاريخ الفحص:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **عدد الأجهزة المكتشفة:** {len(active_devices)}\n\n")
        f.write("| عنوان IP | الاسم (Hostname) | المنافذ المفتوحة |\n")
        f.write("|---|---|---|\n")

        for d in active_devices:
            ports_str = ", ".join(d["ports"])
            f.write(f"| {d['ip']} | {d['hostname']} | {ports_str} |\n")

    return report_path


def main():
    if len(sys.argv) > 1:
        target_input = sys.argv[1]
    else:
        auto_subnet, _ = get_default_gateway_and_subnet()
        if auto_subnet:
            console.print(f"[bold yellow]لم يتم تحديد نطاق، تم اكتشاف النطاق تلقائياً: {auto_subnet}[/]")
            target_input = auto_subnet
        else:
            console.print("[bold red]يرجى تحديد النطاق: python3 net_radar.py <IP/CIDR>[/]")
            sys.exit(1)

    try:
        network = ipaddress.ip_network(target_input, strict=False)
        hosts = [str(ip) for ip in network.hosts()] if network.num_addresses > 1 else [target_input]
    except ValueError as e:
        console.print(f"[bold red]صيغة النطاق أو الـ IP غير صالحة: {e}[/]")
        sys.exit(1)

    console.print(f"[bold cyan]🔍 فحص نطاق الشبكة:[/] {target_input}")

    active_hosts = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} ({task.percentage:>3.0f}%)"),
        console=console
    ) as progress:
        task = progress.add_task("  جاري مسح العناوين والمنافذ...", total=len(hosts))
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            for result in executor.map(scan_single_host, hosts):
                if result:
                    active_hosts.append(result)
                progress.advance(task)

    console.print("\n         📡 [bold green]نتائج رادار الشبكة المحلية[/]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("عنوان IP", style="cyan", width=16)
    table.add_column("الاسم (Hostname)", style="green", width=20)
    table.add_column("المنافذ المفتوحة", style="white")

    for host in active_hosts:
        table.add_row(host["ip"], host["hostname"], "\n".join(host["ports"]))

    console.print(table)

    report_file = save_report(active_hosts, target_input)
    console.print(f"\n[bold green]✔ تم حفظ التقرير في:[/]\n{report_file}\n")


if __name__ == "__main__":
    main()
