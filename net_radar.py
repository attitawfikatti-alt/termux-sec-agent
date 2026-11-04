import socket
import struct
import ipaddress
import datetime
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

console = Console()

TARGET_PORTS = {
    5555: "ADB Wireless",
    80: "HTTP Web",
    443: "HTTPS",
    22: "SSH",
    53: "DNS"
}

def get_default_gateway_and_subnet():
    try:
        with open("/proc/net/route", "r") as f:
            for line in f:
                fields = line.strip().split()
                if len(fields) >= 3 and fields[1] == "00000000":
                    gateway_hex = fields[2]
                    gateway_ip = socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))
                    network = ipaddress.ip_network(f"{gateway_ip}/24", strict=False)
                    return gateway_ip, str(network)
    except Exception:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            gateway_guess = str(network.network_address + 1)
            return gateway_guess, str(network)
    except Exception:
        return "192.168.8.1", "192.168.8.0/24"

def check_port(ip, port, timeout=0.6):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except:
        return False

def scan_host(ip):
    open_ports = []
    for port, desc in TARGET_PORTS.items():
        if check_port(ip, port):
            open_ports.append(f"{port} ({desc})")
    
    hostname = "Unknown"
    if open_ports or check_port(ip, 80, 0.3):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except:
            pass
        return {"ip": str(ip), "hostname": hostname, "ports": open_ports}
    return None

def run_radar(subnet_cidr):
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    hosts = list(net.hosts())
    results = []

    console.print(f"[bold cyan]🔍 فحص نطاق الشبكة:[/bold cyan] [bold yellow]{subnet_cidr}[/bold yellow]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[green]جاري مسح العناوين والمنافذ...", total=len(hosts))
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_host, host): host for host in hosts}
            for f in futures:
                res = f.result()
                if res and res["ports"]:
                    results.append(res)
                progress.advance(task)

    table = Table(title="📡 نتائج رادار الشبكة المحلية", border_style="bright_blue", show_lines=True)
    table.add_column("عنوان IP", style="bold cyan", width=16)
    table.add_column("الاسم (Hostname)", style="white", width=20)
    table.add_column("المنافذ المفتوحة والخدمات", style="green")

    for r in results:
        ports_str = ", ".join(r["ports"]) if r["ports"] else "لا توجد منافذ مفتوحة"
        table.add_row(r["ip"], r["hostname"], ports_str)

    console.print(table)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_dir = os.path.expanduser("~/reports")
    os.makedirs(reports_dir, exist_ok=True)
    report_file = os.path.join(reports_dir, f"radar_report_{timestamp}.md")

    with open(report_file, "w", encoding="utf-8") as rf:
        rf.write(f"# تقرير فحص الرادار: {subnet_cidr}\n")
        rf.write(f"**التاريخ:** `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n\n")
        rf.write("| عنوان IP | الاسم المستعار | المنافذ المفتوحة |\n| :--- | :--- | :--- |\n")
        for r in results:
            rf.write(f"| `{r['ip']}` | {r['hostname']} | {', '.join(r['ports'])} |\n")

    console.print(f"[bold green]✔[/bold green] تم حفظ التقرير في: [dim]{report_file}[/dim]\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "":
        cidr = sys.argv[1]
    else:
        gw_ip, auto_cidr = get_default_gateway_and_subnet()
        console.print(f"[bold green]✔[/bold green] تم التعرف على البوابة الافتراضية تلقائياً: [bold yellow]{gw_ip}[/bold yellow]")
        cidr = auto_cidr

    run_radar(cidr)
