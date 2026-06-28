#!/usr/bin/env python3
"""
Professional Multi-threaded Port Scanner
Built for cybersecurity portfolio and ethical security practice.

Author: MurtezaSelim
License: MIT
"""

import argparse
import socket
import concurrent.futures
import json
import csv
import sys
from datetime import datetime
from typing import List, Tuple, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None

# Common well-known ports and services
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS-SSN", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}


def get_service_name(port: int) -> str:
    """Return common service name for a port."""
    return SERVICE_MAP.get(port, "unknown")


def scan_port(target_ip: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """Scan a single TCP port. Returns (port, is_open, banner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                banner = ""
                try:
                    sock.settimeout(0.8)
                    data = sock.recv(1024)
                    banner = data.decode('utf-8', errors='ignore').strip()[:200]
                except (socket.timeout, ConnectionResetError, OSError):
                    banner = "(no banner)"
                return port, True, banner
    except (socket.gaierror, socket.error, OSError, PermissionError):
        pass
    return port, False, ""


def parse_ports(ports_arg: str) -> List[int]:
    """Parse port argument: 'common', '1-1000', '22,80,443', or mixed."""
    ports = set()
    if ports_arg.lower() == "common":
        return COMMON_PORTS
    parts = ports_arg.replace(" ", "").split(",")
    for part in parts:
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.update(range(max(1, start), min(65535, end) + 1))
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(list(ports)) if ports else COMMON_PORTS


def display_results_rich(open_ports: List[Tuple[int, str, str]], target: str, start_time: datetime, duration: float):
    """Display results using Rich library."""
    console = Console()
    table = Table(title=f"Scan Results for {target}", show_header=True, header_style="bold magenta")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Status", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Banner / Info", style="dim", max_width=50)

    for port, service, banner in open_ports:
        status = "[bold green]OPEN[/bold green]"
        table.add_row(str(port), status, service, banner or "-")

    console.print(table)
    console.print(f"\n[bold]Scan Summary[/bold]")
    console.print(f"[green]✔ Open ports found: {len(open_ports)}[/green]")
    console.print(f"[blue]⏱ Duration: {duration:.2f} seconds")


def display_results_plain(open_ports: List[Tuple[int, str, str]], target: str, start_time: datetime, duration: float):
    """Fallback plain text display."""
    print(f"\n=== Scan Results for {target} ===")
    print(f"{'Port':<8} {'Status':<10} {'Service':<15} {'Banner':<50}")
    print("-" * 85)
    for port, service, banner in open_ports:
        print(f"{port:<8} {'OPEN':<10} {service:<15} {banner[:47] if banner else '-':<50}")
    print("\n=== Summary ===")
    print(f"Open ports found: {len(open_ports)}")
    print(f"Duration: {duration:.2f} seconds")


def export_results(open_ports: List[Tuple[int, str, str]], target: str, filename: str):
    """Export results to JSON, CSV or TXT based on file extension."""
    data = []
    for port, service, banner in open_ports:
        data.append({
            "port": port,
            "status": "open",
            "service": service,
            "banner": banner,
            "target": target,
            "timestamp": datetime.now().isoformat()
        })

    if filename.endswith(".json"):
        with open(filename, "w") as f:
            json.dump({"target": target, "results": data, "scan_time": datetime.now().isoformat()}, f, indent=2)
        print(f"[INFO] Results exported to {filename}")
    elif filename.endswith(".csv"):
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "status", "service", "banner", "target", "timestamp"])
            writer.writeheader()
            writer.writerows(data)
        print(f"[INFO] Results exported to {filename}")
    elif filename.endswith(".txt"):
        with open(filename, "w") as f:
            f.write(f"Port Scanner Results for {target}\n")
            f.write("=" * 50 + "\n")
            for item in data:
                f.write(f"Port {item['port']}: {item['service']} - {item['banner']}\n")
        print(f"[INFO] Results exported to {filename}")
    else:
        print("[WARNING] Unsupported export format. Use .json, .csv or .txt")


def main():
    parser = argparse.ArgumentParser(
        description="Professional Multi-threaded Port Scanner | Cybersecurity Portfolio Project",
        epilog="Ethical use only. Scan only systems you own or have permission to test."
    )
    parser.add_argument("--target", required=True, help="Target hostname or IP address")
    parser.add_argument("--ports", default="common", help="Ports to scan (e.g. 'common', '1-1000', '22,80,443')")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--output", help="Export results to file (.json, .csv, .txt)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output and show banners")
    parser.add_argument("--no-rich", action="store_true", help="Force plain text output")

    args = parser.parse_args()

    use_rich = RICH_AVAILABLE and not args.no_rich

    if use_rich:
        console = Console()
        console.print("[bold blue]🔍 Professional Port Scanner[/bold blue]")
    else:
        print("=== Professional Port Scanner ===")

    # Resolve target
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[ERROR] Could not resolve hostname: {args.target}")
        sys.exit(1)

    ports_to_scan = parse_ports(args.ports)

    if use_rich:
        rprint(f"[cyan]Target:[/cyan] {args.target} ({target_ip})")
        rprint(f"[cyan]Ports to scan:[/cyan] {len(ports_to_scan)} | Threads: {args.threads}")
    else:
        print(f"Target: {args.target} ({target_ip})")
        print(f"Ports: {len(ports_to_scan)} | Threads: {args.threads}")

    start_time = datetime.now()

    open_ports = []

    # Use progress bar if rich available
    if use_rich:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=Console()
        ) as progress:
            task = progress.add_task("Scanning ports...", total=len(ports_to_scan))
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                future_to_port = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports_to_scan}
                for future in concurrent.futures.as_completed(future_to_port):
                    port, is_open, banner = future.result()
                    if is_open:
                        service = get_service_name(port)
                        open_ports.append((port, service, banner))
                    progress.update(task, advance=1)
    else:
        print("Scanning... (this may take a while)")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_port = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    service = get_service_name(port)
                    open_ports.append((port, service, banner))

    duration = (datetime.now() - start_time).total_seconds()
    open_ports.sort(key=lambda x: x[0])

    # Display
    if use_rich:
        display_results_rich(open_ports, args.target, start_time, duration)
    else:
        display_results_plain(open_ports, args.target, start_time, duration)

    # Export if requested
    if args.output:
        export_results(open_ports, args.target, args.output)

    if use_rich:
        rprint("\n[bold green]✅ Scan complete![/bold green]")
        rprint("[dim]Remember: Use responsibly and only on authorized targets.[/dim]")
    else:
        print("\nScan complete! Use responsibly.")

if __name__ == "__main__":
    main()
