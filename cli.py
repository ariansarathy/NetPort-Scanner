#!/usr/bin/env python3
"""
NetPort Scanner — CLI Interface
Usage:
    python cli.py <host> [options]

Examples:
    python cli.py 192.168.1.1
    python cli.py scanme.nmap.org --range 1-10000 --threads 300 --export json
    python cli.py example.com --range 80-443 --export csv --output results
"""

import argparse
import sys
import os
import time
from scanner import run_scan, export_json, export_csv

# ANSI color codes
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


BANNER = f"""{CYAN}{BOLD}
 ███╗   ██╗███████╗████████╗██████╗  ██████╗ ██████╗ ████████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
 ██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██████╔╝   ██║   
 ██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██║   ██║██╔══██╗   ██║   
 ██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝██║  ██║   ██║   
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
            {RESET}{YELLOW}TCP Port Scanner | github.com/netport-scanner{RESET}
"""


def parse_range(range_str: str) -> tuple:
    """Parse a port range string like '1-1024' into a tuple."""
    try:
        parts = range_str.split("-")
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError
        return (start, end)
    except (ValueError, IndexError):
        print(f"{RED}[ERROR] Invalid port range '{range_str}'. Use format: start-end (e.g. 1-1024){RESET}")
        sys.exit(1)


def progress_bar(current: int, total: int, width: int = 40) -> str:
    filled = int(width * current / total)
    bar = "█" * filled + "░" * (width - filled)
    pct = current / total * 100
    return f"\r[{bar}] {pct:.1f}% ({current}/{total})"


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="NetPort Scanner — TCP port scanning utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("host", help="Target IP address or hostname")
    parser.add_argument("--range", dest="port_range", default="1-1024",
                        help="Port range to scan (default: 1-1024)")
    parser.add_argument("--threads", type=int, default=200,
                        help="Number of concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--export", choices=["json", "csv", "both"],
                        help="Export results to file (json/csv/both)")
    parser.add_argument("--output", default="scan_results",
                        help="Output filename without extension (default: scan_results)")
    parser.add_argument("--no-banner", action="store_true",
                        help="Disable ASCII banner")

    args = parser.parse_args()
    port_range = parse_range(args.port_range)
    found_open = []

    print(f"{BOLD}Target  :{RESET} {args.host}")
    print(f"{BOLD}Range   :{RESET} {args.port_range}")
    print(f"{BOLD}Threads :{RESET} {args.threads}")
    print(f"{BOLD}Timeout :{RESET} {args.timeout}s")
    print(f"\n{CYAN}{'─' * 60}{RESET}")
    print(f"{YELLOW}[*] Starting scan...{RESET}\n")

    def on_progress(scanned, total, result):
        if result["state"] == "open":
            found_open.append(result)
            svc = result["service"]
            port = result["port"]
            print(f"\r{GREEN}[OPEN]{RESET} Port {BOLD}{port:>5}{RESET}  →  {CYAN}{svc}{RESET}")
        sys.stdout.write(progress_bar(scanned, total))
        sys.stdout.flush()

    results = run_scan(
        host=args.host,
        port_range=port_range,
        max_threads=args.threads,
        timeout=args.timeout,
        progress_callback=on_progress,
    )

    if "error" in results:
        print(f"\n{RED}[ERROR] {results['error']}{RESET}")
        sys.exit(1)

    # Final newline after progress bar
    print(f"\n\n{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}SCAN COMPLETE{RESET}")
    print(f"{CYAN}{'─' * 60}{RESET}")
    print(f"  Host            : {results['host']} ({results['ip']})")
    print(f"  Ports Scanned   : {results['total_ports_scanned']}")
    print(f"  Open Ports      : {GREEN}{results['open_count']}{RESET}")
    print(f"  Duration        : {results['duration_seconds']}s")
    print(f"{CYAN}{'─' * 60}{RESET}\n")

    if results["open_ports"]:
        print(f"{BOLD}{'PORT':<8} {'SERVICE':<18} {'SECURITY NOTE'}{RESET}")
        print("─" * 75)
        for p in results["open_ports"]:
            port_col  = f"{CYAN}{p['port']:<8}{RESET}"
            svc_col   = f"{p['service']:<18}"
            rec_col   = p["recommendation"]
            print(f"{port_col}{svc_col}{rec_col}")
            if p.get("banner"):
                print(f"         {YELLOW}Banner: {p['banner'][:80]}{RESET}")
        print()
    else:
        print(f"{YELLOW}No open ports found in range {args.port_range}.{RESET}\n")

    # Exports
    if args.export:
        os.makedirs("reports", exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base = f"reports/{args.output}_{timestamp}"

        if args.export in ("json", "both"):
            path = f"{base}.json"
            export_json(results, path)
            print(f"{GREEN}[✓] JSON report saved → {path}{RESET}")

        if args.export in ("csv", "both"):
            path = f"{base}.csv"
            export_csv(results, path)
            print(f"{GREEN}[✓] CSV report saved  → {path}{RESET}")
        print()


if __name__ == "__main__":
    main()
