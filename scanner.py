"""
NetPort Scanner - Core scanning engine
"""

import socket
import threading
import json
import csv
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# Common services mapped to ports
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    1723: "PPTP VPN", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt2", 9200: "Elasticsearch",
    27017: "MongoDB", 6443: "Kubernetes API",
}

# Security recommendations per service
SECURITY_TIPS = {
    "FTP":        "⚠️  FTP transmits credentials in plain text. Replace with SFTP or FTPS.",
    "Telnet":     "🚨 Telnet is insecure. Migrate to SSH immediately.",
    "SSH":        "✅ SSH is generally secure. Ensure key-based auth is enforced.",
    "HTTP":       "⚠️  Unencrypted HTTP. Consider enforcing HTTPS with a redirect.",
    "HTTPS":      "✅ HTTPS enabled. Verify TLS certificate validity.",
    "RDP":        "🚨 RDP exposed publicly is a critical risk. Restrict with a VPN or firewall.",
    "SMB":        "🚨 SMB exposed publicly is dangerous (EternalBlue). Block port 445 at firewall.",
    "MySQL":      "⚠️  Database port exposed. Restrict to localhost or trusted IPs only.",
    "PostgreSQL": "⚠️  Database port exposed. Restrict to localhost or trusted IPs only.",
    "MongoDB":    "🚨 MongoDB with no auth has caused major breaches. Restrict access immediately.",
    "Redis":      "🚨 Redis often has no auth by default. Bind to localhost and add a password.",
    "VNC":        "⚠️  VNC can be brute-forced. Use strong passwords and restrict access via VPN.",
    "NetBIOS":    "⚠️  NetBIOS can leak system info. Disable if not needed on public interfaces.",
    "DNS":        "✅ DNS port open. Ensure it's not an open resolver to prevent amplification attacks.",
    "Elasticsearch": "🚨 Elasticsearch has no auth by default. Restrict immediately.",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Attempt a TCP connection to determine if a port is open."""
    result = {
        "port": port,
        "state": "closed",
        "service": SERVICE_MAP.get(port, "Unknown"),
        "banner": None,
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            conn = sock.connect_ex((host, port))
            if conn == 0:
                result["state"] = "open"
                # Try banner grabbing
                try:
                    sock.settimeout(0.5)
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    result["banner"] = banner[:200] if banner else None
                except Exception:
                    pass
    except (socket.timeout, socket.error, OSError):
        pass
    return result


def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP. Returns None on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def run_scan(
    host: str,
    port_range: tuple = (1, 1024),
    max_threads: int = 200,
    timeout: float = 1.0,
    progress_callback=None,
) -> dict:
    """
    Run a full port scan against `host`.

    Returns a result dictionary with metadata and open ports.
    """
    start_time = datetime.now()

    resolved_ip = resolve_host(host)
    if not resolved_ip:
        return {"error": f"Could not resolve host: {host}"}

    start_port, end_port = port_range
    total_ports = end_port - start_port + 1
    open_ports = []
    scanned = 0
    lock = threading.Lock()

    def _scan(port):
        nonlocal scanned
        res = scan_port(resolved_ip, port, timeout)
        with lock:
            scanned += 1
            if progress_callback:
                progress_callback(scanned, total_ports, res)
        return res

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_scan, p): p for p in range(start_port, end_port + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    # Attach security recommendations
    for entry in open_ports:
        svc = entry["service"]
        entry["recommendation"] = SECURITY_TIPS.get(svc, "ℹ️  Review whether this port needs to be publicly accessible.")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    return {
        "host": host,
        "ip": resolved_ip,
        "scan_range": f"{start_port}-{end_port}",
        "total_ports_scanned": total_ports,
        "open_count": len(open_ports),
        "open_ports": open_ports,
        "scan_started": start_time.isoformat(),
        "scan_finished": end_time.isoformat(),
        "duration_seconds": round(duration, 2),
    }


def export_json(results: dict, filepath: str):
    """Export scan results to a JSON file."""
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)


def export_csv(results: dict, filepath: str):
    """Export open ports to a CSV file."""
    fieldnames = ["port", "service", "state", "banner", "recommendation"]
    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for port_info in results.get("open_ports", []):
            writer.writerow({k: port_info.get(k, "") for k in fieldnames})
