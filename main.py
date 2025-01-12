import socket

# Function to scan the ports
def scan_ports(ip):
    open_ports = []
    ports_to_scan = [21, 22, 23, 80, 443, 3389]  # List of common ports to scan
    
    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

# Main function
def main():
    ip = input("Enter the IP address to scan: ")
    open_ports = scan_ports(ip)
    
    if open_ports:
        print(f"Open ports on {ip}: {open_ports}")
    else:
        print(f"No open ports found on {ip}.")

if __name__ == "__main__":
    main()
