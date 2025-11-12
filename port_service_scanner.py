import socket
import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
DEFAULT_PORTS = range(1, 1025)  # Common ports; change to range(1, 65536) for full scan
TIMEOUT = 1  # Socket timeout in seconds
MAX_THREADS = 100  # Concurrent threads for speed

def resolve_target(target):
    """Resolve domain to IP if needed."""
    try:
        ipaddress.ip_address(target)  # Check if already an IP
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            raise ValueError(f"Unable to resolve {target}")

def scan_port(target_ip, port, results, lock):
    """Scan a single port and attempt service identification."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((target_ip, port))
        if result == 0:  # Port is open
            service = identify_service(sock, port)
            with lock:
                results[port] = service
        sock.close()
    except Exception as e:
        pass  # Ignore errors for simplicity

def identify_service(sock, port):
    """Attempt to identify service via banner grabbing."""
    try:
        if port == 80 or port == 443:  # HTTP/HTTPS
            sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            if "HTTP" in banner:
                return f"HTTP Service (Banner: {banner.split('\n')[0]})"
        elif port == 21:  # FTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return f"FTP (Banner: {banner.strip()})"
        elif port == 22:  # SSH
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return f"SSH (Banner: {banner.strip()})"
        elif port == 25:  # SMTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return f"SMTP (Banner: {banner.strip()})"
        else:
            # Generic banner grab
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return f"Unknown Service (Banner: {banner[:50]}...)" if banner else "Open Port (No Banner)"
    except:
        return "Open Port (Banner Grab Failed)"
    return "Open Port"

def port_scan(target, ports=DEFAULT_PORTS):
    """Perform the port scan."""
    target_ip = resolve_target(target)
    print(f"Scanning {target} ({target_ip}) for open ports...")
    
    results = {}
    lock = threading.Lock()
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(scan_port, target_ip, port, results, lock) for port in ports]
        for future in as_completed(futures):
            pass  # Wait for completion
    
    return results

def main():
    target = input("Enter target IP or domain: ").strip()
    port_range = input("Enter port range (e.g., 1-1024) or press Enter for default: ").strip()
    
    if port_range:
        start, end = map(int, port_range.split('-'))
        ports = range(start, end + 1)
    else:
        ports = DEFAULT_PORTS
    
    start_time = time.time()
    open_ports = port_scan(target, ports)
    end_time = time.time()
    
    print(f"\nScan completed in {end_time - start_time:.2f} seconds.")
    if open_ports:
        print("Open Ports and Services:")
        for port, service in sorted(open_ports.items()):
            print(f"Port {port}: {service}")
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()
