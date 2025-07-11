import socket
import argparse
import threading
from queue import Queue
from datetime import datetime
from tqdm import tqdm
import os
import json
import csv
import socks
import sys

# configuring necessary perimeters before the primary code
open_ports = []
open_ports_udp = []
queue = Queue()
print_lock = threading.Lock()

# list of common service operations of the specified ports; can add more
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Proxy"
}

# configure optional proxy, if provided
def configure_proxy(proxy):
    if proxy:
        try:
            proxy_ip, proxy_port = proxy.split(":")
            socks.set_default_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
            socket.socket = socks.socksocket
            print(f"[i] Using SOCKS5 proxy at {proxy_ip}:{proxy_port}")
        except Exception as e:
            print(f"[x] Failed to configure proxy: {e}")
            sys.exit(1)

# code to attempt to grab any banners by decoding the first 1024 bytes of the socket
def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except:
        return ""

# central function towards finding out if a port is open or not, calling on the banner function as well
def probe_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(ip, port)
            service = COMMON_PORTS.get(port, "Unknown")
            with print_lock:
                print(f"[+] Port {port} ({service}) is open" + (f" - Banner: {banner}" if banner else ""))
            open_ports.append({"port": port, "service": service, "banner": banner})
        sock.close()
    except Exception:
        pass

# worker function for TCP ports
def worker(ip, pbar):
    while not queue.empty():
        port = queue.get()
        probe_port(ip, port)
        pbar.update(1)
        queue.task_done()

# UDP port scan code, if provided
def probe_udp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'', (ip, port))
        sock.recvfrom(1024)
        with print_lock:
            print(f"[+] UDP Port {port} might be open or filtered")
        open_ports_udp.append({"port": port, "service": "Unknown"})
        sock.close()
    except socket.timeout:
        with print_lock:
            print(f"[?] UDP Port {port} might be open|filtered (no response)")
        open_ports_udp.append({"port": port, "service": "Unknown"})
    except Exception:
        pass

# worker function for UDP ports
def udp_worker(ip, pbar):
    while not queue.empty():
        port = queue.get()
        probe_udp_port(ip, port)
        pbar.update(1)
        queue.task_done()

# function to save logs in JSON and CSV formats
def save_logs(ip, output_dir, timestamp):
    ip_safe = ip.replace('.', '-')
    json_path = os.path.join(output_dir or '.', f"scan_{ip_safe}_{timestamp}.json")
    csv_path = os.path.join(output_dir or '.', f"scan_{ip_safe}_{timestamp}.csv")

    try:
        with open(json_path, 'w') as jf:
            json.dump({"tcp": open_ports, "udp": open_ports_udp}, jf, indent=4)
        with open(csv_path, 'w', newline='') as cf:
            writer = csv.writer(cf)
            writer.writerow(["Protocol", "Port", "Service", "Banner"])
            for entry in open_ports:
                writer.writerow(["TCP", entry["port"], entry["service"], entry["banner"]])
            for entry in open_ports_udp:
                writer.writerow(["UDP", entry["port"], entry["service"], "N/A"])
        print(f"[v] Results saved to: {json_path}, {csv_path}")
    except Exception as e:
        print(f"[x] Failed to save logs: {e}")

# main function that runs the scanner by calling on every output defined so far, also tracking the time for later
def run_scanner(ip, start_port, end_port, threads, output_dir, scan_udp):
    print(f"[+] Scanning {ip} from port {start_port} to {end_port} with {threads} threads")
    start_time = datetime.now()

    try:
        reverse_dns = socket.gethostbyaddr(ip)
        hostname = reverse_dns[0]
        print(f"[i] Reverse DNS lookup successful: {hostname}")
    except socket.herror:
        hostname = None
        print(f"[i] Reverse DNS lookup failed for {ip}, no hostname available")

    for port in range(start_port, end_port + 1):
        queue.put(port)

    pbar = tqdm(total=queue.qsize(), desc=f"Scanning TCP {ip}")
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(ip, pbar))
        t.daemon = True
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    pbar.close()

    # Optional UDP scan
    if scan_udp:
        print(f"\n[~] Starting UDP scan for {ip}")
        for port in range(start_port, end_port + 1):
            queue.put(port)
        pbar = tqdm(total=queue.qsize(), desc=f"Scanning UDP {ip}")
        udp_threads = []
        for _ in range(threads):
            t = threading.Thread(target=udp_worker, args=(ip, pbar))
            t.daemon = True
            t.start()
            udp_threads.append(t)
        for t in udp_threads:
            t.join()
        pbar.close()

    end_time = datetime.now()
    print(f"[+] Scan completed in: {end_time - start_time}")

    # output results
    if open_ports:
        print("\nOpen TCP Ports:")
        for entry in open_ports:
            print(f"Port {entry['port']} ({entry['service']}) - Banner: {entry['banner'] if entry['banner'] else 'N/A'}")

    if open_ports_udp:
        print("\nUDP Ports (open or filtered):")
        for entry in open_ports_udp:
            print(f"UDP Port {entry['port']} ({entry['service']})")

    timestamp = end_time.strftime("%Y-%m-%d_%H-%M-%S")
    save_logs(ip, output_dir, timestamp)

# makes sure script is executed when called on, not imported, adds arguments for customizability
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Advanced Multi-threaded Port Scanner")
    parser.add_argument('-i', '--ip', required=True, help='Target IP address')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range (e.g., 1-65535)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output-dir', help='Directory to save results')
    parser.add_argument('--udp', action='store_true', help='Enable UDP scanning')
    parser.add_argument('--proxy', help='SOCKS proxy in format ip:port')

    args = parser.parse_args()
    ip = args.ip
    start_port, end_port = map(int, args.ports.split('-'))

    configure_proxy(args.proxy)
    run_scanner(ip, start_port, end_port, args.threads, args.output_dir, args.udp)
