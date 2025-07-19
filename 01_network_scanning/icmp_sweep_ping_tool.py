import argparse
import sys
import os
import socket
import time
import csv
import json
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

ICMP_ECHO_REQUEST = 8

# function that checks for errors in checksum for icmp in a very simplified manner
def checksum(src):
    n = len(src)
    s = 0
    for i in range(0, n, 2):
        s += (src[i] << 8) + (src[i+1] if i+1 < n else 0)
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

# function that creates the packet, uses previous function to make sure packet isnt corrupted
def create_packet(id):
    header = bytearray(8)
    header[0] = ICMP_ECHO_REQUEST
    header[1] = 0
    header[2:4] = (0, 0)
    header[4:6] = (id >> 8, id & 0xff)
    header[6:8] = (0, 0)  # Sequence
    data = b'NetScan'
    packet = header + data
    cs = checksum(packet)
    packet[2] = (cs >> 8) & 0xff
    packet[3] = cs & 0xff
    return packet

# function that sends a single echo icmp ping and tracks the rtt
def ping_once(dest_addr, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
        sock.settimeout(timeout)
    except PermissionError:
        print("|x| ERROR: You must run this script as root!")
        sys.exit(1)
    pkt_id = os.getpid() & 0xFFFF
    packet = create_packet(pkt_id)
    try:
        start = time.time()
        sock.sendto(packet, (str(dest_addr), 1))
        sock.recvfrom(1024)
        return round((time.time() - start)*1000, 2)
    except socket.timeout:
        return None
    finally:
        sock.close()

# function that performs the sweep using the tracked rtt, has threads for greater speed and a progress bar
def sweep(iprange, threads=100, retries=0, csv_file=None, json_file=None):
    live_hosts = []
    hosts = [str(ip) for ip in ip_network(iprange).hosts()]
    print(f"|*| Pinging {len(hosts)} hosts ({iprange})…")

    def try_ping(ip):
        latency = ping_once(ip)
        for _ in range(retries):
            if latency is not None:
                break
            latency = ping_once(ip)
        return (ip, latency)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_ping, ip): ip for ip in hosts}
        for fut in tqdm(as_completed(futures), total=len(hosts), desc="ICMP Sweep"):
            ip, latency = fut.result()
            if latency is not None:
                print(f"|+| {ip:<16} responded in {latency}ms")
                live_hosts.append({"ip": ip, "latency_ms": latency})

    print(f"\n|*| Sweep complete. {len(live_hosts)} host(s) are alive.")

    # code to save to csv
    if csv_file:
        try:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "latency_ms"])
                writer.writeheader()
                writer.writerows(live_hosts)
            print(f"|*| CSV results saved to {csv_file}")
        except Exception as e:
            print(f"|x| Error writing CSV file: {e}")

    # code to save to json
    if json_file:
        try:
            with open(json_file, 'w') as f:
                json.dump(live_hosts, f, indent=2)
            print(f"|*| JSON results saved to {json_file}")
        except Exception as e:
            print(f"|x| Error writing JSON file: {e}")

    return live_hosts

# function that parses arguments and adds cli customizability
def cli():
    parser = argparse.ArgumentParser(description='ICMP Sweep (Ping Scan) Tool')
    parser.add_argument('target', help='Target IP range (e.g. 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of concurrent threads')
    parser.add_argument('--retries', type=int, default=0, help='Number of retry attempts per host if no response')
    parser.add_argument('-o', '--output', help='Output CSV file to save results')
    parser.add_argument('-j', '--json', help='Output JSON file to save results')
    args = parser.parse_args()

    if os.name != "nt" and os.geteuid() != 0:
        print("|x| Please run as root for raw socket privileges.")
        sys.exit(1)

    sweep(args.target, args.threads, args.retries, args.output, args.json)

if __name__ == "__main__":
    cli()
