import socket
import argparse
import threading
from queue import Queue
from datetime import datetime
from tqdm import tqdm
import os

# configuring necessary perimeters before the primary code
open_ports = []
queue = Queue()
print_lock = threading.Lock()

# list of common service operations of the specified ports; can add more 
COMMON_PORTS = {
  7: "Echo (TCP/UDP)"
  19: "CHARGEN (TCP/UDP)"
  21: "FTP"
  22: "SSH"
  23: "Telnet"
  25: "SMTP"
  37: "Time (TCP/UDP)"
  49: "TACACS/TACACS+"
  53: "DNS"
  67: "DHCP (Server) (UDP)"
  68: "DHCP (Client) (UDP)"
  69: "TFTP (UDP)"
  79: "Finger"
  80: "HTTP"
  88: "Kerberos"
  110: "POP3"
  111: "RPCBind / Portmapper (Often used by NFS)"
  123: "NTP (UDP)"
  135: "RPC/EPMAP (Microsoft) (Remote Procedure Call)"
  137: "NetBIOS Name Service (NBNS) (UDP)"
  138: "NetBIOS Datagram Service (UDP)"
  139: "NetBIOS Session Service (SMB over NetBIOS)"
  143: "IMAP"
  161: "SNMP (UDP)"
  162: "SNMP Trap (UDP)"
  194: "IRC"
  389: "LDAP"
  443: "HTTPS"
  445: "SMB/CIFS (Microsoft-DS) (Direct SMB over TCP)"
  465: "SMTPS (SMTP over SSL/TLS - older, often 587 is used now)"
  500: "ISAKMP (IPsec VPN) (UDP)"
  514: "Syslog (UDP)"
  587: "SMTP Submission (TLS/SSL) (often for email client to server)"
  631: "IPP (Internet Printing Protocol)"
  636: "LDAPS (LDAP over SSL/TLS)"
  902: "VMware Server (Service Console) (Often for vCenter/ESXi management)"
  993: "IMAPS (IMAP over SSL/TLS)"
  995: "POP3S (POP3 over SSL/TLS)"
  1080: "Socks Proxy"
  1194: "OpenVPN (UDP)"
  1433: "Microsoft SQL Server"
  1434: "Microsoft SQL Monitor (UDP)"
  1521: "Oracle SQL"
  1720: "H.323 (VoIP)"
  1723: "PPTP (VPN)"
  3128: "Squid Proxy (HTTP)"
  3306: "MySQL"
  3389: "RDP (Remote Desktop Protocol)"
  5432: "PostgreSQL"
  5900: "VNC (Remote Desktop)"
  8000: "HTTP Alternate (often development/web servers)"
  8080: "HTTP Alternate (often web servers, proxies, or development)"
  8443: "HTTPS Alternate (often web servers or proxies)"
}

# code to attempt to grab any banners by decoding the first 1024 bytes of the socket
def grab_banner(ip, port):
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
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
            open_ports.append((port, service, banner))
        sock.close()
    except Exception as e:
        pass

# function that creates the flow of ports being scanned as well as the progress bar
def worker(ip, pbar):
    while not queue.empty():
        port = queue.get()
        probe_port(ip, port)
        pbar.update(1)
        queue.task_done()

# main function that runs the scanner by calling on every output defined so far, also tracking the time for later
def run_scanner(ip, start_port, end_port, threads, output_dir):
    print(f"[+] Scanning {ip} from port {start_port} to {end_port} with {threads} threads")
    start_time = datetime.now()

#puts the ports into queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

# progress bar and empty thread list is intialized, worker threads are formed and executed, converted to daemon
    pbar = tqdm(total=queue.qsize(), desc="Scanning")
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(ip, pbar))
        t.daemon = True
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

#end of progress bar and shows the amount of time the scan took
    pbar.close()
    end_time = datetime.now()
    print(f"[+] Scan completed in: {end_time - start_time}")

# if statement to print open ports and their respective service and banner
    if open_ports:
        print("\nOpen Ports:")
        for port, service, banner in open_ports:
            print(f"Port {port} ({service}) - Banner: {banner if banner else 'N/A'}")
# outputs results into a file with a descriptive filename, making sure no errors occur
        timestamp = end_time.strftime("%Y-%m-%d_%H-%M-%S")
        ip_safe = ip.replace('.', '-')
        output_path = os.path.join(output_dir or '.', f"scan_{ip_safe}_{timestamp}.txt")
        try:
            with open(output_path, 'w') as f:
                for port, service, banner in open_ports:
                    f.write(f"Port {port} ({service}) - Banner: {banner if banner else 'N/A'}\n")
            print(f"[v] Results saved to: {output_path}")
        except Exception as e:
            print(f"[x] Failed to save results: {e}")
    else:
        print("[x] No open ports found.")

# makes sure script is executed when called on, not imported, adds arguments for customizability
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Advanced Multi-threaded Port Scanner")
    parser.add_argument('-i', '--ip', required=True, help='Target IP address')
    parser.add_argument('-p', '--ports', default='1-1024', help='Port range (e.g., 1-65535)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output-dir', help='Directory to save results')

# parses cli arguments, maps ip to given -i argument, and creates the start_port and end_port variables
    args = parser.parse_args()
    ip = args.ip
    start_port, end_port = map(int, args.ports.split('-'))

    run_scanner(ip, start_port, end_port, args.threads, args.output_dir)
