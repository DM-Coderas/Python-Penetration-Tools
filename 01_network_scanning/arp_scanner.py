import argparse
import os
import sys
import json
import csv
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
from tqdm import tqdm

# code to save info into file formats like csv and json
def save_results(results, output_path, fmt):
    try:
        if fmt == "json":
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
        elif fmt == "csv":
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "MAC Address"])
                for r in results:
                    writer.writerow([r["ip"], r["mac"]])
        else:
            with open(output_path, "w") as f:
                for r in results:
                    f.write(f"{r['ip']} - {r['mac']}\n")
        print(f"\n[+] Results saved to {output_path} ({fmt.upper()})")
    except Exception as e:
        print(f"[x] Failed to save results → {e}")

# check if the user has root privilege
def check_root():
    if os.name != "nt" and os.geteuid() != 0:
        print("[x] This script must be run as root.")
        sys.exit(1)

# primary arp scanning function, complete with datetime and a progress bar
def arp_scan(interface, ips, output_path=None, fmt="text"):
    print("[*] Starting ARP scan…")
    start_time = datetime.now()

    conf.verb = 0
    results = []

    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
            timeout=2,
            iface=interface,
            inter=0.1
        )
    except Exception as e:
        print(f"[x] Error during scan: {e}")
        return

    print("\n[*] Live Hosts Found:")
    print("{:<16} {}".format("IP Address", "MAC Address"))
    print("-" * 30)

    for _, rcv in tqdm(ans, desc="Processing", unit="host"):
        ip = rcv.psrc
        mac = rcv.hwsrc
        results.append({"ip": ip, "mac": mac})
        print("{:<16} {}".format(ip, mac))

    total_time = datetime.now() - start_time
    print(f"\n[*] Scan complete in {total_time}")
    print(f"[+] Hosts discovered: {len(results)}")

    if output_path:
        save_results(results, output_path, fmt)

# cli parser to make the scanner customizable 
def cli():
    parser = argparse.ArgumentParser(description="ARP scanner with CSV/JSON output and progress bar")
    parser.add_argument("interface", help="Network interface (e.g., eth0)")
    parser.add_argument("ip_range", help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text", help="Output format")
    args = parser.parse_args()

    check_root()
    arp_scan(args.interface, args.ip_range, args.output, args.format)

if __name__ == "__main__":
    cli()
