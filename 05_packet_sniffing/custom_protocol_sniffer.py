import argparse
import csv
import json
import os
from scapy.all import sniff, Raw

# global list to store all captured packet data
packet_log = []

# define paths for output files
CSV_FILE = "output.csv"
JSON_FILE = "output.json"

# initialize csv file with headers 
def init_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode="w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Source IP", "Destination IP", "Protocol", "Payload (Hex)"])

# function to append one row to csv 
def write_to_csv(ip_src, ip_dst, proto, payload_hex):
    with open(CSV_FILE, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([ip_src, ip_dst, proto, payload_hex])

# function to dump full json list to file
def write_to_json():
    with open(JSON_FILE, mode="w") as f:
        json.dump(packet_log, f, indent=4)

# function to process each captured packet
def process_packet(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        proto = packet["IP"].proto

        payload_hex = ""
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            payload_hex = payload.hex()
        else:
            payload = None

        print(f"|*| Packet: {ip_src} -> {ip_dst} | Proto: {proto}")
        if payload:
            print(f"    Payload (hex): {payload_hex}")

        write_to_csv(ip_src, ip_dst, proto, payload_hex)

        packet_log.append({
            "source_ip": ip_src,
            "destination_ip": ip_dst,
            "protocol": proto,
            "payload_hex": payload_hex
        })
    else:
        print(packet.summary())

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Custom Protocol Sniffer with CSV/JSON Export")
    parser.add_argument("-i", "--iface", help="Network interface to sniff on (e.g. eth0, wlan0)", required=True)
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0=unlimited)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g. 'tcp port 1337')")
    args = parser.parse_args()

    print("|*| Starting custom protocol sniffer... Press Ctrl+C to stop.")
    init_csv()

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=process_packet,
            store=0,
            count=args.count
        )
    except KeyboardInterrupt:
        print("\n|*| Sniffing stopped by user.")
    finally:
        print("|*| Writing captured data to JSON file...")
        write_to_json()
        print("|*| Done. Packets saved to 'output.csv' and 'output.json'.")

if __name__ == "__main__":
    main()
