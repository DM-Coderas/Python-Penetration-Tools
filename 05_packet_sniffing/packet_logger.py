import argparse
import csv
import json
from scapy.all import sniff, TCP, UDP, IP

# list to define the fields that can be exported
DEFAULT_FIELDS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]

# function that converts packet info into the dictionary
def packet_to_dict(pkt, fields):
    pkt_dict = {}
    for field in fields:
        value = None
        if field == "src_ip":
            value = pkt[IP].src if IP in pkt else ""
        elif field == "dst_ip":
            value = pkt[IP].dst if IP in pkt else ""
        elif field == "src_port":
            if TCP in pkt or UDP in pkt:
                value = pkt.sport
        elif field == "dst_port":
            if TCP in pkt or UDP in pkt:
                value = pkt.dport
        elif field == "protocol":
            value = pkt[IP].proto if IP in pkt else ""
        else:
            value = getattr(pkt, field, "")
        pkt_dict[field] = value
    return pkt_dict

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Custom Packet Sniffer with CSV/JSON Export")
    parser.add_argument("-i", "--iface", required=True, help="Network interface to sniff on")
    parser.add_argument("-o", "--output", default="packets.csv", help="Output file path")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Output format (csv or json)")
    parser.add_argument("--fields", nargs="+", default=DEFAULT_FIELDS, help="Fields to log")
    parser.add_argument("--verbose", action="store_true", help="Print packets to stdout")

    args = parser.parse_args()
    captured_packets = []

# functionthat logs packets
    def log_packet(pkt):
        pkt_dict = packet_to_dict(pkt, args.fields)
        if args.verbose:
            print(pkt_dict)
        captured_packets.append(pkt_dict)

    print(f"|*| Sniffing on {args.iface}... Press Ctrl+C to stop.")
    sniff(iface=args.iface, filter=args.filter, prn=log_packet, count=args.count, store=False)

    # save to file after capture ends
    print(f"|*| Writing {len(captured_packets)} packets to {args.output} ({args.format})")
    if args.format == "csv":
        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=args.fields)
            writer.writeheader()
            writer.writerows(captured_packets)
    elif args.format == "json":
        with open(args.output, "w") as f:
            json.dump(captured_packets, f, indent=2)

if __name__ == "__main__":
    main()
