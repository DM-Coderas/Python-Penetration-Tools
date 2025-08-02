import argparse
import json
import csv
from datetime import datetime
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP

results = []

# function that if packets contain dns information, extract only useful info like source/dest ips, and distinguishes among numerous filters like queries versus responses
def process_pkt(pkt, args):
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        ip = pkt[IP]
        dns = pkt[DNS]
        qname = dns[DNSQR].qname.decode('utf-8', errors='ignore')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if args.filter and args.filter.lower() not in qname.lower():
            return

        entry = {
            "timestamp": timestamp,
            "src": ip.src,
            "dst": ip.dst,
            "qname": qname,
            "type": "query" if dns.qr == 0 else "response",
            "qtype": dns[DNSQR].qtype
        }

        if dns.qr == 0 and not args.only_response:
            print(f"[Query] {timestamp} | {ip.src} -> {ip.dst} | {qname} | Type: {dns[DNSQR].qtype}")
            results.append(entry)
        elif dns.qr == 1 and not args.only_query:
            answers = []
            for i in range(dns.ancount):
                rr = dns.an[i]
                if rr.type == 1:  # A record
                    answers.append(rr.rdata)
            entry["answers"] = answers
            print(f"[Resp ] {timestamp} | {ip.src} -> {ip.dst} | {qname} | Answers: {', '.join(answers) if answers else 'N/A'}")
            results.append(entry)

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Advanced DNS Sniffer using Scapy")
    parser.add_argument("-i", "--iface", help="Network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--jsonout", help="Save captured DNS data to JSON")
    parser.add_argument("--csvout", help="Save captured DNS data to CSV")
    parser.add_argument("--filter", help="Only capture DNS requests matching domain keyword")
    parser.add_argument("--only-query", action="store_true", help="Show only DNS queries")
    parser.add_argument("--only-response", action="store_true", help="Show only DNS responses")

    args = parser.parse_args()
    print("|*| Starting DNS sniffer... Press CTRL+C to stop.")

    try:
        sniff(
            iface=args.iface,
            filter="udp port 53",
            prn=lambda pkt: process_pkt(pkt, args),
            count=args.count,
            store=0
        )
    except KeyboardInterrupt:
        print("\n|*| Sniffing stopped.")

    if args.jsonout:
        with open(args.jsonout, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"|*| JSON saved to {args.jsonout}")

    if args.csvout:
        with open(args.csvout, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp", "src", "dst", "qname", "type", "qtype", "answers"])
            writer.writeheader()
            for r in results:
                if "answers" not in r:
                    r["answers"] = ""
                elif isinstance(r["answers"], list):
                    r["answers"] = ", ".join(r["answers"])
                writer.writerow(r)
        print(f"|*| CSV saved to {args.csvout}")

if __name__ == "__main__":
    main()
