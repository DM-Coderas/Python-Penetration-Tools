import argparse
import json
import csv
from datetime import datetime
from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest
from colorama import init, Fore

# experimental colorama for colorized output
init(autoreset=True)
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RED = Fore.RED
CYAN = Fore.CYAN

# global list to store sniffed http request data
results = []

# main function that processes captured packets to extract http request data using scapy
def process_packet(packet, args):
    if packet.haslayer(HTTPRequest):
        # extract source and destination IPs
        ip_src = packet[0][1].src
        ip_dst = packet[0][1].dst
        http_layer = packet[HTTPRequest]

        method = http_layer.Method.decode() if http_layer.Method else "UNKNOWN"
        host = http_layer.Host.decode() if http_layer.Host else ""
        path = http_layer.Path.decode() if http_layer.Path else ""
        url = f"http://{host}{path}"

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        user_agent = http_layer.User_Agent.decode() if hasattr(http_layer, "User_Agent") else ""

        if args.only_get and method != "GET":
            return
        if args.only_post and method != "POST":
            return

        color = GREEN if method == "GET" else YELLOW if method == "POST" else CYAN

        print(f"{color}[HTTP] {timestamp} | {ip_src} -> {ip_dst} | {method} {url}")

        entry = {
            "timestamp": timestamp,
            "src": ip_src,
            "dst": ip_dst,
            "method": method,
            "url": url,
            "user_agent": user_agent
        }

        if method == "POST" and args.show_raw and packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode(errors="ignore")
            print(f"{RED}[POST Data] {raw_data}")
            entry["post_data"] = raw_data

        results.append(entry)

# outputs info to json or csv formats
def save_results(args):
    if args.jsonout:
        with open(args.jsonout, 'w') as jf:
            json.dump(results, jf, indent=2)
        print(f"{CYAN}[*] JSON results saved to {args.jsonout}")

    if args.csvout:
        with open(args.csvout, 'w', newline='') as cf:
            fieldnames = ["timestamp", "src", "dst", "method", "url", "user_agent", "post_data"]
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                if "post_data" not in r:
                    r["post_data"] = ""  
                writer.writerow(r)
        print(f"{CYAN}|*| CSV results saved to {args.csvout}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Advanced HTTP Packet Sniffer")
    parser.add_argument("-i", "--iface", help="Network interface to sniff on")
    parser.add_argument("--show-raw", action="store_true", help="Show raw POST data")
    parser.add_argument("--jsonout", help="Save sniffed HTTP data to JSON file")
    parser.add_argument("--csvout", help="Save sniffed HTTP data to CSV file")
    parser.add_argument("--only-get", action="store_true", help="Capture only HTTP GET requests")
    parser.add_argument("--only-post", action="store_true", help="Capture only HTTP POST requests")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to sniff (0=unlimited)")
    args = parser.parse_args()

    print(f"{CYAN}|*| Starting HTTP sniffer... Press CTRL+C to stop.")

    try:
        sniff(
            iface=args.iface,
            filter="tcp port 80",  
            prn=lambda pkt: process_packet(pkt, args),
            store=0,
            count=args.count
        )
    except KeyboardInterrupt:
        print(f"\n{CYAN}|*| Sniffing stopped. Saving results...")

    save_results(args)

if __name__ == "__main__":
    main()
