import sys
import os
import json
import csv
import requests
from datetime import datetime
from scapy.all import srp, Ether, ARP, sniff, conf, get_if_hwaddr
from mac_vendor_lookup import MacLookup
from tqdm import tqdm

# code to save files in the formats of json and csv
class OutputHandler:
    def __init__(self, out_path=None, fmt="text"):
        self.out_path = out_path
        self.format = fmt.lower()
        self.results = []

    def add(self, data):
        self.results.append(data)

    def save(self):
        if not self.out_path:
            return
        try:
            if self.format == "json":
                with open(self.out_path, "w") as f:
                    json.dump(self.results, f, indent=2)
            elif self.format == "csv":
                with open(self.out_path, "w", newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                    writer.writeheader()
                    for row in self.results:
                        writer.writerow(row)
            print(f"|+| Results saved to {self.out_path}")
        except Exception as e:
            print(f"|x| Error saving results: {e}")

# checks user if they have root privilege
def check_root():
    if os.geteuid() != 0:
        print("|x| This script must be run as root.")
        sys.exit(1)

# code to get geolocation of the ip
def get_geolocation(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res["status"] == "success":
            return f"{res['country']}, {res['regionName']}, {res['city']}"
        return "Unknown"
    except:
        return "Unknown"

# primary function for arp scan, including vendor check, progress bar, datetime
def arp_scan(interface, ips, output_handler):
    print("|*| Starting active ARP scan …")
    start_time = datetime.now()

    conf.verb = 0
    mac_lookup = MacLookup()
    mac_lookup.update_vendors()

    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
        timeout=2,
        iface=interface,
        inter=0.1
    )

    print("\n|*| IP - MAC - Vendor - Location")
    for snd, rcv in tqdm(ans, desc="Processing responses"):
        ip = rcv.psrc
        mac = rcv.hwsrc
        try:
            vendor = mac_lookup.lookup(mac)
        except:
            vendor = "Unknown"
        location = get_geolocation(ip)

        print(f"{ip} - {mac} - {vendor} - {location}")
        output_handler.add({
            "IP": ip,
            "MAC": mac,
            "Vendor": vendor,
            "Location": location
        })

    print("\n|*| Active scan complete in", datetime.now() - start_time)

# code to enable passive sniffing, also has vendor check
def passive_sniff(interface, output_handler):
    print("|*| Starting passive ARP sniffing. Press Ctrl+C to stop.")
    mac_lookup = MacLookup()
    mac_lookup.update_vendors()

    def handle_packet(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 1:
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            try:
                vendor = mac_lookup.lookup(mac)
            except:
                vendor = "Unknown"
            location = get_geolocation(ip)

            print(f"{ip} - {mac} - {vendor} - {location}")
            output_handler.add({
                "IP": ip,
                "MAC": mac,
                "Vendor": vendor,
                "Location": location
            })

    sniff(filter="arp", prn=handle_packet, store=0, iface=interface)

# main function and an argument parser for cli customizability
def main():
    import argparse
    parser = argparse.ArgumentParser(description="ARP Network Scanner (Active & Passive Modes)")
    parser.add_argument("interface", help="Interface to use (e.g. eth0)")
    parser.add_argument("ips", nargs="?", help="CIDR/IP range for active scan (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--passive", action="store_true", help="Enable passive sniffing mode")
    parser.add_argument("-o", "--output", type=str, help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json", help="Output format (default: json)")
    args = parser.parse_args()

    check_root()

    out = OutputHandler(args.output, args.format)

    if args.passive:
        passive_sniff(args.interface, out)
    elif args.ips:
        arp_scan(args.interface, args.ips, out)
    else:
        print("|x| You must provide either an IP range for active scan or use --passive")
        return

    if out.results:
        out.save()

if __name__ == "__main__":
    main()
