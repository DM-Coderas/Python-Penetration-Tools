import argparse
from collections import Counter, deque
import threading
import time
import signal
import json
import csv
import sys

from scapy.all import sniff
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# thread counters for protocols
protocol_counts = Counter()
timestamps = deque(maxlen=50)          
counts_history = deque(maxlen=50)      

# global variables for shutdown
stop_sniffing = False
start_time = None

# function to handle each sniffed packet and categorize by protocol
def packet_handler(packet):
    proto = None
    if packet.haslayer('TCP'):
        proto = 'TCP'
    elif packet.haslayer('UDP'):
        proto = 'UDP'
    elif packet.haslayer('ICMP'):
        proto = 'ICMP'
    else:
        proto = 'Other'
    protocol_counts[proto] += 1

# function to sniff packets on specified interface and filter
def sniff_packets(interface, bpf_filter, duration):
    global stop_sniffing
    start = time.time()

    def _should_stop(packet):
        nonlocal start
        return stop_sniffing or (duration and (time.time() - start > duration))

    sniff(iface=interface, filter=bpf_filter, store=False, prn=packet_handler, stop_filter=_should_stop)

# function to live updating matplotlib graph of traffic over time
def animate(i):
    current_time = time.strftime('%H:%M:%S')
    total = sum(protocol_counts.values())
    timestamps.append(current_time)
    counts_history.append(total)

    plt.cla()
    plt.title('Network Traffic Packets Per Interval')
    plt.xlabel('Time')
    plt.ylabel('Packets')
    plt.plot(timestamps, counts_history, label='Total Packets')
    plt.legend(loc='upper left')
    plt.tight_layout()

# function to save final protocol counts to csv or json
def save_output(filepath, fmt):
    if fmt == "csv":
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Protocol", "Count"])
            for proto, count in protocol_counts.items():
                writer.writerow([proto, count])
    elif fmt == "json":
        with open(filepath, 'w') as f:
            json.dump(dict(protocol_counts), f, indent=4)
    print(f"|+| Saved results to {filepath}")

# function for exit on keyboard interrupt
def signal_handler(sig, frame):
    global stop_sniffing
    stop_sniffing = True
    print("\n|!| Stopping sniffer... Please wait for final output.")

signal.signal(signal.SIGINT, signal_handler)

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Network Traffic Visualizer + Exporter")
    parser.add_argument("-i", "--iface", required=True, help="Network interface to sniff (e.g. eth0, wlan0)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("-t", "--interval", type=int, default=2, help="Graph refresh interval in seconds")
    parser.add_argument("-o", "--output", default="protocol_counts.csv", help="Output file (e.g., output.csv or output.json)")
    parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Output format")
    parser.add_argument("--duration", type=int, default=0, help="Sniffing duration in seconds (0 = infinite)")
    args = parser.parse_args()

    sniff_thread = threading.Thread(target=sniff_packets, args=(args.iface, args.filter, args.duration), daemon=True)
    sniff_thread.start()

    ani = FuncAnimation(plt.gcf(), animate, interval=args.interval * 1000)
    plt.tight_layout()
    plt.show()

    save_output(args.output, args.format)

if __name__ == "__main__":
    main()
