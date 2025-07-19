import argparse
import json
import csv
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, ip_address
from pysnmp.hlapi import *
from tqdm import tqdm

# added set of known oids to make this more “user friendly”
KNOWN_OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.1.3.0": "sysUptime",
    "1.3.6.1.2.1.1.4.0": "sysContact"
}

# primary function that creates an snmp get request to attain information from the snmp agent
def snmp_get(ip, community, oid, timeout=1, retries=0):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=0),
        UdpTransportTarget((str(ip), 161), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication or errorStatus:
        return None

    for varBind in varBinds:
        return str(varBind[1])
    return None

# function for multithreaded ip range scans
def scan_snmp(ip_range, community, oid, threads=50, timeout=1):
    result = []
    ips = parse_targets(ip_range)
    print(f"|*| Scanning {len(ips)} host(s)…")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(snmp_get, ip, community, oid, timeout): ip for ip in ips}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            ip = futures[fut]
            try:
                response = fut.result()
                if response:
                    print(f"|+| {ip} - {response}")
                    result.append((str(ip), response))
            except Exception:
                pass

    print(f"\n|*| Scan complete. Found {len(result)} responsive host(s).")
    return result

# function to save results in either json or csv
def save_results(results, fmt, out_path):
    if not results or not fmt or not out_path:
        return
    try:
        if fmt == "json":
            with open(out_path, "w") as f:
                json.dump([{"IP": ip, "Response": resp} for ip, resp in results], f, indent=2)
        elif fmt == "csv":
            with open(out_path, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Response"])
                writer.writerows(results)
        print(f"[+] Results saved to {out_path}")
    except Exception as e:
        print(f"[x] Failed to save results: {e}")

# function that allows user to input whatever type of target they want, from domain to ip range to just ip
def parse_targets(target_str):
    try:
        if "/" in target_str:
            return list(ip_network(target_str).hosts())
        else:
            ip = socket.gethostbyname(target_str)
            return [ip_address(ip)]
    except Exception as e:
        print(f"[x] Invalid target: {e}")
        sys.exit(1)

# arg parser to add cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Simple SNMP Scanner in Python")
    parser.add_argument("target", help="IP or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-c", "--community", default="public", help='SNMP community string (default: "public")')
    parser.add_argument("-o", "--oid", default="1.3.6.1.2.1.1.1.0", help="SNMP OID to query (default: sysDescr)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=1.0, help="SNMP timeout in seconds (default: 1.0)")
    parser.add_argument("-f", "--format", choices=["json", "csv"], help="Output format")
    parser.add_argument("-O", "--output", help="Output file path")
    args = parser.parse_args()

    oid_name = KNOWN_OIDS.get(args.oid, None)
    if oid_name:
        print(f"[i] Querying OID: {oid_name} ({args.oid})")
    else:
        print(f"[i] Querying OID: {args.oid}")

    results = scan_snmp(args.target, args.community, args.oid, args.threads, args.timeout)
    save_results(results, args.format, args.output)

if __name__ == "__main__":
    cli()
