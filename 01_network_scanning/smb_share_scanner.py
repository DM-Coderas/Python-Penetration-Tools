import argparse
import socket
import json
import requests
from impacket.smbconnection import SMBConnection
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor, as_completed

# reverse dns lookup
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

# simple ip geolocation
def ip_geolocate(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if resp['status'] == 'success':
            return f"{resp['city']}, {resp['regionName']}, {resp['country']}"
    except:
        pass
    return "Unknown"

# function that checks if the share is writable
def is_share_writable(smb, share_name):
    try:
        fid = smb.createFile(share_name, '\\test_write_check.txt')
        smb.closeFile(share_name, fid)
        smb.deleteFile(share_name, '\\test_write_check.txt')
        return True
    except:
        return False

# primary function to enumerate smb shares using the impacket package, geolocation and reverse dns included
def smb_enum(ip, username="", password="", timeout=2, check_writable=False):
    try:
        smb = SMBConnection(ip, ip, sess_port=445, timeout=timeout)
        smb.login(username, password)

        domain = smb.getServerDomain()
        os_version = smb.getServerOS()
        netbios = smb.getServerName()
        shares = []
        writable = []

        for share in smb.listShares():
            share_name = share['shi1_netname'][:-1]  # trim null
            shares.append(share_name)

            if check_writable and is_share_writable(smb, share_name):
                writable.append(share_name)

        smb.close()

        return {
            "ip": ip,
            "hostname": reverse_dns(ip),
            "location": ip_geolocate(ip),
            "netbios": netbios,
            "domain": domain,
            "os": os_version,
            "shares": shares,
            "writable_shares": writable
        }

    except Exception:
        return None

# function to scan a network for smb shares, uses future packaged threads
def scan_network(network, threads=50, username="", password="", timeout=2, check_writable=False):
    hosts = list(ip_network(network).hosts())
    results = []

    print(f"|*| Scanning {len(hosts)} hosts for SMB...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                smb_enum, str(ip), username, password, timeout, check_writable
            ): ip for ip in hosts
        }

        for fut in as_completed(futures):
            data = fut.result()
            if data:
                print(f"\n|+| Host Found: {data['ip']}")
                print(f"    - Hostname:      {data.get('hostname', 'N/A')}")
                print(f"    - Location:      {data.get('location', 'N/A')}")
                print(f"    - NetBIOS Name:  {data['netbios']}")
                print(f"    - Domain:        {data['domain']}")
                print(f"    - OS:            {data['os']}")
                print(f"    - Shares:        {', '.join(data['shares']) if data['shares'] else 'None'}")
                if check_writable:
                    print(f"    - Writable:      {', '.join(data['writable_shares']) if data['writable_shares'] else 'None'}")
                results.append(data)

    print(f"\n|*| SMB scan completed. {len(results)} host(s) found.")
    return results

# output for json files
def save_results(results, filename="smb_results.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"|+| Results saved to {filename}")

# arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Enhanced SMB/NetBIOS Enumerator")
    parser.add_argument("target", help="Target network range (e.g. 192.168.1.0/24)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("-u", "--username", default="", help="SMB username (default: anonymous)")
    parser.add_argument("-p", "--password", default="", help="SMB password (default: empty)")
    parser.add_argument("--timeout", type=int, default=2, help="Connection timeout in seconds (default: 2)")
    parser.add_argument("--check-writable", action="store_true", help="Check if shares are writable")
    parser.add_argument("-o", "--output", default="smb_results.json", help="Output filename (default: smb_results.json)")
    args = parser.parse_args()

    results = scan_network(
        args.target,
        threads=args.threads,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        check_writable=args.check_writable
    )
    save_results(results, args.output)

if __name__ == "__main__":
    cli()
