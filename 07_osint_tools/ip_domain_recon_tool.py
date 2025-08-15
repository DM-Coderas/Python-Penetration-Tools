import requests
import whois
from ipwhois import IPWhois
import dns.resolver
import argparse
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# various lookup functions that parses through the internet for information
def get_whois(domain):
    try:
        w = whois.whois(domain)
        return w.text
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def get_ipwhois(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res
    except Exception as e:
        return f"IP WHOIS lookup failed: {e}"

def get_dns(domain):
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']:
        try:
            result = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in result]
        except Exception:
            records[rtype] = []
    return records

def get_geoip(ip):
    try:
        resp = requests.get(f'https://ipinfo.io/{ip}/json', timeout=5)
        return resp.json()
    except Exception as e:
        return f"GeoIP lookup failed: {e}"

def get_reputation(ip):
    try:
        resp = requests.get(f'https://ip-api.io/json/{ip}', timeout=5)
        return resp.json()
    except Exception as e:
        return f"Reputation lookup failed: {e}"

# function that uses threadpool to concurrently recon and execute previous functions on a target
def recon(target):
    output = {}

    is_ip = all(c.isdigit() or c == '.' for c in target)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}

        if is_ip:
            ip = target
            output["Type"] = "IP"
            futures["IP WHOIS"] = executor.submit(get_ipwhois, ip)
            futures["GeoIP"] = executor.submit(get_geoip, ip)
            futures["Reputation"] = executor.submit(get_reputation, ip)

        else:
            domain = target
            output["Type"] = "Domain"
            futures["WHOIS"] = executor.submit(get_whois, domain)
            futures["DNS"] = executor.submit(get_dns, domain)

            try:
                ip = socket.gethostbyname(domain)
                output["Resolved IP"] = ip
                futures["IP WHOIS"] = executor.submit(get_ipwhois, ip)
                futures["GeoIP"] = executor.submit(get_geoip, ip)
                futures["Reputation"] = executor.submit(get_reputation, ip)
            except Exception as e:
                output["Resolved IP"] = f"Resolution failed: {e}"

        for key, future in futures.items():
            output[key] = future.result()

    return output

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Multithreaded Python Recon Tool")
    parser.add_argument("target", help="IP address or domain to investigate")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    results = recon(args.target)

    print(json.dumps(results, indent=4))

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"|+| Results saved to {args.output}")

if __name__ == "__main__":
    main()
