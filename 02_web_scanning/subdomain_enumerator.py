import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.exception
import json
import csv
import random
import string
from tqdm import tqdm

# output handler to support multiple output formats like json and csv and simple default text
class OutputHandler:
    def __init__(self, output_path: Path | None = None, fmt: str = "text"):
        self.output_path = output_path
        self.results: list[str] = []
        self.format = fmt.lower()

    def add(self, subdomain: str):
        self.results.append(subdomain)

    def show(self):
        for subdomain in self.results:
            print(subdomain)

    def save(self):
        if not self.output_path:
            return
        try:
            if self.format == "json":
                self.output_path.write_text(json.dumps(self.results, indent=2))
            elif self.format == "csv":
                with self.output_path.open("w", newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["subdomain"])
                    for sub in self.results:
                        writer.writerow([sub])
            else:  
                self.output_path.write_text("\n".join(self.results))
            print(f"|+| Results saved to {self.output_path} ({self.format.upper()})")
        except Exception as e:
            print(f"|x| Failed to save results → {e}")

# subdomain enumerator that queries the dns, checks for wildcards, and includes threading
def query_dns(sub: str, domain: str, resolver: dns.resolver.Resolver, wildcard_ips: set[str]) -> str | None:
    """Return subdomain string if it resolves, else None."""
    full = f"{sub}.{domain}"
    try:
        answer = resolver.resolve(full, "A")
        ips = {r.address for r in answer}
        if not wildcard_ips or ips - wildcard_ips:
            return full
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException as e:
        print(f"|!| {full} → {e}")
        return None

def is_wildcard(domain: str, resolver: dns.resolver.Resolver) -> set[str]:
    label = ''.join(random.choices(string.ascii_lowercase, k=16))
    try:
        res = resolver.resolve(f"{label}.{domain}", "A")
        return {r.address for r in res}
    except dns.exception.DNSException:
        return set()

def enumerate_subdomains(
    domain: str,
    wordlist: Path,
    threads: int,
    out: OutputHandler,
    resolvers: list[str] | None = None,
) -> None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2  # seconds timeout
    if resolvers:
        resolver.nameservers = resolvers

    try:
        words = wordlist.read_text().splitlines()
    except FileNotFoundError:
        print(f"|x| Wordlist not found: {wordlist}")
        return

    wildcard_ips = is_wildcard(domain, resolver)
    if wildcard_ips:
        print(f"|*| Wildcard DNS detected → {', '.join(wildcard_ips)}")

    print(f"|*| Enumerating {len(words):,} sub‑domains on {domain} with {threads} thread(s) …")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(query_dns, w.strip(), domain, resolver, wildcard_ips) for w in words]
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Resolving"):
            result = fut.result()
            if result:
                print(f"|+| {result}")
                out.add(result)

# cli arguments added, main initializer
def cli() -> None:
    p = argparse.ArgumentParser(description="Threaded DNS sub‑domain enumerator")
    p.add_argument("domain", help="Target domain (e.g., example.com)")
    p.add_argument("wordlist", type=Path, help="Wordlist file")
    p.add_argument("-o", "--output", type=Path, help="Save discovered sub‑domains here")
    p.add_argument(
        "-t", "--threads", type=int, default=50, help="Number of concurrent DNS queries (default 50)"
    )
    p.add_argument(
        "-f", "--format", choices=["text", "json", "csv"], default="text",
        help="Output format: text (default), json, or csv"
    )
    p.add_argument(
        "-R", "--resolvers", help="Comma-separated list of DNS resolvers (e.g., 1.1.1.1,8.8.8.8)", default=""
    )
    args = p.parse_args()

    resolvers = args.resolvers.split(",") if args.resolvers else None

    out = OutputHandler(args.output, args.format)
    enumerate_subdomains(args.domain, args.wordlist, args.threads, out, resolvers=resolvers)

    print("\n|*| Enumeration complete.")
    if out.results:
        print(f"|+| Total found: {len(out.results)}")
        out.show()
        out.save()
    else:
        print("|-| No sub‑domains discovered.")

if __name__ == "__main__":
    cli()
