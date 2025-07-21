import argparse
import requests
import json
import csv
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm
from urllib.parse import urljoin, urlparse

# to disable secure warnings when using self signed certs like in a pentester environment (AKA dont do this in critical security infrastructure, it can reveal good info)
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# shuffled user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
]

# function to send get entries with ua
def check_url(url, retries=2):
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    for attempt in range(retries + 1):
        try:
            res = requests.get(url, timeout=5, verify=False, allow_redirects=False, headers=headers)
            return (url, res.status_code)
        except requests.RequestException:
            if attempt == retries:
                return (url, None)
            time.sleep(0.3)

# function to check for a robots text directory
def check_robots_txt(base_url):
    robots_url = urljoin(base_url + "/", "robots.txt")
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        res = requests.get(robots_url, headers=headers, timeout=5, verify=False)
        if res.status_code == 200:
            print(f"|*| Found robots.txt at {robots_url}")
            for line in res.text.splitlines():
                if line.lower().startswith("disallow:"):
                    print(f"|!| Disallowed: {line.split(':', 1)[1].strip()}")
        else:
            print("|*| No robots.txt found")
    except Exception:
        print("|x| Failed to retrieve robots.txt")

# primary function that initiates the brute force, using progress bar and threads, using perimeters like wordlist
def brute_force(base_url, wordlist_path, extensions, threads, exclude_codes):
    found = []
    try:
        words = Path(wordlist_path).read_text().splitlines()
    except FileNotFoundError:
        print(f"[x] Wordlist not found: {wordlist_path}")
        return found

    urls = []
    for word in words:
        word = word.strip()
        if not word:
            continue
        urls.append(f"{base_url}/{word}/")  
        for ext in extensions:
            urls.append(f"{base_url}/{word}.{ext.strip('.')}")
    
    print(f"|*| Scanning {len(urls):,} paths with {threads} thread(s)...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_url, url, retries=2) for url in urls]
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            url, code = future.result()
            if code and code < 400 and code not in exclude_codes:
                print(f"[+] Found: {url} [Status {code}]")
                found.append((url, code))

    return found

# function to save results to json or csv
def save_results(results, output_path, json_mode=False, csv_mode=False):
    try:
        if json_mode:
            json.dump([{"url": url, "status": code} for url, code in results], output_path.open("w"), indent=2)
        elif csv_mode:
            with output_path.open("w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["URL", "Status Code"])
                for url, code in results:
                    writer.writerow([url, code])
        else:
            output_path.write_text("\n".join([f"{url} [HTTP {code}]" for url, code in results]))
        print(f"[+] Results saved to {output_path}")
    except Exception as e:
        print(f"[x] Error saving results: {e}")

# arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Simple Python Directory/File Brute Forcer")
    parser.add_argument("url", help="Base URL (e.g., http://example.com)")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("-e", "--extensions", default="php,html,txt", help="Comma-separated list of file extensions")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads to use (default 50)")
    parser.add_argument("-o", "--output", type=Path, help="File to save results")
    parser.add_argument("--json", action="store_true", help="Save results in JSON format")
    parser.add_argument("--csv", action="store_true", help="Save results in CSV format")
    parser.add_argument("--exclude", help="Comma-separated list of status codes to exclude (e.g. 403,301)")
    args = parser.parse_args()

    if args.url.endswith("/"):
        args.url = args.url[:-1]

    extensions = [ext.strip() for ext in args.extensions.split(",") if ext.strip()]
    exclude_codes = set(int(code.strip()) for code in args.exclude.split(",")) if args.exclude else set()

    check_robots_txt(args.url)
    results = brute_force(args.url, args.wordlist, extensions, args.threads, exclude_codes)

    print(f"\n|*| Scan complete. {len(results)} path(s) found.")
    if args.output:
        save_results(results, args.output, json_mode=args.json, csv_mode=args.csv)

if __name__ == "__main__":
    cli()
