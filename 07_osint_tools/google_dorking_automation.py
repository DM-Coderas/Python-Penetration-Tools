import requests
from bs4 import BeautifulSoup
import argparse
import time
import random
import json
import csv
from urllib.parse import urlparse, unquote

# list of user agents for google
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile Safari/604.1"
]

# main function that enacts the process of google dorking depending on the user’s wants
def google_dork(query, max_results=10, delay=2, proxy=None, unique_domains=False):
    url = "https://www.google.com/search"
    results = []
    seen_domains = set()

    proxies = {"http": proxy, "https": proxy} if proxy else None

    for start in range(0, max_results, 10):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        params = {"q": query, "start": start}

        resp = requests.get(url, params=params, headers=headers, proxies=proxies)
        if "unusual traffic" in resp.text.lower():
            print("|!| Blocked by Google. Try using a proxy or slowing down requests.")
            break

        soup = BeautifulSoup(resp.text, "html.parser")
        for link in soup.select("a"):
            href = link.get("href")
            if href and href.startswith("/url?q="):
                actual_url = unquote(href.split("/url?q=")[1].split("&")[0])
                if unique_domains:
                    domain = urlparse(actual_url).netloc
                    if domain in seen_domains:
                        continue
                    seen_domains.add(domain)
                results.append(actual_url)

        time.sleep(delay) 
        if len(results) >= max_results:
            break

    return results[:max_results]

# function to save results to json or csv
def save_results(results, json_file=None, csv_file=None):
    if json_file:
        with open(json_file, "w", encoding="utf-8") as jf:
            json.dump(results, jf, indent=4)
        print(f"|+| Saved JSON output to {json_file}")

    if csv_file:
        with open(csv_file, "w", newline="", encoding="utf-8") as cf:
            writer = csv.writer(cf)
            writer.writerow(["Index", "URL"])
            for idx, url in enumerate(results, 1):
                writer.writerow([idx, url])
        print(f"|+| Saved CSV output to {csv_file}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Google Dork Automation Tool (Enhanced)")
    parser.add_argument("dork", help="Google Dork query (wrap in quotes)")
    parser.add_argument("-n", "--num", type=int, default=10, help="Number of results to fetch")
    parser.add_argument("-d", "--delay", type=float, default=2, help="Delay between requests (seconds)")
    parser.add_argument("-p", "--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--unique", action="store_true", help="Return only unique domains")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--csv", help="Save results to CSV file")
    args = parser.parse_args()

    links = google_dork(args.dork, max_results=args.num, delay=args.delay, proxy=args.proxy, unique_domains=args.unique)

    print(f"\n|+| Results for: {args.dork}\n")
    for idx, link in enumerate(links, 1):
        print(f"{idx}. {link}")

    if args.json or args.csv:
        save_results(links, json_file=args.json, csv_file=args.csv)

if __name__ == "__main__":
    main()
