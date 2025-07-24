import argparse
import requests
from requests.exceptions import RequestException
from tabulate import tabulate
import re
import json
import csv

# set of security headers for the script to analyze
SECURITY_HEADERS = {
    "Content-Security-Policy": "Defines trusted content sources (prevents XSS).",
    "Strict-Transport-Security": "Forces browsers to use HTTPS (HSTS).",
    "X-Content-Type-Options": "Prevents MIME sniffs ('nosniff' expected).",
    "X-Frame-Options": "Limits if your site can be framed (clickjacking).",
    "Referrer-Policy": "Controls what referrer info is sent with requests.",
    "Permissions-Policy": "Restricts allowed browser features/APIs.",
    "X-XSS-Protection": "Legacy XSS filter for older browsers.",
}

# list of headers that are essential for the added feature of fingerprinting
FINGERPRINT_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Runtime",
    "Via"
]

# function which checks the purported recommended hsts settings
def check_hsts(header_value):
    directives = dict(
        item.strip().split('=') if '=' in item else (item.strip(), True)
        for item in header_value.split(';')
    )
    results = {
        "max-age": int(directives.get("max-age", 0)) >= 31536000,
        "includeSubDomains": "includeSubDomains" in directives,
        "preload": "preload" in directives
    }
    return results

# function that analyzes headers by sending a get request, receiving a response, and analyzes the headers in the response
def analyze_headers(url, json_out=None, csv_out=None):
    if not re.match(r'^https?://', url):
        url = "https://" + url

    try:
        resp = requests.get(url, timeout=10, verify=True)
    except RequestException as e:
        print(f"|x| Error accessing {url}: {e}")
        return

    headers = resp.headers
    sec_table = []
    json_output = {
        "url": url,
        "security_headers": [],
        "server_fingerprint": []
    }

    # for loop that is the primary code for analysis and judgement of the headers
    for header, desc in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value:
            if header == "Strict-Transport-Security":
                hsts = check_hsts(value)
                if all(hsts.values()):
                    status = "Configured"
                    details = value
                else:
                    status = "Misconfigured"
                    details = (f"max-age: {hsts['max-age']}, "
                               f"includeSubDomains: {hsts['includeSubDomains']}, "
                               f"preload: {hsts['preload']}")
            elif header == "X-Content-Type-Options":
                status = "OK" if value.lower() == "nosniff" else "Incorrect"
                details = value
            else:
                status = "Present"
                details = value
        else:
            status = "Missing"
            details = "N/A"

        sec_table.append([header, status, details, desc])
        json_output["security_headers"].append({
            "header": header,
            "status": status,
            "details": details,
            "purpose": desc
        })

    print(f"\nSecurity Header Analysis for {url}:\n")
    print(tabulate(sec_table, headers=["Header", "Status", "Details", "Purpose"], tablefmt="fancy_grid"))

    # --- Server Fingerprinting ---
    print("\n|+| Server Fingerprinting:\n")
    for h in FINGERPRINT_HEADERS:
        val = headers.get(h)
        if val:
            print(f" - {h}: {val}")
            if re.search(r"\d+\.\d+", val):
                print(f"   |!| Potentially sensitive version info exposed in {h}")
            json_output["server_fingerprint"].append({
                "header": h,
                "value": val,
                "version_exposed": bool(re.search(r"\d+\.\d+", val))
            })

    if not json_output["server_fingerprint"]:
        print(" - No fingerprinting headers found (good).")

    # options to output results into json or csv formats
    if json_out:
        with open(json_out, "w") as f:
            json.dump(json_output, f, indent=2)
        print(f"\n|+| JSON output saved to {json_out}")

    if csv_out:
        with open(csv_out, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Header", "Status", "Details", "Purpose"])
            for row in sec_table:
                writer.writerow(row)
        print(f"|+| CSV output saved to {csv_out}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Security Header Analyzer with Server Fingerprinting and Export Options")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--json-output", help="Save results as JSON file")
    parser.add_argument("--csv-output", help="Save security headers as CSV file")
    args = parser.parse_args()
    analyze_headers(args.url, json_out=args.json_output, csv_out=args.csv_output)
