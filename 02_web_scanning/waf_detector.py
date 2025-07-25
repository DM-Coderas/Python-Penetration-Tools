import argparse
import requests
from tqdm import tqdm
import csv
import json
from urllib.parse import urlparse

# these are a list of known waf vendors for fingerprinting, can be expanded if wished
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-request-id", "cf-cache-status", "cloudflare"],
    "Akamai": ["akamai", "akamai-ghost", "akamai-bot"],
    "AWS WAF": ["awselb", "x-amzn-remapped-content-length"],
    "F5 BIG-IP ASM": ["x-waf-event", "x-asm-waf"],
    "Imperva Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "incapsula"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-block"],
    "Barracuda": ["barracuda", "nginx-barracuda"],
}

# payloads commonly blocked by wafs
WAF_TEST_PAYLOADS = [
    "/<script>alert(1)</script>",
    "/' AND 1=1--",
    "/../../../../etc/passwd",
    "/?param=<script>",
    "/?param=' OR 'a'='a"
]

# function that attempts to connect the waf to the vendor list based on their unique http headers
def check_waf_headers(headers):
    found = []
    lower = {k.lower(): v.lower() for k, v in headers.items()}
    for waf, keys in WAF_SIGNATURES.items():
        for k in keys:
            for h in lower:
                if k in h or k in lower[h]:
                    found.append(waf)
    return list(set(found))

# function that identifies the signs of a vendor blocking
def is_suspicious(status_code, resp_text):
    return status_code in [403, 406, 419, 501, 999] or "waf" in resp_text.lower()

# function that saves results into the csv format
def export_to_csv(data, output_file):
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Field", "Value"])
        for key, value in data.items():
            if isinstance(value, dict):
                for sub_key, sub_val in value.items():
                    writer.writerow([f"{key}.{sub_key}", sub_val])
            elif isinstance(value, list):
                writer.writerow([key, "; ".join(str(v) for v in value)])
            else:
                writer.writerow([key, value])

# function that outputs results into the json format
def export_to_json(data, output_file):
    with open(output_file, mode='w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

# primary function in which it deconstructs and reconstructs the url with the payload, sends it as a get request and records the result using previous functions, like vendor or status codes
def detect_waf(url, export_csv=False, export_json=False):
    results = {
        "url": url,
        "detected_wafs": [],
        "response_codes": {},
        "titles": [],
        "challenge_detected": False
    }

    try:
        base = url.rstrip("/")
        findings = set()
        print(f"|*| Testing for WAF fingerprints at {base} ...")
        for payload in tqdm(WAF_TEST_PAYLOADS, desc="Probing"):
            target = base + payload
            try:
                resp = requests.get(target, timeout=8, headers={'User-Agent': "Mozilla/5.0 WAFTest"})
                results["response_codes"][payload] = resp.status_code

                # check headers
                wafs = check_waf_headers(resp.headers)
                if wafs:
                    for w in wafs:
                        findings.add(w)

                # check for suspicious page titles
                if "<title>" in resp.text.lower():
                    title_start = resp.text.lower().find("<title>")
                    title_end = resp.text.lower().find("</title>")
                    if title_start != -1 and title_end != -1:
                        title = resp.text[title_start + 7:title_end]
                        results["titles"].append(title.strip())
                        if "attention required" in title.lower() or "challenge" in title.lower():
                            results["challenge_detected"] = True

                # check for suspicious responses
                if is_suspicious(resp.status_code, resp.text):
                    findings.add("generic/unknown (blocked response)")

            except requests.RequestException:
                continue

        results["detected_wafs"] = sorted(list(findings))

        if findings:
            print(f"\n|+| WAF detected! Possible vendor(s): {', '.join(findings)}")
        else:
            print("|*| No WAF detected with basic fingerprinting.")

        # export if requested
        domain = urlparse(url).netloc.replace('.', '_')
        if export_csv:
            csv_path = f"waf_results_{domain}.csv"
            export_to_csv(results, csv_path)
            print(f"|+| CSV results saved to: {csv_path}")
        if export_json:
            json_path = f"waf_results_{domain}.json"
            export_to_json(results, json_path)
            print(f"|+| JSON results saved to: {json_path}")

    except Exception as e:
        print(f"|x| Error: {e}")

# arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Advanced Python WAF Detector")
    parser.add_argument("url", help="Base URL to test (e.g. https://example.com/)")
    parser.add_argument("--csv", action="store_true", help="Export results to CSV")
    parser.add_argument("--json", action="store_true", help="Export results to JSON")
    args = parser.parse_args()
    detect_waf(args.url, export_csv=args.csv, export_json=args.json)

if __name__ == "__main__":
    cli()
