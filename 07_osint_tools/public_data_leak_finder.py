import requests
from bs4 import BeautifulSoup
import re
import argparse
import os
import json
import time
import csv

# config constants
GITHUB_TOKEN = "YOUR_GITHUB_TOKEN"  
OUTPUT_FILE = "leak_results.json"
CSV_FILE = "leak_results.csv"

# keywords to search for
KEYWORDS = [
    "password", "passwd", "api_key", "secret", "credential", "leak",
    ".env", ".pem", "token", "confidential"
]

# regex patterns for sensitive data
DATA_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
    re.compile(r"AIza[0-9A-Za-z-_]{35}"),  # Google API Key
    re.compile(r"['\"](password|passwd|pwd)['\"]\s*[:=]\s*['\"][^'\"]+['\"]"),  
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),  # Slack tokens
    re.compile(r"discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),  
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+")  
]

# function that searches github code for keyword using api
def github_code_search(query, token, max_results=10):
    url = "https://api.github.com/search/code"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    params = {"q": query, "per_page": min(max_results, 100)}

    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 403 and "X-RateLimit-Remaining" in resp.headers:
        reset_time = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
        wait_for = reset_time - int(time.time())
        print(f"|!| Rate limit hit. Waiting {wait_for}s...")
        time.sleep(wait_for + 1)
        return github_code_search(query, token, max_results)

    if resp.status_code != 200:
        print(f"|!| GitHub search failed: {resp.status_code}")
        return []

    return resp.json().get("items", [])

# function that scrapes pastebin search results for a keyword
def pastebin_search(keyword, max_results=5):
    url = f"https://pastebin.com/search?q={keyword}"
    results = []
    r = requests.get(url)
    soup = BeautifulSoup(r.text, "html.parser")
    for a in soup.select(".glist-item a[href^='/']")[:max_results]:
        results.append("https://pastebin.com" + a["href"])
    return results

# function that checks text against regex patterns for sensitive data
def find_leaks_in_text(text):
    findings = []
    for pattern in DATA_PATTERNS:
        matches = pattern.findall(text)
        findings.extend(matches)
    return list(set(findings))  # unique results

# functions that save info into json or csv outputs
def save_json(results, out_file=OUTPUT_FILE):
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"|+| Results saved to {out_file}")


def save_csv(results, out_file=CSV_FILE):
    rows = []
    for src, entries in results.items():
        for entry in entries:
            for finding in entry["findings"]:
                rows.append([entry["source"], entry["url"], finding])

    with open(out_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "url", "finding"])
        writer.writerows(rows)

    print(f"|+| Results saved to {out_file}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Public Data Leak Finder")
    parser.add_argument("-k", "--keyword", help="Keyword to search for (default: built-in list)")
    parser.add_argument("-n", "--github-num", type=int, default=10, help="Max GitHub results")
    parser.add_argument("-t", "--token", help="GitHub token (or set GITHUB_TOKEN env var)")
    parser.add_argument("-o", "--output", help="JSON output file", default=OUTPUT_FILE)
    parser.add_argument("--csv", help="Optional CSV output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN") or GITHUB_TOKEN
    keywords = [args.keyword] if args.keyword else KEYWORDS

    all_results = {"github": [], "pastebin": []}

    print("|*| Searching GitHub for leaks...")
    for kw in keywords:
        gh_results = github_code_search(kw, token, args.github_num)
        for item in gh_results:
            file_url = item.get("html_url")
            snippet_url = item.get("url")
            code_resp = requests.get(snippet_url, headers={"Authorization": f"token {token}"})
            code_data = code_resp.json()

            if "content" in code_data and code_data["content"]:
                code_text = code_data["content"]
                findings = find_leaks_in_text(code_text)
                if findings:
                    entry = {"source": "github", "url": file_url, "findings": findings}
                    all_results["github"].append(entry)
                    if args.verbose:
                        print(f"[GITHUB LEAK] {file_url}: {findings}")

    print("|*| Searching Pastebin for leaks...")
    for kw in keywords:
        paste_results = pastebin_search(kw)
        for url in paste_results:
            page = requests.get(url)
            text = BeautifulSoup(page.text, "html.parser").text
            findings = find_leaks_in_text(text)
            if findings:
                entry = {"source": "pastebin", "url": url, "findings": findings}
                all_results["pastebin"].append(entry)
                if args.verbose:
                    print(f"[PASTEBIN LEAK] {url}: {findings}")

    save_json(all_results, args.output)
    if args.csv:
        save_csv(all_results, args.csv)

    print("\n|*| Done.")


if __name__ == "__main__":
    main()
