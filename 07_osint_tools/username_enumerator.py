import requests
import argparse
import concurrent.futures
import csv
import json
import os

# list of platforms and url patterns, each individual tuple
PLATFORMS = [
    ("GitHub",        "https://github.com/{}"),
    ("Twitter",       "https://twitter.com/{}"),
    ("Instagram",     "https://instagram.com/{}"),
    ("Reddit",        "https://www.reddit.com/user/{}"),
    ("YouTube",       "https://www.youtube.com/@{}"),
    ("Facebook",      "https://facebook.com/{}"),
    ("Twitch",        "https://twitch.tv/{}"),
    ("Medium",        "https://medium.com/@{}"),
    ("Pinterest",     "https://pinterest.com/{}"),
    # add more platforms if needed
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# function that checks if a username exists on a platform and returns the tuple
def check_single(username, platform, url_format):
    url = url_format.format(username)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=7)

        if resp.status_code == 200:
            return (platform, url, True)
        elif resp.status_code == 404:
            return (platform, url, False)
        else:
            if platform == "YouTube" and "This channel does not exist" in resp.text:
                return (platform, url, False)
            return (platform, url, True)

    except Exception:
        return (platform, url, None)

# function that performs a multiplatform username check
def check_username(username, threads=5):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_platform = {
            executor.submit(check_single, username, platform, url_format): (platform, url_format)
            for platform, url_format in PLATFORMS
        }
        for future in concurrent.futures.as_completed(future_to_platform):
            results.append(future.result())
    return results

# functions that save results to csv and json
def save_csv(filename, results):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Platform", "Profile URL", "Status"])
        for platform, url, exists in results:
            if exists is True:
                status = "TAKEN"
            elif exists is False:
                status = "FREE"
            else:
                status = "ERROR"
            writer.writerow([platform, url, status])

def save_json(filename, results):
    data = []
    for platform, url, exists in results:
        if exists is True:
            status = "TAKEN"
        elif exists is False:
            status = "FREE"
        else:
            status = "ERROR"
        data.append({"platform": platform, "url": url, "status": status})

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Username Enumeration Across Multiple Platforms")
    parser.add_argument("username", help="The username to check")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads for parallel checks")
    parser.add_argument("--csv", help="Save results to a CSV file")
    parser.add_argument("--json", help="Save results to a JSON file")
    args = parser.parse_args()

    print(f"|*| Checking username: '{args.username}' across {len(PLATFORMS)} platforms...\n")
    results = check_username(args.username, threads=args.threads)

    for platform, url, exists in sorted(results):
        if exists is True:
            print(f"[TAKEN]  {platform:<12} {url}")
        elif exists is False:
            print(f"[FREE]   {platform:<12}")
        else:
            print(f"[ERROR]  {platform:<12} (Request failed)")

    if args.csv:
        save_csv(args.csv, results)
        print(f"|+| Results saved to CSV: {os.path.abspath(args.csv)}")

    if args.json:
        save_json(args.json, results)
        print(f"|+| Results saved to JSON: {os.path.abspath(args.json)}")

    print("\n|+| Done.")

if __name__ == "__main__":
    main()
