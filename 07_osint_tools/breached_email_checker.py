import requests
import argparse
import csv
import json
import datetime
import time
import os

API_KEY = "YOUR_RAPIDAPI_KEY"  
API_URL = "https://breachdirectory.p.rapidapi.com/"
API_HOST = "breachdirectory.p.rapidapi.com"

# function that queries apis to check if an email was breached
def check_email_breached(email, api_key):
    params = {"func": "auto", "term": email}
    headers = {
        "X-RapidAPI-Key": api_key,
        "X-RapidAPI-Host": API_HOST
    }

    print(f"|*| Checking breaches for {email}...")
    try:
        resp = requests.get(API_URL, headers=headers, params=params, timeout=10)
        if resp.status_code != 200:
            print(f"|!| API error {resp.status_code} for {email}")
            return None
        return resp.json()
    except requests.RequestException as e:
        print(f"|!| Request error for {email}: {e}")
        return None

# functions to save results to csv and json
def save_csv(results, filename):
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Email", "Breached", "Breaches Found"])
        for email, breach_info in results.items():
            breached = "Yes" if breach_info and "result" in breach_info else "No"
            breaches_list = ", ".join(b["name"] for b in breach_info.get("result", [])) if breached == "Yes" else "None"
            writer.writerow([email, breached, breaches_list])
    print(f"|+| CSV report saved: {filename}")

def save_json(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    print(f"|+| JSON report saved: {filename}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Email Breach Checker via BreachDirectory API")
    parser.add_argument("-e", "--email", help="Email address to check")
    parser.add_argument("-l", "--list", help="CSV file containing emails to check (one per line)")
    parser.add_argument("-k", "--key", help="BreachDirectory API key", default=API_KEY)
    parser.add_argument("-o", "--output", help="Base filename for output (default: timestamped)")
    parser.add_argument("--json", action="store_true", help="Also save results in JSON format")
    args = parser.parse_args()

    api_key = args.key
    results = {}
    emails = []

    if args.email:
        emails = [args.email.strip()]
    elif args.list:
        if os.path.exists(args.list):
            with open(args.list, newline='', encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:  
                        emails.append(row[0].strip())
        else:
            print(f"|!| File not found: {args.list}")
            return
    else:
        print("|!| Provide either an email (-e) or CSV list (-l)")
        return

    dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_filename = args.output or f"email_breach_report_{dt}"

    for email in emails:
        breach_data = check_email_breached(email, api_key)
        results[email] = breach_data
        time.sleep(1)  # Prevent hitting free API rate limit

    csv_file = f"{base_filename}.csv"
    save_csv(results, csv_file)

    if args.json:
        json_file = f"{base_filename}.json"
        save_json(results, json_file)

    print("|+| Done.")

if __name__ == "__main__":
    main()
