import sys
import argparse
import json
import csv
import os
from samdumpy.sam import parseSAM
from samdumpy.system import parseSYSTEM

# constants that direct to the default paths
DEFAULT_CONFIG_PATH = r"C:\Windows\System32\config"
DEFAULT_SAM_PATH = os.path.join(DEFAULT_CONFIG_PATH, "SAM")
DEFAULT_SYSTEM_PATH = os.path.join(DEFAULT_CONFIG_PATH, "SYSTEM")

# function that parses through the system and sam hives to find valuable info and outputs it into json or csv formats
def extract_ntlm_hashes(sam_path, system_path, output=None, jsonout=None, csvout=None, filter_empty=False):
    bootkey = parseSYSTEM(system_path)
    users = parseSAM(sam_path, bootkey)

    results = []

    for username, entry in users.items():
        ntlm_hash = entry['hash_ntlm'].hex()
        if filter_empty and (ntlm_hash == '' or ntlm_hash == '31d6cfe0d16ae931b73c59d7e0c089c0'):  # default blank hash
            continue
        results.append({'username': username, 'ntlm': ntlm_hash})
        print(f"{username}:{ntlm_hash}")

    if output:
        with open(output, "w") as f:
            for r in results:
                f.write(f"{r['username']}:{r['ntlm']}\n")

    if jsonout:
        with open(jsonout, "w") as f:
            json.dump(results, f, indent=2)

    if csvout:
        with open(csvout, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["username", "ntlm"])
            writer.writeheader()
            writer.writerows(results)

# checks if the file exists
def file_exists_or_exit(path, name):
    if not os.path.exists(path):
        print(f"|!| {name} file not found: {path}")
        sys.exit(1)

# arg parser for cli customizability
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract NTLM hashes from Windows SAM and SYSTEM hive files.")
    parser.add_argument("--sam", help="Path to SAM hive (default: Windows config path)", default=DEFAULT_SAM_PATH)
    parser.add_argument("--system", help="Path to SYSTEM hive (default: Windows config path)", default=DEFAULT_SYSTEM_PATH)
    parser.add_argument("--output", help="Output file (username:hash)")
    parser.add_argument("--jsonout", help="Save output as JSON")
    parser.add_argument("--csvout", help="Save output as CSV")
    parser.add_argument("--filter-empty", action="store_true", help="Filter out empty/default hashes")

    args = parser.parse_args()

    file_exists_or_exit(args.sam, "SAM")
    file_exists_or_exit(args.system, "SYSTEM")

    extract_ntlm_hashes(
        sam_path=args.sam,
        system_path=args.system,
        output=args.output,
        jsonout=args.jsonout,
        csvout=args.csvout,
        filter_empty=args.filter_empty
    )
