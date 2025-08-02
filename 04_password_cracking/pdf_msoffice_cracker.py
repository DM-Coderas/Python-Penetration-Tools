import argparse
import os
import time
from tqdm import tqdm
from pathlib import Path
import json
import csv

# function that uses pikepdf to iterate through a provided wordlist to brute force the pdf
def crack_pdf(pdf_file, wordlist, verbose=False):
    import pikepdf
    passwords = load_wordlist(wordlist)
    start = time.time()
    for pwd in tqdm(passwords, desc="Trying PDF passwords"):
        try:
            with pikepdf.open(pdf_file, password=pwd):
                print(f"|+| PDF password found: {pwd}")
                return pwd, time.time() - start
        except pikepdf._qpdf.PasswordError:
            if verbose:
                print(f"|-| Failed: {pwd}")
        except Exception as e:
            if verbose:
                print(f"|!| Error with {pwd}: {e}")
    print("|-| PDF password not found in wordlist.")
    return None, time.time() - start

# function that iterates through a provided wordlist to crack the office file
def crack_office(doc_file, wordlist, output_file=None, verbose=False):
    import msoffcrypto
    passwords = load_wordlist(wordlist)
    start = time.time()
    for pwd in tqdm(passwords, desc="Trying Office passwords"):
        try:
            with open(doc_file, "rb") as in_file:
                office = msoffcrypto.OfficeFile(in_file)
                office.load_key(password=pwd)
                if output_file:
                    with open(output_file, "wb") as out_file:
                        office.decrypt(out_file)
                else:
                    office.decrypt(None)
                print(f"|+| Office password found: {pwd}")
                return pwd, time.time() - start
        except Exception as e:
            if verbose:
                print(f"|-| Failed: {pwd} - {e}")
    print("|-| Office document password not found in wordlist.")
    return None, time.time() - start

# function that makes a wordlist readable and usable
def load_wordlist(path):
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

# function that saves output into json and csv formats
def save_output(password, duration, output, fmt="json"):
    data = {
        "password": password,
        "time_taken": round(duration, 2),
    }
    if fmt == "json":
        with open(Path(output).with_suffix(".json"), "w") as f:
            json.dump(data, f, indent=2)
    elif fmt == "csv":
        with open(Path(output).with_suffix(".csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["password", "time_taken"])
            writer.writeheader()
            writer.writerow(data)

# arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="PDF/Office Document Password Cracker")
    parser.add_argument("file", help="Password-protected file (.pdf/.docx/.xlsx/.pptx)")
    parser.add_argument("wordlist", help="Password wordlist file")
    parser.add_argument("-o", "--output", help="Output decrypted file (for Office) or result log", default=None)
    parser.add_argument("--outfmt", choices=["json", "csv"], help="Output format if saving result")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    ext = os.path.splitext(args.file)[1].lower()
    password = None
    duration = 0

    if ext == ".pdf":
        password, duration = crack_pdf(args.file, args.wordlist, args.verbose)
    elif ext in (".docx", ".xlsx", ".pptx"):
        password, duration = crack_office(args.file, args.wordlist, args.output, args.verbose)
    else:
        print("|x| Unsupported file type. Only PDF, DOCX/XLSX/PPTX are supported.")
        return

    if password and args.output and args.outfmt:
        save_output(password, duration, args.output, args.outfmt)

if __name__ == "__main__":
    cli()
