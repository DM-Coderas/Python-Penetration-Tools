import os
import exifread
from PyPDF2 import PdfReader
from docx import Document
from mutagen import File as AudioFile
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# function that performs the act of extracting metadata from images
def extract_image_metadata(filepath):
    try:
        with open(filepath, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        return {k: str(v) for k, v in tags.items()}
    except Exception as e:
        return {"error": f"Image metadata extraction failed: {e}"}

# function that performs the act of extracting metadata from pdfs
def extract_pdf_metadata(filepath):
    try:
        reader = PdfReader(filepath)
        meta = reader.metadata
        return {k: str(v) for k, v in meta.items()}
    except Exception as e:
        return {"error": f"PDF metadata extraction failed: {e}"}

# function that performs the act of extracting metadata from docx files
def extract_docx_metadata(filepath):
    try:
        doc = Document(filepath)
        core = doc.core_properties
        props = {k: getattr(core, k) for k in dir(core) if not k.startswith("_") and not callable(getattr(core, k))}
        return props
    except Exception as e:
        return {"error": f"DOCX metadata extraction failed: {e}"}

# function that performs the act of extracting metadata from audio files
def extract_audio_metadata(filepath):
    try:
        audio = AudioFile(filepath)
        if not audio:
            return {}
        return {k: str(v) for k, v in audio.items()}
    except Exception as e:
        return {"error": f"Audio metadata extraction failed: {e}"}
# function that activates previous functions
def extract_metadata(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ['.jpg', '.jpeg', '.tiff', '.png']:
        return extract_image_metadata(filepath)
    elif ext == '.pdf':
        return extract_pdf_metadata(filepath)
    elif ext == '.docx':
        return extract_docx_metadata(filepath)
    elif ext in ['.mp3', '.flac', '.ogg', '.wav', '.m4a']:
        return extract_audio_metadata(filepath)
    else:
        return {"error": "Unsupported file type."}

# function that performs the action of finding the files the user wants
def find_files(paths, recursive=False):
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            if recursive:
                for root, _, filenames in os.walk(p):
                    for fname in filenames:
                        files.append(os.path.join(root, fname))
            else:
                for fname in os.listdir(p):
                    fpath = os.path.join(p, fname)
                    if os.path.isfile(fpath):
                        files.append(fpath)
    return files

# function that parses through file ensuring existence
def process_file(filepath):
    if not os.path.exists(filepath):
        return filepath, {"error": "File not found"}
    meta = extract_metadata(filepath)
    return filepath, meta

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Metadata Extractor")
    parser.add_argument("path", nargs="+", help="File(s) or directory(ies) to extract metadata from")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively scan directories")
    parser.add_argument("-o", "--output", help="Save results to a JSON file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    args = parser.parse_args()

    all_files = find_files(args.path, args.recursive)
    results = {}

    print(f"|*| Processing {len(all_files)} files using {args.threads} threads...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_file, f): f for f in all_files}
        for future in as_completed(futures):
            filepath, meta = future.result()
            results[filepath] = meta

            print(f"\n=== Metadata for {filepath} ===")
            for k, v in meta.items():
                print(f"{k}: {v}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out:
                json.dump(results, out, indent=4)
            print(f"\n|+| Metadata saved to {args.output}")
        except Exception as e:
            print(f"|!| Failed to save JSON output: {e}")

if __name__ == "__main__":
    main()
