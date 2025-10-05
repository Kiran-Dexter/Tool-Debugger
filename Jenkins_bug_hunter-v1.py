import os
import zipfile
import argparse
import tempfile
import csv
import traceback
import sys
import io

# Force stdout to UTF-8 encoding to avoid "charmap" errors on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', errors='replace')

KEYWORDS = ["System.exit", "exit", "shutdown", "Terminating", "Shutting down"]
CSV_FILENAME = "jenkins_exit_report.csv"

def search_file(file_path):
    matches = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            for i, line in enumerate(f, start=1):
                for keyword in KEYWORDS:
                    if keyword.lower() in line.lower():
                        matches.append((file_path, i, keyword, line.strip()))
    except Exception as e:
        print(f"[WARNING] Skipped unreadable file: {file_path} ({e})")
    return matches

def search_directory(path):
    all_matches = []
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            matches = search_file(file_path)
            all_matches.extend(matches)
    return all_matches

def extract_zip(zip_path):
    try:
        temp_dir = tempfile.mkdtemp(prefix="jenkins_support_")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        print(f"[INFO] Extracted ZIP to temporary folder: {temp_dir}")
        return temp_dir
    except zipfile.BadZipFile:
        print("[ERROR] The file is not a valid ZIP archive.")
        exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to extract ZIP: {e}")
        traceback.print_exc()
        exit(1)

def save_to_csv(matches):
    try:
        with open(CSV_FILENAME, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["File", "Line Number", "Keyword", "Line"])
            for row in matches:
                writer.writerow(row)
        print(f"\n[INFO] CSV saved to: {os.path.abspath(CSV_FILENAME)}")
    except Exception as e:
        print(f"[ERROR] Failed to write CSV: {e}")

def print_result(matches):
    if matches:
        print("\n[RESULTS] Matches Found:\n")
        for file_path, line_no, keyword, line in matches:
            print(f"[FILE] {file_path}")
            print(f"  Line {line_no} | Keyword: {keyword}")
            print(f"  >> {line}\n")
        save_to_csv(matches)
    else:
        print("[OK] No shutdown-related keywords found in the bundle.")

def main():
    parser = argparse.ArgumentParser(description="Scan Jenkins support bundle for System.exit and shutdown activity.")
    parser.add_argument("path", help="Path to Jenkins support bundle (.zip or folder)")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print("[ERROR] Path does not exist.")
        exit(1)

    if os.path.isfile(args.path) and args.path.endswith(".zip"):
        scan_path = extract_zip(args.path)
    elif os.path.isdir(args.path):
        scan_path = args.path
    else:
        print("[ERROR] Unsupported file type. Provide a .zip or a folder path.")
        exit(1)

    print(f"[INFO] Scanning for shutdown keywords in: {scan_path}")
    matches = search_directory(scan_path)
    print_result(matches)

if __name__ == "__main__":
    main()
