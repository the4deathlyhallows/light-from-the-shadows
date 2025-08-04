import re
import argparse

def read_iocs(file_path):
    try:
        with open(file_path, 'r') as file:
            iocs = [line.strip() for line in file if line.strip()]
            return iocs
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []

def detect_ioc_type(ioc):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(ioc):
        return "IP Address"

    md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
    if md5_pattern.match(ioc):
        return "MD5 Hash"

    domain_pattern = re.compile(r'^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$')
    if domain_pattern.match(ioc):
        return "Domain"

    return "Unknown"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IOC Enrichment Tool")
    parser.add_argument(
        "file",
        type=str,
        help="Path to file containing IOCs (one per line)"
    )
    args = parser.parse_args()

    ioc_list = read_iocs(args.file)
    if not ioc_list:
        print("No IOCs to process. Exiting.")
        exit()

    print("IOCs loaded:")
    for ioc in ioc_list:
        ioc_type = detect_ioc_type(ioc)
        print(f" - {ioc} ({ioc_type})")
