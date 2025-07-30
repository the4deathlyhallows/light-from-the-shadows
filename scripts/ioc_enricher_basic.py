def check_ioc_reputation(ioc):
    suspicious_keywords = ['bad', 'malware', 'evil']
    for keyword in suspicious_keywords:
        if keyword in ioc.lower():
            return True
    return False

def enrich_iocs(iocs):
    results = {}
    for ioc in iocs:
        if check_ioc_reputation(ioc):
            results[ioc] = "Suspicious"
        else:
            results[ioc] = "Clean"
    return results

def read_iocs_from_file(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

if __name__ == "__main__":
    filename = "iocs.txt"
    try:
        iocs = read_iocs_from_file(filename)
        enriched = enrich_iocs(iocs)
        for ioc, status in enriched.items():
            print(f"{ioc}: {status}")
    except FileNotFoundError:
        print(f"File '{filename}' not found. Please create it with one IOC per line.")
