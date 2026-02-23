# tag_suspicious_domains.py
# Example Python script to tag suspicious domains in log data

def tag_domain(domain):
    suspicious_keywords = ["bad", "evil", "malware"]
    for keyword in suspicious_keywords:
        if keyword in domain:
            return True
    return False

if __name__ == "__main__":
    domains = ["good.com", "bad-domain.com", "neutral.net"]
    for d in domains:
        if tag_domain(d):
            print(f"Suspicious domain detected: {d}")
