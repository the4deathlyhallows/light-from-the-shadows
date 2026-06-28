def search_ip_in_log(log_file, target_ip):
    try:
        with open(log_file, "r") as f:
            for line_num, line in enumerate(f,1):
                if target_ip in line:
                    print(f"Line {line_num}: {line.strip()}")

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
if __name__ == "__main__":
    log_filename = "example.log"
    ip_to_find = "192.168.1.100"

    search_ip_in_log(log_filename, ip_to_find)