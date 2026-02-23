IP Search in Logs
A simple Python script to search for a specific IP address in a log file and print all matching lines with their line numbers.
Usage
Update the script search_ip.py with your log file path and the IP address you want to find:
log_filename = "example.log"      # Replace with your log file
ip_to_find = "192.168.1.100"      # Replace with the IP address you want to search
Run the script:
python3 search_ip.py
The script prints all lines containing the IP along with their line numbers.
How it works
Opens the log file safely
Reads each line and checks if the target IP is present
Prints matching lines cleanly with line numbers
Handles file-not-found errors gracefully
