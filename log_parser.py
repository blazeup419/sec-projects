import re
from collections import Counter

def parse_auth_log(log_path):
    failed_attempts = Counter()

    # Regular expression (regex) to hunt for failed login attempts and extract the IP address
    ip_pattern = re.compile(r'Failed password for(?: invalid user)? \S+ from (\d+\.\d+\.\d+\.\d+)')

    print(f"[*] Analyzing log file: {log_path}...\n")

    try:
        with open(log_path, 'r') as file:
            for line in file:
                # Search each line of the log for our attack pattern
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(1)
                    failed_attempts[ip] += 1

        print("[+] Brute-Force Detection Summary:")
        # Display the top attacking IPs
        for ip, count in failed_attempts.most_common(5):
            print(f"    [ALERT] IP: {ip} - {count} failed login attempts")

    except FileNotFoundError:
        print(f"[-] Error: Could not find the file at {log_path}")

if __name__ == "__main__":
    # Tell the script to parse our dummy log file
    parse_auth_log('dummy_auth.log')