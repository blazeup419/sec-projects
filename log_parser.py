import re
from collections import Counter

def parse_auth_log(log_path):
    failed_attempts = Counter()
    sql_injections = Counter()
    
    # Regex to hunt for brute-force IPs
    ip_pattern = re.compile(r'Failed password for(?: invalid user)? \S+ from (\d+\.\d+\.\d+\.\d+)')
    
    # Regex to hunt for SQL Injection (e.g., ' OR 1=1, UNION SELECT)
    sqli_pattern = re.compile(r'(\b(UNION|SELECT|DROP)\b|(?:\'|\").*(?:OR|AND).*(?:\'|\"))', re.IGNORECASE)
    
    print(f"[*] Analyzing log file: {log_path}...\n")
    
    try:
        with open(log_path, 'r') as file:
            for line in file:
                # Check for brute-force patterns
                ip_match = ip_pattern.search(line)
                if ip_match:
                    ip = ip_match.group(1)
                    failed_attempts[ip] += 1
                
                # Check for SQL injection patterns
                sqli_match = sqli_pattern.search(line)
                if sqli_match:
                    sql_injections["SQLi Attempt Detected"] += 1
                    
        print("[+] Brute-Force Detection Summary:")
        for ip, count in failed_attempts.most_common(5):
            print(f"    [ALERT] IP: {ip} - {count} failed login attempts")
            
        print("\n[+] SQL Injection Detection Summary:")
        for attack, count in sql_injections.items():
            print(f"    [CRITICAL] {attack} - {count} times")
                
    except FileNotFoundError:
        print(f"[-] Error: Could not find the file at {log_path}")

if __name__ == "__main__":
    parse_auth_log('dummy_auth.log')