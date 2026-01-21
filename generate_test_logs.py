#!/usr/bin/env python3
"""
Generate test log file with various attack patterns for testing the log auditor.
This creates a realistic Apache access.log file with normal traffic mixed with attack attempts.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

# Normal IP addresses
NORMAL_IPS = [
    "192.168.1.100",
    "10.0.0.45",
    "172.16.0.12",
    "203.0.113.50",
    "198.51.100.25",
]

# Suspicious IPs (for attack simulation)
ATTACKER_IPS = [
    "185.220.100.240",
    "45.146.164.110",
    "176.113.115.94",
]

# Normal user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

# Normal endpoints
NORMAL_ENDPOINTS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/login",
    "/api/users",
]

# Attack payloads organized by type
SQL_INJECTION_PAYLOADS = [
    "/login?user=admin' OR '1'='1&pass=test",
    "/search?q=test' UNION SELECT * FROM users--",
    "/api?id=1; DROP TABLE users;--",
    "/user?id=1' OR 1=1--",
    "/login?user=' OR '1'='1--",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert('XSS')</script>",
    "/comment?text=<img src=x onerror=alert(1)>",
    "/search?q=javascript:alert(document.cookie)",
    "/user?name=<iframe src=javascript:alert(1)></iframe>",
]

COMMAND_INJECTION_PAYLOADS = [
    "/api/execute?cmd=cat /etc/passwd",
    "/download?file=../../../etc/passwd",
    "/api?param=test; ls -la",
    "/user?data=`whoami`",
]

PATH_TRAVERSAL_PAYLOADS = [
    "/../../etc/passwd",
    "/....//....//etc/passwd",
    "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/windows/../../system32/config/sam",
]

FILE_INCLUSION_PAYLOADS = [
    "/page.php?file=../../etc/passwd",
    "/include?path=../../../config.php",
    "/template?file=php://filter/read=string.rot13/resource=index.php",
]

AUTH_BYPASS_PAYLOADS = [
    "/login?user=admin'--",
    "/auth?username=admin OR 1=1--",
    "/login?pass=' OR '1'='1",
]


def generate_apache_log_entry(ip, timestamp, method, endpoint, status_code, user_agent):
    """Generate a standard Apache access.log entry."""
    return f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status_code} {random.randint(100, 5000)} "{user_agent}"\n'


def generate_test_log(output_file: str, num_lines: int = 500):
    """Generate a test log file with normal traffic and attack attempts."""
    
    print(f"🔨 Generating test log file: {output_file}")
    print(f"   Total lines: {num_lines}")
    print(f"   Includes: Normal traffic + Attack patterns\n")
    
    output_path = Path(output_file)
    base_time = datetime.now() - timedelta(hours=24)
    
    # Collect all attack payloads
    all_attacks = (
        [(payload, "SQL Injection") for payload in SQL_INJECTION_PAYLOADS] +
        [(payload, "Cross-Site Scripting (XSS)") for payload in XSS_PAYLOADS] +
        [(payload, "Command Injection") for payload in COMMAND_INJECTION_PAYLOADS] +
        [(payload, "Path Traversal") for payload in PATH_TRAVERSAL_PAYLOADS] +
        [(payload, "File Inclusion") for payload in FILE_INCLUSION_PAYLOADS] +
        [(payload, "Authentication Bypass") for payload in AUTH_BYPASS_PAYLOADS]
    )
    
    with open(output_path, 'w') as f:
        attack_count = 0
        normal_count = 0
        
        for i in range(num_lines):
            # 20% chance of attack, 80% normal traffic
            is_attack = random.random() < 0.20
            
            # Increment time slightly for each log entry
            timestamp = (base_time + timedelta(seconds=i*30)).strftime('%d/%b/%Y:%H:%M:%S %z')
            
            if is_attack and all_attacks:
                # Generate attack log entry
                attacker_ip = random.choice(ATTACKER_IPS)
                payload, attack_type = random.choice(all_attacks)
                
                # Mix of GET and POST for attacks
                method = random.choice(["GET", "POST"])
                status_code = random.choice([200, 400, 403, 404, 500])  # Various response codes
                user_agent = random.choice(USER_AGENTS)
                
                log_entry = generate_apache_log_entry(
                    attacker_ip, timestamp, method, payload, status_code, user_agent
                )
                f.write(log_entry)
                attack_count += 1
            else:
                # Generate normal log entry
                normal_ip = random.choice(NORMAL_IPS)
                endpoint = random.choice(NORMAL_ENDPOINTS)
                method = random.choice(["GET", "POST", "HEAD"])
                status_code = random.choice([200, 200, 200, 304, 404])  # Mostly successful
                user_agent = random.choice(USER_AGENTS)
                
                log_entry = generate_apache_log_entry(
                    normal_ip, timestamp, method, endpoint, status_code, user_agent
                )
                f.write(log_entry)
                normal_count += 1
    
    print(f"✅ Test log generated!")
    print(f"   Normal entries: {normal_count}")
    print(f"   Attack entries: {attack_count}")
    print(f"   File location: {output_path.absolute()}\n")
    print(f"💡 You can now run:")
    print(f"   python3 log_auditor.py {output_file}")


if __name__ == "__main__":
    import sys
    
    output_file = "test_access.log"
    num_lines = 500
    
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    if len(sys.argv) > 2:
        num_lines = int(sys.argv[2])
    
    generate_test_log(output_file, num_lines)
