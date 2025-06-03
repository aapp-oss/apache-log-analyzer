import re
from collections import defaultdict, Counter

# === Configurations ===
LOG_FILE = "log.txt"                    # Apache log file to analyze
FAILED_STATUSES = {'401', '403'}        # Status codes for failed logins
SCAN_THRESHOLD = 30                     # # of requests before flagging scanner
FAIL_THRESHOLD = 5                      # # of failed logins to flag an IP

# === Regex pattern for Apache combined log format ===
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s'     # Match IP address
    r'\S+\s\S+\s'                       # Skip logname & user
    r'\[(?P<time>[^\]]+)\]\s'           # Match timestamp
    r'"(?P<method>GET|POST|HEAD|PUT|DELETE|OPTIONS)\s(?P<path>.*?)\sHTTP/1\.\d"\s'  # HTTP request
    r'(?P<status>\d{3})\s'              # Status code
    r'\d+'                              # Ignore response size
)

# === Data tracking ===
request_count = Counter()               # Count all requests per IP
failed_logins = defaultdict(int)        # Count failed logins per IP
interesting_paths = ["/login", "/wp-login", "/admin"]

# === Parse the log file ===
with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        match = log_pattern.search(line)
        if match:
            ip = match.group("ip")
            status = match.group("status")
            path = match.group("path")

            request_count[ip] += 1

            if status in FAILED_STATUSES:
                failed_logins[ip] += 1

            if any(p in path.lower() for p in interesting_paths):
                print(f"[!] Interesting path hit by {ip}: {path}")

# === Report ===
print("\n=== Top Talkers ===")
for ip, count in request_count.most_common(10):
    print(f"{ip}: {count} requests")

print("\n=== Failed Login Attempts ===")
for ip, count in failed_logins.items():
    if count >= FAIL_THRESHOLD:
        print(f"{ip}: {count} failed logins")

print("\n=== Potential Scanners ===")
for ip, count in request_count.items():
    if count >= SCAN_THRESHOLD:
        print(f"{ip}: {count} requests — possible scanning behavior")

print("\n✅ Analysis complete.")