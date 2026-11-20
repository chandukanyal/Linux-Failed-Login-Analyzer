import re
from collections import Counter
from datetime import datetime

# Log file
log_file = "auth.log"

# Threshold for suspicious activity
threshold = 5

# Store failed login attempts
failed_ips = Counter()
failed_users = Counter()

# Read log file
try:
    with open(log_file, "r", encoding="utf-8") as file:
        logs = file.readlines()
except FileNotFoundError:
    print("Log file not found!")
    exit()

# Analyze logs
for line in logs:

    if "Failed password" in line:

        # Extract IP address
        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)

        # Extract username
        user_match = re.search(
            r"Failed password for (?:invalid user )?(\w+)",
            line
        )

        if ip_match:
            ip = ip_match.group(1)
            failed_ips[ip] += 1

        if user_match:
            username = user_match.group(1)
            failed_users[username] += 1

# Generate report
report = []

report.append("LINUX LOGIN SECURITY REPORT")
report.append("=" * 45)
report.append(f"Analysis Date: {datetime.now()}")
report.append("")

report.append("FAILED LOGIN ATTEMPTS BY IP")
report.append("-" * 45)

for ip, count in failed_ips.most_common():
    report.append(f"{ip} : {count} failed attempts")

report.append("")
report.append("FAILED LOGIN ATTEMPTS BY USERNAME")
report.append("-" * 45)

for username, count in failed_users.most_common():
    report.append(f"{username} : {count} failed attempts")

report.append("")
report.append("SUSPICIOUS IP ADDRESSES")
report.append("-" * 45)

suspicious_found = False

for ip, count in failed_ips.items():
    if count >= threshold:
        report.append(f"ALERT: {ip} - {count} failed attempts")
        suspicious_found = True

if not suspicious_found:
    report.append("No IP exceeded the alert threshold.")

report.append("")
report.append("Analysis completed.")

# Display report
for line in report:
    print(line)

# Save report
with open("security_report.txt", "w", encoding="utf-8") as file:
    file.write("\n".join(report))

print("\nReport saved to security_report.txt")