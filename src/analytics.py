import pandas as pd
from datetime import datetime

# Load datasets
users = pd.read_csv("data/users.csv")
login_history = pd.read_csv("data/login_history.csv")

print("\n========== ACCESSGUARD AI ==========")

# -----------------------------------
# DORMANT ACCOUNT DETECTION
# -----------------------------------

today = datetime(2026, 5, 31)

users["last_login"] = pd.to_datetime(users["last_login"])

users["days_inactive"] = (
    today - users["last_login"]
).dt.days

dormant_users = users[
    users["days_inactive"] > 90
]

print("\n=== DORMANT ACCOUNTS ===")
print(
    dormant_users[
        ["user_id", "name", "role", "days_inactive"]
    ]
)

# -----------------------------------
# PRIVILEGED USER DETECTION
# -----------------------------------

privileged_roles = [
    "Cloud Admin",
    "System Admin"
]

privileged_users = users[
    users["role"].isin(privileged_roles)
]

print("\n=== PRIVILEGED USERS ===")
print(
    privileged_users[
        ["user_id", "name", "role"]
    ]
)

# -----------------------------------
# FAILED LOGIN ANALYSIS
# -----------------------------------

failed_logins = login_history[
    login_history["status"] == "Failed"
]

failed_counts = (
    failed_logins
    .groupby("user_id")
    .size()
    .reset_index(name="failed_attempts")
)

print("\n=== FAILED LOGIN COUNTS ===")
print(
    failed_counts.sort_values(
        by="failed_attempts",
        ascending=False
    ).head(10)
)

# -----------------------------------
# BRUTE FORCE DETECTION
# -----------------------------------

brute_force = failed_counts[
    failed_counts["failed_attempts"] > 5
]

print("\n=== POTENTIAL BRUTE FORCE USERS ===")
print(brute_force)

# -----------------------------------
# SUSPICIOUS IP DETECTION
# -----------------------------------

suspicious_ips = (
    failed_logins
    .groupby("ip_address")
    .size()
    .reset_index(name="failed_count")
)

suspicious_ips = suspicious_ips[
    suspicious_ips["failed_count"] > 5
]

print("\n=== SUSPICIOUS IPS ===")
print(
    suspicious_ips.sort_values(
        by="failed_count",
        ascending=False
    )
)

# -----------------------------------
# SUMMARY
# -----------------------------------

print("\n=== SECURITY SUMMARY ===")

print("Total Users:", len(users))
print("Dormant Users:", len(dormant_users))
print("Privileged Users:", len(privileged_users))
print("Brute Force Alerts:", len(brute_force))
print("Suspicious IPs:", len(suspicious_ips))