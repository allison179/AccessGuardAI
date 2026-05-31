import pandas as pd
import random
from datetime import datetime, timedelta

# Load users
users = pd.read_csv("data/users.csv")

records = []

today = datetime(2026, 5, 31)

for _, user in users.iterrows():

    user_id = user["user_id"]

    # Generate 20-60 login events per user
    num_events = random.randint(20, 60)

    for _ in range(num_events):

        days_ago = random.randint(0, 180)

        login_date = today - timedelta(days=days_ago)

        # 90% success, 10% failure
        status = random.choices(
            ["Success", "Failed"],
            weights=[90, 10]
        )[0]

        ip_address = (
            f"192.168."
            f"{random.randint(1,20)}."
            f"{random.randint(1,254)}"
        )

        records.append([
            user_id,
            login_date.strftime("%Y-%m-%d"),
            status,
            ip_address
        ])

# Add brute-force attack simulation
for _ in range(30):

    records.append([
        "U002",
        "2026-05-20",
        "Failed",
        "203.0.113.10"
    ])

# Add suspicious activity
for _ in range(20):

    records.append([
        "U019",
        "2026-05-25",
        "Failed",
        "198.51.100.5"
    ])

df = pd.DataFrame(
    records,
    columns=[
        "user_id",
        "login_date",
        "status",
        "ip_address"
    ]
)

df.to_csv(
    "data/login_history.csv",
    index=False
)

print(
    f"Generated {len(df)} login events"
)