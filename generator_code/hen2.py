import pandas as pd
from datetime import datetime, timedelta
import random

# ==========================================
# CONFIG
# ==========================================

USAGE_MIN_OFFSET_SEC = 5        # minimum 5 seconds after login
USAGE_MAX_OFFSET_SEC = 600      # maximum 10 minutes after login

# ==========================================
# STEP 1: Load existing CSVs
# ==========================================

okta_df = pd.read_csv("data/okta_logins.csv")
usage_df = pd.read_csv("data/app_usage.csv")

# Convert timestamps to datetime
okta_df["timestamp"] = pd.to_datetime(okta_df["timestamp"])
usage_df["timestamp"] = pd.to_datetime(usage_df["timestamp"])

# Filter only SUCCESS logins (FAILED logins cannot generate usage sessions)
okta_success = okta_df[okta_df["login_status"] == "SUCCESS"]

# Group logins per user
logins_by_user = {
    user: group.sort_values("timestamp").reset_index(drop=True)
    for user, group in okta_success.groupby("user")
}

# ==========================================
# STEP 2: Adjust app usage timestamps
# ==========================================

new_usage_times = []

for idx, row in usage_df.iterrows():
    user = row["user"]

    # If user has NO login events, keep original timestamp
    if user not in logins_by_user:
        new_usage_times.append(row["timestamp"])
        continue

    # Pick the most recent login BEFORE the usage
    user_logins = logins_by_user[user]

    # Choose ANY login event (latest or random)
    chosen_login = user_logins.sample(1).iloc[0]

    login_time = chosen_login["timestamp"]

    # Random offset (5 sec to 10 min)
    offset_sec = random.randint(USAGE_MIN_OFFSET_SEC, USAGE_MAX_OFFSET_SEC)
    new_time = login_time + timedelta(seconds=offset_sec)

    new_usage_times.append(new_time)

# Update the DataFrame
usage_df["timestamp"] = new_usage_times

# ==========================================
# STEP 3: Write back updated usage CSV
# ==========================================

usage_df.to_csv("data/app_usage.csv", index=False)

print("[OK] Updated app_usage.csv with realistic timestamps.")
