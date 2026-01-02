# ===========================
# FILE PART 1 / 4
# ===========================

import pandas as pd
import random
import uuid
import numpy as np
import math
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Set
from collections import namedtuple

# --- Configuration ---
NUM_USERS = 50
START_DATE = datetime(2025, 10, 1)
END_DATE = datetime(2025, 12, 1)
SESSION_DURATION_HRS = 8
ANOMALY_RATE = 0.03

# ------------------------------------
# HR LIFECYCLE DEFINITIONS
# ------------------------------------
DEPARTMENTS = ["Engineering", "Finance", "HR", "DevOps", "DataScience", "Support"]
ROLES = ["Intern", "Associate", "Developer", "Analyst", "Senior", "Manager"]
LOCATIONS = ["India", "USA", "UK", "Germany", "Singapore"]

HrEvent = namedtuple("HrEvent", [
    "user", "join_date", "move_date1", "move_date2",
    "termination_date", "department", "job_role", "location"
])

def generate_hr_events():
    hr_data = []
    for user in USERS:
        join_date = START_DATE + timedelta(days=random.randint(0, 5))

        # Movers—40% chance
        move_date1 = join_date + timedelta(days=random.randint(10, 25)) \
            if random.random() < 0.4 else None
        move_date2 = (move_date1 + timedelta(days=random.randint(10, 25))
                      if move_date1 and random.random() < 0.3 else None)

        # Leavers—20%
        termination_date = (join_date + timedelta(days=random.randint(30, 55))
                            if random.random() < 0.2 else None)
        if termination_date and termination_date > END_DATE:
            termination_date = END_DATE - timedelta(days=1)

        hr_data.append(HrEvent(
            user=user,
            join_date=join_date,
            move_date1=move_date1,
            move_date2=move_date2,
            termination_date=termination_date,
            department=random.choice(DEPARTMENTS),
            job_role=random.choice(ROLES),
            location=random.choice(LOCATIONS)
        ))
    return hr_data

# ------------------------------------
# IDENTITY, LOGGING & ACTION DEFINITIONS
# ------------------------------------
USERS = [f'user{i+1}' for i in range(NUM_USERS)]
DEVICES = ['Mac', 'Windows', 'Linux', 'iPhone', 'Android']
MFA_TYPES = ['TOTP', 'Push', 'SMS', 'Email']
COUNTRIES = ['USA', 'UK', 'Germany', 'Japan', 'Singapore', 'India', 'Brazil', 'Australia']
SAVIYNT_APPS = ['Snowflake', 'Databricks', 'GitHub', 'Jira', 'Salesforce', 'SAP', 'Workday']
AD_GROUPS = ['DBA', 'DevOps', 'Finance', 'HR', 'Workday', 'Contractor']
ACTIONS = ['view', 'modify', 'upload', 'download']
SAVIYNT_ROLES = ['Reader', 'Editor', 'Developer', 'Admin']
JUSTIFICATIONS = ['BAU', 'Project Work', 'Emergency']
AD_ACTIONS = ['add_member', 'remove_member', 'privilege_escalation']

# ------------------------------------
# Anomaly Labels
# ------------------------------------
ANOMALY_LABELS = {
    'Q1': 'Q1: IMPOSSIBLE TRAVEL: Login from {country1} → {country2} within {time_diff} minutes',
    'Q2': 'Q2: ORPHAN REQUEST: Approved request {req_id} had no usage',
    'Q3': 'Q3: PRIVILEGE ESCALATION: {initiator} escalated themselves in {group}',
    'Q4': 'Q4: VPN GEO MISMATCH False Positive',
    'Q5': 'Q5: LONG SESSION: Session lasted {session_duration}h > {limit}',
    'Q6': 'Q6: AD EVENT AFTER SESSION EXPIRY: Event {event_id} occurred {time_diff} hours late',
}

# ------------------------------------
# Helper Functions
# ------------------------------------
def _get_random_ip(country):
    if country in ['USA', 'UK']:
        return f"{random.randint(10,199)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
    elif country in ['Japan', 'Singapore']:
        return f"{random.randint(200,220)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
    else:
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def _random_timestamp(start, end):
    return start + timedelta(seconds=random.randint(0, int((end-start).total_seconds())))

# ===========================
# FILE PART 2 / 4
# ===========================

# ------------------------------------
# NAMEDTUPLES
# ------------------------------------
OktaRequest = namedtuple('OktaRequest',
    ['req_id', 'user', 'ts', 'device', 'ip', 'country', 'mfa', 'status', 'session_id']
)

SaviyntRequest = namedtuple('SaviyntRequest',
    ['req_id', 'user', 'ts', 'app', 'role', 'status', 'approver', 'group']
)

AdGroupEvent = namedtuple('AdGroupEvent',
    ['event_id', 'ts', 'user', 'group', 'action', 'initiator', 'ip', 'request_id']
)

AppUsage = namedtuple('AppUsage',
    ['usage_id', 'ts', 'user', 'app', 'action', 'duration', 'data_mb', 'session_id', 'request_id']
)

# ------------------------------------
# Anomaly Injectors
# ------------------------------------
def _inject_impossible_travel_anomaly(user, logins):
    ts1 = _random_timestamp(START_DATE, END_DATE - timedelta(minutes=20))
    ts2 = ts1 + timedelta(minutes=random.randint(1, 5))

    c1 = random.choice(['USA', 'UK'])
    c2 = random.choice(['Japan', 'Singapore'])

    logins.append(OktaRequest(
        str(uuid.uuid4()), user, ts1, random.choice(DEVICES),
        _get_random_ip(c1), c1, random.choice(MFA_TYPES),
        'SUCCESS', str(uuid.uuid4())
    ))

    logins.append(OktaRequest(
        str(uuid.uuid4()), user, ts2, random.choice(DEVICES),
        _get_random_ip(c2), c2, random.choice(MFA_TYPES),
        'SUCCESS', str(uuid.uuid4())
    ))

    diff = int((ts2 - ts1).total_seconds() / 60)
    return ANOMALY_LABELS['Q1'].format(country1=c1, country2=c2, time_diff=diff)


def _inject_false_positive_anomaly(user, logins):
    ts1 = _random_timestamp(START_DATE, END_DATE - timedelta(days=3))
    ts2 = ts1 + timedelta(days=random.randint(2, 5))

    # Same IP → different GeoCountries
    ip = "192.168.1.5"

    logins.append(OktaRequest(
        str(uuid.uuid4()), user, ts1, random.choice(DEVICES),
        ip, 'USA', random.choice(MFA_TYPES), 'SUCCESS', str(uuid.uuid4())
    ))

    logins.append(OktaRequest(
        str(uuid.uuid4()), user, ts2, random.choice(DEVICES),
        ip, 'India', random.choice(MFA_TYPES), 'SUCCESS', str(uuid.uuid4())
    ))

    return ANOMALY_LABELS['Q4']


# ========================================================
# OKTA LOGIN GENERATOR (LIFECYCLE-AWARE + REALISTIC)
# ========================================================
def generate_okta_logins(anomaly_users, hr_map):
    all_logins = []
    anomalies = {}

    for user in USERS:
        hr = hr_map[user]
        start = hr.join_date
        end = hr.termination_date or END_DATE

        # daily pattern: more logins AM & PM
        num = random.randint(15, 55)
        for _ in range(num):
            ts = _random_timestamp(start, end)

            country = random.choice(COUNTRIES)
            status = 'SUCCESS' if random.random() < 0.9 else 'FAILED'
            session_id = str(uuid.uuid4()) if status == 'SUCCESS' else ''

            all_logins.append(
                OktaRequest(
                    str(uuid.uuid4()), user, ts, random.choice(DEVICES),
                    _get_random_ip(country), country,
                    random.choice(MFA_TYPES), status, session_id
                )
            )

    # anomalies (unchanged logic)
    for user in anomaly_users:
        if random.random() < 0.5:
            anomalies.setdefault(user, []).append(
                _inject_impossible_travel_anomaly(user, all_logins)
            )
        if random.random() < 0.5:
            anomalies.setdefault(user, []).append(
                _inject_false_positive_anomaly(user, all_logins)
            )

    all_logins.sort(key=lambda x: x.ts)
    return all_logins, anomalies


# ========================================================
# SAVIYNT ACCESS REQUEST GENERATOR (LIFECYCLE-AWARE)
# ========================================================
def generate_saviynt_requests(okta_logins, anomaly_users, hr_map):
    all_requests = []
    anomalies = {}

    for user in USERS:
        hr = hr_map[user]
        start = hr.join_date
        end = hr.termination_date or END_DATE

        num = random.randint(3, 12)

        for _ in range(num):
            ts = _random_timestamp(start, end)

            # Movers — advanced roles
            if hr.move_date1 and ts > hr.move_date1:
                role = random.choice(['Developer', 'Admin'])
            else:
                role = random.choice(['Reader', 'Editor'])

            all_requests.append(
                SaviyntRequest(
                    str(uuid.uuid4()), user, ts,
                    random.choice(SAVIYNT_APPS), role,
                    random.choice(['APPROVED', 'REJECTED', 'PENDING']),
                    random.choice(USERS), random.choice(JUSTIFICATIONS)
                )
            )

    # ORPHAN REQUEST anomaly
    for user in anomaly_users:
        if random.random() < 0.5:
            req_id = str(uuid.uuid4())
            ts = _random_timestamp(hr_map[user].join_date,
                                   hr_map[user].termination_date or END_DATE)

            all_requests.append(
                SaviyntRequest(
                    req_id, user, ts,
                    random.choice(SAVIYNT_APPS),
                    'Developer', 'APPROVED',
                    random.choice(USERS), 'Emergency'
                )
            )

            anomalies.setdefault(user, []).append(
                ANOMALY_LABELS['Q2'].format(req_id=req_id)
            )

    all_requests.sort(key=lambda x: x.ts)
    return all_requests, anomalies


# ========================================================
# AD GROUP EVENT GENERATOR (LIFECYCLE-AWARE + DRIFT)
# ========================================================
def generate_ad_group_events(anomaly_users, hr_map):
    all_events = []
    anomalies = {}

    for user in USERS:
        hr = hr_map[user]
        start = hr.join_date
        end = hr.termination_date or END_DATE

        num = random.randint(2, 7)

        for _ in range(num):
            ts = _random_timestamp(start, end)

            # Movers → drift toward higher privilege groups
            if hr.move_date1 and ts > hr.move_date1:
                group = random.choice(['DBA', 'DevOps', 'Finance'])
            else:
                group = random.choice(AD_GROUPS)

            all_events.append(
                AdGroupEvent(
                    str(uuid.uuid4()), ts,
                    random.choice(USERS), group,
                    random.choice(AD_ACTIONS),
                    random.choice(USERS),
                    _get_random_ip(random.choice(COUNTRIES)),
                    str(uuid.uuid4()) if random.random() < 0.5 else ""
                )
            )

    # privilege escalation anomaly
    for user in anomaly_users:
        if random.random() < 0.5:
            hr = hr_map[user]
            ts = _random_timestamp(hr.join_date, hr.termination_date or END_DATE)
            group = random.choice(AD_GROUPS)

            all_events.append(
                AdGroupEvent(
                    str(uuid.uuid4()), ts, user, group,
                    "privilege_escalation", user,
                    _get_random_ip(random.choice(COUNTRIES)),
                    str(uuid.uuid4())
                )
            )

            anomalies.setdefault(user, []).append(
                ANOMALY_LABELS['Q3'].format(
                    user=user, initiator=user, group=group
                )
            )

    all_events.sort(key=lambda x: x.ts)
    return all_events, anomalies
# ===========================
# FILE PART 3 / 4
# ===========================

# ========================================================
# APP USAGE GENERATOR (LIFECYCLE AWARE + BEHAVIORAL DRIFT)
# ========================================================
def generate_usage_data(okta_logins, saviynt_requests, anomaly_users, hr_map):
    all_usage = []
    anomalies = {}
    injected = set()

    successful = [l for l in okta_logins if l.status == "SUCCESS"]
    approved = [r for r in saviynt_requests if r.status == "APPROVED"]

    # --------------------------------------------
    # NORMAL APP USAGE (ALIGNED WITH SESSIONS)
    # --------------------------------------------
    for login in successful:
        hr = hr_map[login.user]
        session_start = login.ts
        session_end = login.ts + timedelta(hours=SESSION_DURATION_HRS)

        # clamp to termination date
        cutoff = hr.termination_date or END_DATE
        if session_start > cutoff:
            continue

        for _ in range(random.randint(1, 5)):
            ts = session_start + timedelta(seconds=random.randint(60, 7200))

            if ts < hr.join_date:
                continue
            if hr.termination_date and ts > hr.termination_date:
                continue

            # mover behavior: shift apps
            if hr.move_date1 and ts > hr.move_date1:
                app = random.choice(["Snowflake", "Databricks", "SAP"])
            else:
                app = random.choice(SAVIYNT_APPS)

            all_usage.append(
                AppUsage(
                    str(uuid.uuid4()), ts, login.user, app,
                    random.choice(ACTIONS),
                    random.randint(30, 3600),
                    round(random.uniform(10, 500), 2),
                    login.session_id, ""
                )
            )

    # --------------------------------------------
    # REQUEST-LINKED USAGE (Post-Approval Activity)
    # --------------------------------------------
    for req in approved:
        hr = hr_map[req.user]

        if random.random() < 0.7:
            for _ in range(random.randint(1, 3)):
                ts = req.ts + timedelta(seconds=random.randint(60, 172800))

                if ts < hr.join_date:
                    continue
                if hr.termination_date and ts > hr.termination_date:
                    continue

                if hr.move_date1 and ts > hr.move_date1:
                    action = random.choice(["modify", "upload"])
                else:
                    action = random.choice(["view", "modify"])

                # sometimes linked to session
                if random.random() < 0.5 and successful:
                    session_id = random.choice(successful).session_id
                else:
                    session_id = ""

                all_usage.append(
                    AppUsage(
                        str(uuid.uuid4()), ts, req.user, req.app,
                        action,
                        random.randint(60, 1800),
                        round(random.uniform(5, 150), 2),
                        session_id, req.req_id
                    )
                )

    # ------------------------------------------------
    # Q5 — LONG SESSION ANOMALY
    # ------------------------------------------------
    long_session_users = {u for u in anomaly_users if random.random() < 0.5}

    for login in successful:
        user = login.user
        hr = hr_map[user]

        if user not in long_session_users:
            continue
        if (user, "Q5") in injected:
            continue

        ts = login.ts + timedelta(hours=random.uniform(SESSION_DURATION_HRS + 0.1, SESSION_DURATION_HRS + 5))

        if hr.termination_date and ts > hr.termination_date:
            continue
        if ts < hr.join_date:
            continue

        session_duration = round((ts - login.ts).total_seconds() / 3600, 2)

        all_usage.append(
            AppUsage(
                str(uuid.uuid4()), ts, user,
                random.choice(SAVIYNT_APPS), "view",
                random.randint(100, 500),
                round(random.uniform(1, 10), 2),
                login.session_id, ""
            )
        )

        anomalies.setdefault(user, []).append(
            ANOMALY_LABELS["Q5"].format(
                session_duration=session_duration,
                limit=SESSION_DURATION_HRS
            )
        )
        injected.add((user, "Q5"))

    # ------------------------------------------------
    # Q6 — AD EVENT OCCURS AFTER SESSION END
    # (anomaly message only; actual AD event added later)
    # ------------------------------------------------
    q6_users = {u for u in anomaly_users if random.random() < 0.5}

    for login in successful:
        user = login.user
        hr = hr_map[user]

        if user not in q6_users:
            continue
        if (user, "Q6") in injected:
            continue

        expiry = login.ts + timedelta(hours=SESSION_DURATION_HRS)
        ad_ts = expiry + timedelta(hours=random.uniform(1, 5))

        if hr.termination_date and ad_ts > hr.termination_date:
            continue

        hours_over = round((ad_ts - expiry).total_seconds() / 3600, 2)
        event_id = str(uuid.uuid4())

        anomalies.setdefault(user, []).append(
            ANOMALY_LABELS["Q6"].format(
                event_id=event_id, time_diff=hours_over
            )
        )

        injected.add((user, "Q6"))

    # final ordering
    all_usage.sort(key=lambda x: x.ts)
    return all_usage, anomalies


# ========================================================
# CSV WRITER
# ========================================================
def write_to_csv(data, filename, header):
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False, header=header)
    print(f"✓ Generated {len(df)} rows → {filename}")
# ===========================
# FILE PART 4 / 4
# ===========================

# ========================================================
# FINAL Q6 ANOMALY INJECTION INTO AD EVENTS
# ========================================================
def inject_q6_ad_events(ad_group_events, okta_logins, anomalies, hr_map):
    q6_users = {user for user, msgs in anomalies.items() for m in msgs if "Q6" in m}

    injected_count = 0

    for user in q6_users:
        hr = hr_map[user]

        # Find latest successful session
        user_logins = [l for l in okta_logins if l.user == user and l.status == "SUCCESS"]
        if not user_logins:
            continue

        latest = max(user_logins, key=lambda x: x.ts)
        expiry = latest.ts + timedelta(hours=SESSION_DURATION_HRS)

        ts = expiry + timedelta(hours=random.uniform(1, 5))

        if hr.termination_date and ts > hr.termination_date:
            continue

        ev = AdGroupEvent(
            event_id=str(uuid.uuid4()),
            ts=ts,
            user=user,
            group=random.choice(AD_GROUPS),
            action="add_member",
            initiator=random.choice(USERS),
            ip=_get_random_ip(random.choice(COUNTRIES)),
            request_id=""
        )

        ad_group_events.append(ev)
        injected_count += 1

    ad_group_events.sort(key=lambda x: x.ts)
    print(f"✓ Injected {injected_count} Q6 AD expiry events")
    return ad_group_events


# ========================================================
# MERGE ANOMALIES FROM ALL SOURCES
# ========================================================
def merge_anomaly_dicts(*dicts):
    merged = {}
    for d in dicts:
        for user, msgs in d.items():
            merged.setdefault(user, []).extend(msgs)
    return merged


# ========================================================
# MAIN SYNTHETIC DATA GENERATOR
# ========================================================
def generate_synthetic_data():

    # STEP 1 — HR Lifecycle
    hr_events = generate_hr_events()
    hr_map = {hr.user: hr for hr in hr_events}
    print("✓ HR lifecycle generated")

    # STEP 2 — Pick anomaly users
    num_anomaly_users = math.ceil(NUM_USERS * ANOMALY_RATE)
    anomaly_users = set(random.sample(USERS, num_anomaly_users))
    print(f"✓ Targeting {num_anomaly_users} anomalies → {anomaly_users}")

    # STEP 3 — Okta
    okta_logins, okta_anoms = generate_okta_logins(anomaly_users, hr_map)
    print("✓ Okta logins generated")

    # STEP 4 — Saviynt
    saviynt_requests, saviynt_anoms = generate_saviynt_requests(
        okta_logins, anomaly_users, hr_map)
    print("✓ Saviynt requests generated")

    # STEP 5 — AD events
    ad_group_events, ad_anoms = generate_ad_group_events(
        anomaly_users, hr_map)
    print("✓ AD group events generated")

    # STEP 6 — App usage
    app_usage, usage_anoms = generate_usage_data(
        okta_logins, saviynt_requests, anomaly_users, hr_map)
    print("✓ App usage generated")

    # STEP 7 — Merge anomalies
    merged_anoms = merge_anomaly_dicts(
        okta_anoms, saviynt_anoms, ad_anoms, usage_anoms
    )
    print(f"✓ Merged anomalies for {len(merged_anoms)} users")

    # STEP 8 — Final Q6 AD event injection
    ad_group_events = inject_q6_ad_events(
        ad_group_events, okta_logins, merged_anoms, hr_map)

    # STEP 9 — Export CSV files
    write_to_csv(hr_events, "hr_events.csv", HrEvent._fields)
    write_to_csv(okta_logins, "okta_logins.csv", OktaRequest._fields)
    write_to_csv(saviynt_requests, "saviynt_requests.csv", SaviyntRequest._fields)
    write_to_csv(ad_group_events, "ad_group_events.csv", AdGroupEvent._fields)
    write_to_csv(app_usage, "app_usage.csv", AppUsage._fields)

    print("\n🎉 ALL DATASETS GENERATED SUCCESSFULLY")


# ========================================================
# ENTRY POINT
# ========================================================
if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)
    generate_synthetic_data()
