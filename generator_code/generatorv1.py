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

# Type Definitions
OktaRequest = namedtuple('OktaRequest', ['req_id', 'user', 'ts', 'device', 'ip', 'country', 'mfa', 'status', 'session_id'])
SaviyntRequest = namedtuple('SaviyntRequest', ['req_id', 'user', 'ts', 'app', 'role', 'status', 'approver', 'group'])
AdGroupEvent = namedtuple('AdGroupEvent', ['event_id', 'ts', 'user', 'group', 'action', 'initiator', 'ip', 'request_id'])
AppUsage = namedtuple('AppUsage', ['usage_id', 'ts', 'user', 'app', 'action', 'duration', 'data_mb', 'session_id', 'request_id'])

ANOMALY_LABELS = {
    'Q1': 'Q1: IMPOSSIBLE TRAVEL: Login from {country1} followed by {country2} in {time_diff} minutes',
    'Q2': 'Q2: ORPHAN REQUEST: Access Request {req_id} approved, but no subsequent App Usage event found',
    'Q3': 'Q3: PRIVILEGE ESCALATION: User {initiator} attempts to escalate privileges for {user} in group {group}',
    'Q4': 'Q4: LOGIN FROM NEW REGION VIA KNOWN CORPORATE VPN GATEWAY (False Positive)',
    'Q5': 'Q5: LONG SESSION: Session lasted {session_duration} hours, exceeding {limit} hour limit',
    'Q6': 'Q6: AD GROUP EVENT AFTER SESSION EXPIRY: Event {event_id} occurred {time_diff} after session ended',
}

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

# ---------------------------- Helper Functions ----------------------------

def _get_random_ip(country: str) -> str:
    if country in ['USA', 'UK']:
        return f'{random.randint(10, 199)}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(10, 250)}'
    elif country in ['Japan', 'Singapore']:
        return f'{random.randint(200, 220)}.{random.randint(10, 250)}.{random.randint(10, 250)}.{random.randint(10, 250)}'
    else:
        return f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}'

def _random_timestamp(start_date: datetime, end_date: datetime) -> datetime:
    delta = end_date - start_date
    return start_date + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

def _inject_impossible_travel_anomaly(user: str, logins: List[OktaRequest]):
    ts1 = _random_timestamp(START_DATE, END_DATE - timedelta(minutes=10))
    ts2 = ts1 + timedelta(minutes=random.randint(1, 5))
    country1 = random.choice(['USA', 'UK'])
    country2 = random.choice(['Japan', 'Singapore'])

    logins.append(OktaRequest(str(uuid.uuid4()), user, ts1, random.choice(DEVICES),
                              _get_random_ip(country1), country1, random.choice(MFA_TYPES), 'SUCCESS', str(uuid.uuid4())))
    logins.append(OktaRequest(str(uuid.uuid4()), user, ts2, random.choice(DEVICES),
                              _get_random_ip(country2), country2, random.choice(MFA_TYPES), 'SUCCESS', str(uuid.uuid4())))

    return ANOMALY_LABELS['Q1'].format(country1=country1, country2=country2, time_diff=int((ts2-ts1).total_seconds()/60))

def _inject_false_positive_anomaly(user: str, logins: List[OktaRequest]):
    ts1 = _random_timestamp(START_DATE, END_DATE - timedelta(hours=1))
    ts2 = ts1 + timedelta(days=random.randint(2, 7))

    logins.append(OktaRequest(str(uuid.uuid4()), user, ts1, random.choice(DEVICES),
                              '192.168.1.5', 'USA', random.choice(MFA_TYPES), 'SUCCESS', str(uuid.uuid4())))
    logins.append(OktaRequest(str(uuid.uuid4()), user, ts2, random.choice(DEVICES),
                              '192.168.1.5', 'India', random.choice(MFA_TYPES), 'SUCCESS', str(uuid.uuid4())))

    return ANOMALY_LABELS['Q4']

# ---------------------------- Generator Functions ----------------------------

def generate_okta_logins(anomaly_users: Set[str]):
    all_logins = []
    anomalies = {}

    for user in USERS:
        for _ in range(random.randint(15, 60)):
            ts = _random_timestamp(START_DATE, END_DATE)
            country = random.choice(COUNTRIES)
            status = 'SUCCESS' if random.random() < 0.9 else 'FAILED'
            session_id = str(uuid.uuid4()) if status == 'SUCCESS' else ''

            all_logins.append(
                OktaRequest(str(uuid.uuid4()), user, ts, random.choice(DEVICES),
                            _get_random_ip(country), country, random.choice(MFA_TYPES),
                            status, session_id)
            )

    for user in anomaly_users:
        if random.random() < 0.5:
            anomalies.setdefault(user, []).append(_inject_impossible_travel_anomaly(user, all_logins))
        if random.random() < 0.5:
            anomalies.setdefault(user, []).append(_inject_false_positive_anomaly(user, all_logins))

    all_logins.sort(key=lambda x: x.ts)
    return all_logins, anomalies

def generate_saviynt_requests(okta_logins, anomaly_users):
    all_requests = []
    anomalies = {}

    for user in USERS:
        for _ in range(random.randint(3, 10)):
            all_requests.append(
                SaviyntRequest(str(uuid.uuid4()), user, _random_timestamp(START_DATE, END_DATE),
                               random.choice(SAVIYNT_APPS), random.choice(SAVIYNT_ROLES),
                               random.choice(['APPROVED', 'REJECTED', 'PENDING']),
                               random.choice(USERS), random.choice(JUSTIFICATIONS))
            )

    for user in anomaly_users:
        if random.random() < 0.5:
            req_id = str(uuid.uuid4())
            ts = _random_timestamp(START_DATE, END_DATE)
            all_requests.append(
                SaviyntRequest(req_id, user, ts, random.choice(SAVIYNT_APPS),
                               'Developer', 'APPROVED', random.choice(USERS), 'Emergency')
            )
            anomalies.setdefault(user, []).append(ANOMALY_LABELS['Q2'].format(req_id=req_id))

    all_requests.sort(key=lambda x: x.ts)
    return all_requests, anomalies

def generate_ad_group_events(anomaly_users):
    all_events = []
    anomalies = {}

    for user in USERS:
        for _ in range(random.randint(1, 5)):
            all_events.append(
                AdGroupEvent(str(uuid.uuid4()), _random_timestamp(START_DATE, END_DATE),
                             random.choice(USERS), random.choice(AD_GROUPS),
                             random.choice(AD_ACTIONS), random.choice(USERS),
                             _get_random_ip(random.choice(COUNTRIES)),
                             str(uuid.uuid4()) if random.random() < 0.5 else '')
            )

    for user in anomaly_users:
        if random.random() < 0.5:
            gid = random.choice(AD_GROUPS)
            all_events.append(
                AdGroupEvent(str(uuid.uuid4()), _random_timestamp(START_DATE, END_DATE),
                             user, gid, 'privilege_escalation', user,
                             _get_random_ip(random.choice(COUNTRIES)), str(uuid.uuid4()))
            )
            anomalies.setdefault(user, []).append(
                ANOMALY_LABELS['Q3'].format(user=user, initiator=user, group=gid))

    all_events.sort(key=lambda x: x.ts)
    return all_events, anomalies

def generate_usage_data(okta_logins, saviynt_requests, anomaly_users):
    all_usage = []
    anomalies = {}
    injected = set()

    successful = [l for l in okta_logins if l.status == 'SUCCESS']
    approved = [r for r in saviynt_requests if r.status == 'APPROVED']

    # Normal session usage
    for login in successful:
        for _ in range(random.randint(1, 5)):
            ts = login.ts + timedelta(seconds=random.randint(60, 7200))
            if (ts - login.ts).total_seconds() / 3600 > SESSION_DURATION_HRS:
                continue
            all_usage.append(
                AppUsage(str(uuid.uuid4()), ts, login.user, random.choice(SAVIYNT_APPS),
                         random.choice(ACTIONS), random.randint(30, 3600),
                         round(random.uniform(10, 500), 2), login.session_id, '')
            )

    # Request-based usage
    for req in approved:
        if random.random() < 0.7:
            for _ in range(random.randint(1, 3)):
                ts = req.ts + timedelta(seconds=random.randint(60, 172800))
                session_id = random.choice(successful).session_id if random.random() < 0.5 else ''
                all_usage.append(
                    AppUsage(str(uuid.uuid4()), ts, req.user, req.app,
                             random.choice(['view', 'modify']),
                             random.randint(60, 1800), round(random.uniform(5, 150), 2),
                             session_id, req.req_id)
                )

    # Q5/Q6 anomalies — (left unchanged)

    all_usage.sort(key=lambda x: x.ts)
    return all_usage, anomalies

# ---------------------------- Quality Report ----------------------------

def print_data_quality_report(df1, df2, df3, df4, merged):
    pass  # Your full function unchanged (too long to paste here)

# ---------------------------- CSV Writer ----------------------------

def write_to_csv(data, filename, header):
    df = pd.DataFrame(data)
    df.to_csv(filename, index=False, header=header)
    print(f"Generated {len(data)} rows -> {filename}")

# ---------------------------- MAIN FIXED FUNCTION ----------------------------

def generate_synthetic_data():
    num_anomaly_users = math.ceil(NUM_USERS * ANOMALY_RATE)
    anomaly_users = set(random.sample(USERS, num_anomaly_users))

    print(f"--- Starting Data Generation ---")
    print(f"Targeting {num_anomaly_users} users ({anomaly_users})")

    okta_logins, okta_anomalies = generate_okta_logins(anomaly_users)

    # FIXED
    saviynt_requests, saviynt_anomalies = generate_saviynt_requests(okta_logins, anomaly_users)

    # FIXED
    ad_group_events, ad_anomalies = generate_ad_group_events(anomaly_users)

    # FIXED
    app_usage, usage_anomalies = generate_usage_data(okta_logins, saviynt_requests, anomaly_users)

    merged = {}
    for d in [okta_anomalies, saviynt_anomalies, ad_anomalies, usage_anomalies]:
        for k, v in d.items():
            merged.setdefault(k, []).extend(v)

    write_to_csv(okta_logins, "okta_logins.csv", OktaRequest._fields)
    write_to_csv(saviynt_requests, "saviynt_requests.csv", SaviyntRequest._fields)
    write_to_csv(ad_group_events, "ad_group_events.csv", AdGroupEvent._fields)
    write_to_csv(app_usage, "app_usage.csv", AppUsage._fields)

# ---------------------------- Run ----------------------------

if __name__ == "__main__":
    random.seed(42)
    np.random.seed(42)
    generate_synthetic_data()
