"""
Identity & Access Management Synthetic Data Generator v2.0
Production-grade IAM event data with embedded security anomalies.

Complete standalone version - ready to run.
"""

import pandas as pd
import random
import uuid
import math
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from collections import namedtuple, defaultdict
from enum import Enum
from pathlib import Path


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Central configuration for data generation with validation"""
    num_users: int = 50
    start_date: datetime = datetime(2025, 10, 1)
    end_date: datetime = datetime(2025, 12, 1)
    session_duration_hrs: int = 8
    anomaly_rate: float = 0.03
    
    # HR lifecycle probabilities
    mover_rate: float = 0.4
    second_move_rate: float = 0.3
    termination_rate: float = 0.2
    
    # Anomaly injection rates
    impossible_travel_rate: float = 0.5
    vpn_mismatch_rate: float = 0.5
    orphan_request_rate: float = 0.5
    privilege_escalation_rate: float = 0.5
    long_session_rate: float = 0.5
    expired_session_rate: float = 0.5
    
    # Activity volumes
    min_logins: int = 15
    max_logins: int = 55
    min_requests: int = 3
    max_requests: int = 12
    min_ad_events: int = 2
    max_ad_events: int = 7
    min_usage_per_session: int = 1
    max_usage_per_session: int = 5
    
    login_success_rate: float = 0.9
    request_link_rate: float = 0.7
    
    # Guarantee at least one anomaly per anomaly user
    guarantee_anomaly: bool = True
    
    def __post_init__(self):
        """Validate configuration parameters"""
        assert 0 < self.anomaly_rate <= 1, f"anomaly_rate must be between 0 and 1, got {self.anomaly_rate}"
        assert self.start_date < self.end_date, "start_date must be before end_date"
        assert self.num_users > 0, "num_users must be positive"
        assert self.session_duration_hrs > 0, "session_duration_hrs must be positive"
        assert 0 <= self.login_success_rate <= 1, "login_success_rate must be between 0 and 1"
        assert self.min_logins <= self.max_logins, "min_logins must be <= max_logins"
        assert self.min_requests <= self.max_requests, "min_requests must be <= max_requests"
        
        # Ensure anomaly rate doesn't exceed user count
        num_anomaly_users = math.ceil(self.num_users * self.anomaly_rate)
        assert num_anomaly_users <= self.num_users, \
            f"Anomaly rate {self.anomaly_rate} produces {num_anomaly_users} anomaly users but only {self.num_users} total users"


# ============================================================================
# DATA MODELS
# ============================================================================

HrEvent = namedtuple("HrEvent", [
    "user", "join_date", "move_date1", "move_date2",
    "termination_date", "department", "job_role", "location"
])

OktaLogin = namedtuple('OktaLogin', [
    'req_id', 'user', 'ts', 'device', 'ip', 'country', 
    'mfa', 'status', 'session_id'
])

SaviyntRequest = namedtuple('SaviyntRequest', [
    'req_id', 'user', 'ts', 'app', 'role', 'status', 
    'approver', 'justification'
])

AdGroupEvent = namedtuple('AdGroupEvent', [
    'event_id', 'ts', 'user', 'group', 'action', 
    'initiator', 'ip', 'request_id'
])

AppUsage = namedtuple('AppUsage', [
    'usage_id', 'ts', 'user', 'app', 'action', 
    'duration', 'data_mb', 'session_id', 'request_id'
])


class AnomalyType(Enum):
    """Security anomaly categories"""
    IMPOSSIBLE_TRAVEL = "Q1"
    ORPHAN_REQUEST = "Q2"
    PRIVILEGE_ESCALATION = "Q3"
    VPN_GEO_MISMATCH = "Q4"
    LONG_SESSION = "Q5"
    EXPIRED_SESSION_EVENT = "Q6"


ANOMALY_TEMPLATES = {
    AnomalyType.IMPOSSIBLE_TRAVEL: "Q1: IMPOSSIBLE TRAVEL: {country1} → {country2} in {time_diff}min",
    AnomalyType.ORPHAN_REQUEST: "Q2: ORPHAN REQUEST: {req_id} approved but unused",
    AnomalyType.PRIVILEGE_ESCALATION: "Q3: PRIVILEGE ESCALATION: {initiator} escalated in {group}",
    AnomalyType.VPN_GEO_MISMATCH: "Q4: VPN GEO MISMATCH (False Positive)",
    AnomalyType.LONG_SESSION: "Q5: LONG SESSION: {session_duration}h > {limit}h",
    AnomalyType.EXPIRED_SESSION_EVENT: "Q6: AD EVENT AFTER EXPIRY: {event_id} +{time_diff}h late",
}


# ============================================================================
# REFERENCE DATA
# ============================================================================

class ReferenceData:
    """Reference data constants for realistic data generation"""
    DEPARTMENTS = ["Engineering", "Finance", "HR", "DevOps", "DataScience", "Support"]
    ROLES = ["Intern", "Associate", "Developer", "Analyst", "Senior", "Manager"]
    LOCATIONS = ["India", "USA", "UK", "Germany", "Singapore"]
    DEVICES = ['Mac', 'Windows', 'Linux', 'iPhone', 'Android']
    MFA_TYPES = ['TOTP', 'Push', 'SMS', 'Email']
    COUNTRIES = ['USA', 'UK', 'Germany', 'Japan', 'Singapore', 'India', 'Brazil', 'Australia']
    APPS = ['Snowflake', 'Databricks', 'GitHub', 'Jira', 'Salesforce', 'SAP', 'Workday']
    AD_GROUPS = ['DBA', 'DevOps', 'Finance', 'HR', 'Workday', 'Contractor']
    ACTIONS = ['view', 'modify', 'upload', 'download']
    ROLES_SAVIYNT = ['Reader', 'Editor', 'Developer', 'Admin']
    JUSTIFICATIONS = ['BAU', 'Project Work', 'Emergency']
    AD_ACTIONS = ['add_member', 'remove_member', 'privilege_escalation']
    
    # Distant country pairs for impossible travel (>8000km)
    DISTANT_PAIRS = [
        (['USA', 'UK'], ['Japan', 'Singapore', 'Australia']),
        (['Germany', 'UK'], ['Japan', 'Singapore', 'India', 'Australia']),
        (['Brazil'], ['Japan', 'Singapore', 'India', 'Australia'])
    ]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_random_ip(country: str) -> str:
    """Generate pseudo-realistic IP address by country"""
    if country in ['USA', 'UK']:
        return f"{random.randint(10,199)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
    elif country in ['Japan', 'Singapore']:
        return f"{random.randint(200,220)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
    else:
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"


def random_timestamp(start: datetime, end: datetime) -> datetime:
    """Generate random timestamp between start and end dates"""
    if start >= end:
        raise ValueError(f"start ({start}) must be before end ({end})")
    delta_seconds = int((end - start).total_seconds())
    return start + timedelta(seconds=random.randint(0, delta_seconds))


def is_within_lifecycle(ts: datetime, hr: HrEvent) -> bool:
    """Check if timestamp is within employee's active period"""
    if ts < hr.join_date:
        return False
    if hr.termination_date and ts > hr.termination_date:
        return False
    return True


# ============================================================================
# HR LIFECYCLE GENERATOR
# ============================================================================

class HRLifecycleGenerator:
    """Generates realistic employee lifecycle events (joiners/movers/leavers)"""
    
    def __init__(self, config: Config):
        self.config = config
        self.users = [f'user{i+1}' for i in range(config.num_users)]
    
    def generate(self) -> Tuple[Dict[str, HrEvent], List[HrEvent]]:
        """
        Generate HR events for all users.
        
        Returns:
            Tuple of (hr_map, hr_events_list)
        """
        hr_events = []
        
        for user in self.users:
            join_date = self.config.start_date + timedelta(days=random.randint(0, 5))
            
            move_date1 = None
            if random.random() < self.config.mover_rate:
                move_date1 = join_date + timedelta(days=random.randint(10, 25))
            
            move_date2 = None
            if move_date1 and random.random() < self.config.second_move_rate:
                move_date2 = move_date1 + timedelta(days=random.randint(10, 25))
            
            termination_date = None
            if random.random() < self.config.termination_rate:
                termination_date = join_date + timedelta(days=random.randint(30, 55))
                if termination_date > self.config.end_date:
                    termination_date = self.config.end_date - timedelta(days=1)
            
            hr_events.append(HrEvent(
                user=user,
                join_date=join_date,
                move_date1=move_date1,
                move_date2=move_date2,
                termination_date=termination_date,
                department=random.choice(ReferenceData.DEPARTMENTS),
                job_role=random.choice(ReferenceData.ROLES),
                location=random.choice(ReferenceData.LOCATIONS)
            ))
        
        return {hr.user: hr for hr in hr_events}, hr_events


# ============================================================================
# OKTA LOGIN GENERATOR
# ============================================================================

class OktaLoginGenerator:
    """Generates Okta authentication logs with lifecycle awareness"""
    
    def __init__(self, config: Config, hr_map: Dict[str, HrEvent]):
        self.config = config
        self.hr_map = hr_map
        self.users = list(hr_map.keys())
    
    def generate(self, anomaly_users: Set[str]) -> Tuple[List[OktaLogin], Dict[str, List[str]]]:
        """Generate login events with injected anomalies"""
        all_logins = []
        anomalies = defaultdict(list)
        
        # Normal logins
        for user in self.users:
            hr = self.hr_map[user]
            start = hr.join_date
            end = hr.termination_date or self.config.end_date
            
            num_logins = random.randint(self.config.min_logins, self.config.max_logins)
            
            for _ in range(num_logins):
                ts = random_timestamp(start, end)
                country = random.choice(ReferenceData.COUNTRIES)
                status = 'SUCCESS' if random.random() < self.config.login_success_rate else 'FAILED'
                session_id = str(uuid.uuid4()) if status == 'SUCCESS' else ''
                
                all_logins.append(OktaLogin(
                    req_id=str(uuid.uuid4()),
                    user=user,
                    ts=ts,
                    device=random.choice(ReferenceData.DEVICES),
                    ip=get_random_ip(country),
                    country=country,
                    mfa=random.choice(ReferenceData.MFA_TYPES),
                    status=status,
                    session_id=session_id
                ))
        
        # Inject anomalies
        for user in anomaly_users:
            injected = False
            
            if random.random() < self.config.impossible_travel_rate:
                anomalies[user].append(self._inject_impossible_travel(user, all_logins))
                injected = True
            
            if random.random() < self.config.vpn_mismatch_rate:
                anomalies[user].append(self._inject_vpn_mismatch(user, all_logins))
                injected = True
            
            if not injected and self.config.guarantee_anomaly:
                anomalies[user].append(self._inject_impossible_travel(user, all_logins))
        
        all_logins.sort(key=lambda x: x.ts)
        return all_logins, dict(anomalies)
    
    def _inject_impossible_travel(self, user: str, logins: List[OktaLogin]) -> str:
        """Inject impossible travel anomaly"""
        ts1 = random_timestamp(self.config.start_date, self.config.end_date - timedelta(minutes=20))
        ts2 = ts1 + timedelta(minutes=random.randint(1, 5))
        
        region1, region2 = random.choice(ReferenceData.DISTANT_PAIRS)
        c1 = random.choice(region1)
        c2 = random.choice(region2)
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts1, random.choice(ReferenceData.DEVICES),
            get_random_ip(c1), c1, random.choice(ReferenceData.MFA_TYPES),
            'SUCCESS', str(uuid.uuid4())
        ))
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts2, random.choice(ReferenceData.DEVICES),
            get_random_ip(c2), c2, random.choice(ReferenceData.MFA_TYPES),
            'SUCCESS', str(uuid.uuid4())
        ))
        
        time_diff = int((ts2 - ts1).total_seconds() / 60)
        return ANOMALY_TEMPLATES[AnomalyType.IMPOSSIBLE_TRAVEL].format(
            country1=c1, country2=c2, time_diff=time_diff
        )
    
    def _inject_vpn_mismatch(self, user: str, logins: List[OktaLogin]) -> str:
        """Inject VPN geo mismatch (false positive)"""
        ts1 = random_timestamp(self.config.start_date, self.config.end_date - timedelta(days=3))
        ts2 = ts1 + timedelta(days=random.randint(2, 5))
        
        vpn_ip = "192.168.1.5"
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts1, random.choice(ReferenceData.DEVICES),
            vpn_ip, 'USA', random.choice(ReferenceData.MFA_TYPES), 'SUCCESS', str(uuid.uuid4())
        ))
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts2, random.choice(ReferenceData.DEVICES),
            vpn_ip, 'India', random.choice(ReferenceData.MFA_TYPES), 'SUCCESS', str(uuid.uuid4())
        ))
        
        return ANOMALY_TEMPLATES[AnomalyType.VPN_GEO_MISMATCH]


# ============================================================================
# SAVIYNT REQUEST GENERATOR
# ============================================================================

class SaviyntRequestGenerator:
    """Generates access request events"""
    
    def __init__(self, config: Config, hr_map: Dict[str, HrEvent]):
        self.config = config
        self.hr_map = hr_map
        self.users = list(hr_map.keys())
    
    def generate(self, anomaly_users: Set[str]) -> Tuple[List[SaviyntRequest], Dict[str, List[str]], Set[str]]:
        """Generate access requests with orphan anomalies"""
        all_requests = []
        anomalies = defaultdict(list)
        orphan_request_ids = set()
        
        # Normal requests
        for user in self.users:
            hr = self.hr_map[user]
            start = hr.join_date
            end = hr.termination_date or self.config.end_date
            
            num_requests = random.randint(self.config.min_requests, self.config.max_requests)
            
            for _ in range(num_requests):
                ts = random_timestamp(start, end)
                
                if hr.move_date1 and ts > hr.move_date1:
                    role = random.choice(['Developer', 'Admin'])
                else:
                    role = random.choice(['Reader', 'Editor'])
                
                all_requests.append(SaviyntRequest(
                    req_id=str(uuid.uuid4()),
                    user=user,
                    ts=ts,
                    app=random.choice(ReferenceData.APPS),
                    role=role,
                    status=random.choice(['APPROVED', 'REJECTED', 'PENDING']),
                    approver=random.choice(self.users),
                    justification=random.choice(ReferenceData.JUSTIFICATIONS)
                ))
        
        # Inject orphan requests
        for user in anomaly_users:
            if random.random() < self.config.orphan_request_rate:
                hr = self.hr_map[user]
                req_id = str(uuid.uuid4())
                ts = random_timestamp(hr.join_date, hr.termination_date or self.config.end_date)
                
                all_requests.append(SaviyntRequest(
                    req_id=req_id,
                    user=user,
                    ts=ts,
                    app=random.choice(ReferenceData.APPS),
                    role='Developer',
                    status='APPROVED',
                    approver=random.choice(self.users),
                    justification='Emergency'
                ))
                
                orphan_request_ids.add(req_id)
                anomalies[user].append(
                    ANOMALY_TEMPLATES[AnomalyType.ORPHAN_REQUEST].format(req_id=req_id)
                )
        
        all_requests.sort(key=lambda x: x.ts)
        return all_requests, dict(anomalies), orphan_request_ids


# ============================================================================
# AD GROUP EVENT GENERATOR
# ============================================================================

class AdGroupEventGenerator:
    """Generates Active Directory group modification events"""
    
    def __init__(self, config: Config, hr_map: Dict[str, HrEvent]):
        self.config = config
        self.hr_map = hr_map
        self.users = list(hr_map.keys())
    
    def generate(
        self, 
        anomaly_users: Set[str],
        approved_requests: List[SaviyntRequest]
    ) -> Tuple[List[AdGroupEvent], Dict[str, List[str]]]:
        """Generate AD group events with privilege escalation anomalies"""
        all_events = []
        anomalies = defaultdict(list)
        used_request_ids = set()
        
        # Normal AD events
        for user in self.users:
            hr = self.hr_map[user]
            start = hr.join_date
            end = hr.termination_date or self.config.end_date
            
            num_events = random.randint(self.config.min_ad_events, self.config.max_ad_events)
            
            for _ in range(num_events):
                ts = random_timestamp(start, end)
                action = random.choice(ReferenceData.AD_ACTIONS)
                group = random.choice(ReferenceData.AD_GROUPS)
                
                request_id = ''
                if action == 'privilege_escalation' and random.random() < 0.7:
                    eligible = [
                        r for r in approved_requests 
                        if r.user == user and r.req_id not in used_request_ids and r.ts < ts
                    ]
                    if eligible:
                        req = random.choice(eligible)
                        request_id = req.req_id
                        used_request_ids.add(req.req_id)
                
                all_events.append(AdGroupEvent(
                    event_id=str(uuid.uuid4()),
                    ts=ts,
                    user=user,
                    group=group,
                    action=action,
                    initiator=random.choice(self.users),
                    ip=get_random_ip(random.choice(ReferenceData.COUNTRIES)),
                    request_id=request_id
                ))
        
        # Inject privilege escalation anomalies
        for user in anomaly_users:
            if random.random() < self.config.privilege_escalation_rate:
                hr = self.hr_map[user]
                ts = random_timestamp(hr.join_date, hr.termination_date or self.config.end_date)
                group = random.choice(ReferenceData.AD_GROUPS)
                
                all_events.append(AdGroupEvent(
                    event_id=str(uuid.uuid4()),
                    ts=ts,
                    user=user,
                    group=group,
                    action='privilege_escalation',
                    initiator=user,
                    ip=get_random_ip(random.choice(ReferenceData.COUNTRIES)),
                    request_id=''
                ))
                
                anomalies[user].append(
                    ANOMALY_TEMPLATES[AnomalyType.PRIVILEGE_ESCALATION].format(
                        initiator=user, group=group
                    )
                )
        
        all_events.sort(key=lambda x: x.ts)
        return all_events, dict(anomalies)


# ============================================================================
# APP USAGE GENERATOR
# ============================================================================

class AppUsageGenerator:
    """Generates application usage events with session linkage"""
    
    def __init__(self, config: Config, hr_map: Dict[str, HrEvent]):
        self.config = config
        self.hr_map = hr_map
        self.users = list(hr_map.keys())
    
    def generate(
        self,
        okta_logins: List[OktaLogin],
        approved_requests: List[SaviyntRequest],
        orphan_request_ids: Set[str],
        anomaly_users: Set[str]
    ) -> Tuple[List[AppUsage], Dict[str, List[str]], List[AdGroupEvent]]:
        """Generate app usage events with anomalies"""
        all_usage = []
        anomalies = defaultdict(list)
        late_ad_events = []
        
        injected_anomalies = set()
        
        successful_logins = [l for l in okta_logins if l.status == 'SUCCESS' and l.session_id]
        approved_dict = {r.req_id: r for r in approved_requests if r.req_id not in orphan_request_ids}
        
        # Generate usage for each session
        for login in successful_logins:
            user = login.user
            hr = self.hr_map[user]
            
            if not is_within_lifecycle(login.ts, hr):
                continue
            
            num_usage = random.randint(
                self.config.min_usage_per_session,
                self.config.max_usage_per_session
            )
            
            for i in range(num_usage):
                session_end = min(
                    login.ts + timedelta(hours=self.config.session_duration_hrs),
                    hr.termination_date or self.config.end_date
                )
                
                # Q5: Long Session Anomaly
                anomaly_key = (user, 'LONG_SESSION')
                if (user in anomaly_users and 
                    random.random() < self.config.long_session_rate and
                    anomaly_key not in injected_anomalies):
                    
                    extra_hours = random.uniform(0.5, 4)
                    ts = login.ts + timedelta(hours=self.config.session_duration_hrs + extra_hours)
                    
                    if hr.termination_date and ts > hr.termination_date:
                        ts = hr.termination_date - timedelta(hours=1)
                    
                    session_duration = round((ts - login.ts).total_seconds() / 3600, 2)
                    
                    anomalies[user].append(
                        ANOMALY_TEMPLATES[AnomalyType.LONG_SESSION].format(
                            session_duration=session_duration,
                            limit=self.config.session_duration_hrs
                        )
                    )
                    injected_anomalies.add(anomaly_key)
                else:
                    ts = random_timestamp(
                        login.ts + timedelta(seconds=60),
                        session_end
                    )
                
                # Link to request
                request_id = ''
                if random.random() < self.config.request_link_rate:
                    eligible = [
                        r for r in approved_dict.values()
                        if r.user == user and r.ts < ts
                    ]
                    if eligible:
                        request_id = random.choice(eligible).req_id
                
                all_usage.append(AppUsage(
                    usage_id=str(uuid.uuid4()),
                    ts=ts,
                    user=user,
                    app=random.choice(ReferenceData.APPS),
                    action=random.choice(ReferenceData.ACTIONS),
                    duration=random.randint(30, 3600),
                    data_mb=round(random.uniform(1.0, 500.0), 2),
                    session_id=login.session_id,
                    request_id=request_id
                ))
        
        # Q6: Inject AD events after session expiry
        for user in anomaly_users:
            anomaly_key = (user, 'EXPIRED_SESSION')
            if (random.random() < self.config.expired_session_rate and
                anomaly_key not in injected_anomalies):
                
                user_logins = [l for l in successful_logins if l.user == user]
                if not user_logins:
                    continue
                
                login = random.choice(user_logins)
                session_expiry = login.ts + timedelta(hours=self.config.session_duration_hrs)
                
                extra_hours = random.uniform(1, 5)
                ad_ts = session_expiry + timedelta(hours=extra_hours)
                
                hr = self.hr_map[user]
                if hr.termination_date and ad_ts > hr.termination_date:
                    ad_ts = hr.termination_date - timedelta(hours=0.5)
                
                event_id = str(uuid.uuid4())
                
                late_ad_events.append(AdGroupEvent(
                    event_id=event_id,
                    ts=ad_ts,
                    user=user,
                    group=random.choice(ReferenceData.AD_GROUPS),
                    action='add_member',
                    initiator=random.choice(self.users),
                    ip=get_random_ip(random.choice(ReferenceData.COUNTRIES)),
                    request_id=''
                ))
                
                anomalies[user].append(
                    ANOMALY_TEMPLATES[AnomalyType.EXPIRED_SESSION_EVENT].format(
                        event_id=event_id[:8],
                        time_diff=round(extra_hours, 1)
                    )
                )
                injected_anomalies.add(anomaly_key)
        
        all_usage.sort(key=lambda x: x.ts)
        return all_usage, dict(anomalies), late_ad_events


# ============================================================================
# DATA QUALITY VALIDATOR
# ============================================================================

class DataQualityValidator:
    """Validates generated data"""
    
    @staticmethod
    def validate(
        okta_logins: List[OktaLogin],
        saviynt_requests: List[SaviyntRequest],
        ad_events: List[AdGroupEvent],
        app_usage: List[AppUsage],
        hr_events: List[HrEvent],
        merged_anomalies: Dict[str, List[str]]
    ) -> None:
        """Comprehensive data quality validation"""
        print("\n" + "="*80)
        print(" " * 25 + "DATA QUALITY VALIDATION REPORT")
        print("="*80)
        
        # Convert to DataFrames
        df_okta = pd.DataFrame(okta_logins)
        df_saviynt = pd.DataFrame(saviynt_requests)
        df_ad = pd.DataFrame(ad_events)
        df_usage = pd.DataFrame(app_usage)
        df_hr = pd.DataFrame(hr_events)
        
        for df in [df_okta, df_saviynt, df_ad, df_usage]:
            if 'ts' in df.columns:
                df['ts'] = pd.to_datetime(df['ts'])
        
        print("\n--- Volume Metrics ---")
        print(f"Okta Logins:       {len(df_okta):,}")
        print(f"Saviynt Requests:  {len(df_saviynt):,}")
        print(f"AD Group Events:   {len(df_ad):,}")
        print(f"App Usage Events:  {len(df_usage):,}")
        print(f"HR Events:         {len(df_hr):,}")
        print(f"Unique Users:      {df_okta['user'].nunique()}")
        
        print("\n--- Anomaly Injection Report ---")
        total_anomalies = sum(len(v) for v in merged_anomalies.values())
        print(f"Total Anomalies:   {total_anomalies}")
        print(f"Affected Users:    {len(merged_anomalies)}")
        
        anomaly_counts = defaultdict(int)
        for msgs in merged_anomalies.values():
            for msg in msgs:
                anomaly_type = msg.split(':')[0]
                anomaly_counts[anomaly_type] += 1
        
        for atype, count in sorted(anomaly_counts.items()):
            print(f"  {atype}: {count}")
        
        print("\n--- Referential Integrity ---")
        
        # Q2: Orphan Request Check
        approved_ids = set(df_saviynt[df_saviynt['status'] == 'APPROVED']['req_id'])
        used_ids = set(df_usage[df_usage['request_id'] != '']['request_id'])
        orphan_count = len(approved_ids - used_ids)
        print(f"✓ Q2 Orphan Requests: {orphan_count} approved but unused")
        
        # Session Linkage
        valid_sessions = set(df_okta[df_okta['status'] == 'SUCCESS']['session_id'])
        usage_sessions = set(df_usage[df_usage['session_id'] != '']['session_id'])
        orphan_sessions = len(usage_sessions - valid_sessions)
        print(f"✓ Orphan Sessions: {orphan_sessions} usage events with invalid session_id")
        
        # Request Linkage in AD
        ad_with_req = df_ad[df_ad['request_id'] != '']
        print(f"✓ AD Linkage: {len(ad_with_req)} / {len(df_ad)} AD events linked to requests")
        
        print("\n--- Temporal Integrity ---")
        
        # Merge usage with logins for causality check
        df_okta_sessions = df_okta[['session_id', 'ts']].rename(columns={'ts': 'login_ts'})
        df_okta_sessions = df_okta_sessions[df_okta_sessions['session_id'] != '']
        
        merged = df_usage.merge(df_okta_sessions, on='session_id', how='left')
        
        # Usage must be after login
        valid_usage = merged[merged['login_ts'].notna()]
        causality_violations = (valid_usage['ts'] < valid_usage['login_ts']).sum()
        print(f"✓ Causality Check: {causality_violations} violations (usage before login)")
        
        # Long sessions
        valid_usage['session_hrs'] = (valid_usage['ts'] - valid_usage['login_ts']).dt.total_seconds() / 3600
        long_sessions = (valid_usage['session_hrs'] > 8).sum()
        print(f"✓ Q5 Long Sessions: {long_sessions} usage events > 8 hours after login")
        
        print("\n--- Lifecycle Compliance ---")
        
        # Check all events are within employee lifecycle
        hr_map = {row['user']: row for _, row in df_hr.iterrows()}
        
        def check_lifecycle(df, ts_col='ts'):
            violations = 0

            for _, row in df.iterrows():
                # Pull HR row safely
                hr = hr_map.get(row['user'], None)
                if hr is None:
                    continue

                # Convert event timestamp
                ts = pd.to_datetime(row[ts_col])

                # Convert HR timestamps
                join = pd.to_datetime(hr['join_date'])
                term = (
                    pd.to_datetime(hr['termination_date'])
                    if pd.notna(hr['termination_date'])
                    else None
                )

                # Check violations
                if ts < join:
                    violations += 1
                elif term and ts > term:
                    violations += 1

            return violations

        
        okta_violations = check_lifecycle(df_okta)
        usage_violations = check_lifecycle(df_usage)
        ad_violations = check_lifecycle(df_ad)
        
        print(f"✓ Okta events outside lifecycle: {okta_violations}")
        print(f"✓ Usage events outside lifecycle: {usage_violations}")
        print(f"✓ AD events outside lifecycle: {ad_violations}")
        
        print("\n--- Date Range ---")
        all_ts = pd.concat([
            df_okta['ts'], df_saviynt['ts'], df_ad['ts'], df_usage['ts']
        ])
        print(f"First Event: {all_ts.min()}")
        print(f"Last Event:  {all_ts.max()}")
        
        print("="*80 + "\n")


# ============================================================================
# CSV WRITER
# ============================================================================

def write_to_csv(data: List, filename: str, header: List[str]) -> None:
    """Write data to ./data folder with auto-folder creation and error handling"""
    try:
        df = pd.DataFrame(data)

        # Ensure data directory exists
        output_dir = Path("data")
        output_dir.mkdir(parents=True, exist_ok=True)

        # Build final file path
        output_path = output_dir / filename

        # Write file
        df.to_csv(output_path, index=False)

        print(f"✓ Wrote {len(data):,} records → {output_path}")
    
    except Exception as e:
        print(f"✗ ERROR writing {filename}: {e}")
        raise



# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main orchestration function"""
    
    # Set seeds for reproducibility
    random.seed(42)
    
    print("="*80)
    print(" " * 20 + "IAM SYNTHETIC DATA GENERATOR v2.0")
    print("="*80)
    
    # Initialize configuration
    config = Config()
    
    print(f"\nConfiguration:")
    print(f"  Users: {config.num_users}")
    print(f"  Date Range: {config.start_date.date()} to {config.end_date.date()}")
    print(f"  Anomaly Rate: {config.anomaly_rate:.1%}")
    print(f"  Session Duration: {config.session_duration_hrs}h")
    
    # Select anomaly users
    num_anomaly_users = math.ceil(config.num_users * config.anomaly_rate)
    all_users = [f'user{i+1}' for i in range(config.num_users)]
    anomaly_users = set(random.sample(all_users, num_anomaly_users))
    
    print(f"\n  Anomaly Users: {num_anomaly_users} ({', '.join(sorted(list(anomaly_users)[:5]))}...)")
    
    print("\n" + "-"*80)
    print("PHASE 1: HR Lifecycle Generation")
    print("-"*80)
    
    hr_gen = HRLifecycleGenerator(config)
    hr_map, hr_events = hr_gen.generate()
    print(f"✓ Generated {len(hr_events)} employee lifecycle records")
    
    print("\n" + "-"*80)
    print("PHASE 2: Okta Login Generation")
    print("-"*80)
    
    okta_gen = OktaLoginGenerator(config, hr_map)
    okta_logins, okta_anomalies = okta_gen.generate(anomaly_users)
    print(f"✓ Generated {len(okta_logins):,} login events")
    print(f"✓ Injected {sum(len(v) for v in okta_anomalies.values())} Okta anomalies")
    
    print("\n" + "-"*80)
    print("PHASE 3: Saviynt Request Generation")
    print("-"*80)
    
    saviynt_gen = SaviyntRequestGenerator(config, hr_map)
    saviynt_requests, saviynt_anomalies, orphan_request_ids = saviynt_gen.generate(anomaly_users)
    print(f"✓ Generated {len(saviynt_requests):,} access requests")
    print(f"✓ Injected {len(orphan_request_ids)} orphan requests")
    
    print("\n" + "-"*80)
    print("PHASE 4: AD Group Event Generation")
    print("-"*80)
    
    ad_gen = AdGroupEventGenerator(config, hr_map)
    ad_events, ad_anomalies = ad_gen.generate(anomaly_users, saviynt_requests)
    print(f"✓ Generated {len(ad_events):,} AD group events")
    print(f"✓ Injected {sum(len(v) for v in ad_anomalies.values())} AD anomalies")
    
    print("\n" + "-"*80)
    print("PHASE 5: App Usage Generation")
    print("-"*80)
    
    usage_gen = AppUsageGenerator(config, hr_map)
    app_usage, usage_anomalies, late_ad_events = usage_gen.generate(
        okta_logins, saviynt_requests, orphan_request_ids, anomaly_users
    )
    print(f"✓ Generated {len(app_usage):,} usage events")
    print(f"✓ Injected {sum(len(v) for v in usage_anomalies.values())} usage anomalies")
    print(f"✓ Injected {len(late_ad_events)} late AD events (Q6)")
    
    # Merge late AD events into main AD list
    all_ad_events = ad_events + late_ad_events
    all_ad_events.sort(key=lambda x: x.ts)
    
    # Merge anomaly dictionaries
    merged_anomalies = defaultdict(list)
    for d in [okta_anomalies, saviynt_anomalies, ad_anomalies, usage_anomalies]:
        for user, msgs in d.items():
            merged_anomalies[user].extend(msgs)
    
    print("\n" + "-"*80)
    print("PHASE 6: Data Quality Validation")
    print("-"*80)
    
    DataQualityValidator.validate(
        okta_logins, saviynt_requests, all_ad_events, app_usage, hr_events, dict(merged_anomalies)
    )
    
    print("\n" + "-"*80)
    print("PHASE 7: CSV Export")
    print("-"*80)
    
    write_to_csv(hr_events, 'hr_lifecycle.csv', HrEvent._fields)
    write_to_csv(okta_logins, 'okta_logins.csv', OktaLogin._fields)
    write_to_csv(saviynt_requests, 'saviynt_requests.csv', SaviyntRequest._fields)
    write_to_csv(all_ad_events, 'ad_group_events.csv', AdGroupEvent._fields)
    write_to_csv(app_usage, 'app_usage.csv', AppUsage._fields)
    
    # Write anomaly key
    anomaly_records = [
        {'user': user, 'anomaly_description': msg}
        for user, msgs in merged_anomalies.items()
        for msg in msgs
    ]
    write_to_csv(anomaly_records, 'anomaly_key.csv', ['user', 'anomaly_description'])
    
    print("\n" + "="*80)
    print(" " * 25 + "GENERATION COMPLETE")
    print("="*80)
    print("\nGenerated Files:")
    print("  - hr_lifecycle.csv")
    print("  - okta_logins.csv")
    print("  - saviynt_requests.csv")
    print("  - ad_group_events.csv")
    print("  - app_usage.csv")
    print("  - anomaly_key.csv")
    print("\nReady for PySpark analysis!")


if __name__ == '__main__':
    main()