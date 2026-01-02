"""
Identity & Access Management Synthetic Data Generator - PART 1 of 2
Generates realistic IAM event data with embedded security anomalies.

USAGE: Copy this entire file, then immediately request Part 2 and append it.
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


# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Central configuration for data generation"""
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

class Ref:
    """Reference data constants"""
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


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_random_ip(country: str) -> str:
    """Generate pseudo-realistic IP by country"""
    if country in ['USA', 'UK']:
        return f"{random.randint(10,199)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
    elif country in ['Japan', 'Singapore']:
        return f"{random.randint(200,220)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
    else:
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"


def random_timestamp(start: datetime, end: datetime) -> datetime:
    """Generate random timestamp between start and end"""
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
    """Generates realistic employee lifecycle events"""
    
    def __init__(self, config: Config):
        self.config = config
        self.users = [f'user{i+1}' for i in range(config.num_users)]
    
    def generate(self) -> Dict[str, HrEvent]:
        """Generate HR events for all users"""
        hr_events = []
        
        for user in self.users:
            join_date = self.config.start_date + timedelta(days=random.randint(0, 5))
            
            # Movers
            move_date1 = None
            if random.random() < self.config.mover_rate:
                move_date1 = join_date + timedelta(days=random.randint(10, 25))
            
            move_date2 = None
            if move_date1 and random.random() < self.config.second_move_rate:
                move_date2 = move_date1 + timedelta(days=random.randint(10, 25))
            
            # Leavers
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
                department=random.choice(Ref.DEPARTMENTS),
                job_role=random.choice(Ref.ROLES),
                location=random.choice(Ref.LOCATIONS)
            ))
        
        return {hr.user: hr for hr in hr_events}, hr_events


# ============================================================================
# OKTA LOGIN GENERATOR
# ============================================================================

class OktaLoginGenerator:
    """Generates Okta authentication logs"""
    
    def __init__(self, config: Config, hr_map: Dict[str, HrEvent]):
        self.config = config
        self.hr_map = hr_map
        self.users = list(hr_map.keys())
    
    def generate(self, anomaly_users: Set[str]) -> Tuple[List[OktaLogin], Dict[str, List[str]]]:
        """Generate login events with anomalies"""
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
                country = random.choice(Ref.COUNTRIES)
                status = 'SUCCESS' if random.random() < self.config.login_success_rate else 'FAILED'
                session_id = str(uuid.uuid4()) if status == 'SUCCESS' else ''
                
                all_logins.append(OktaLogin(
                    req_id=str(uuid.uuid4()),
                    user=user,
                    ts=ts,
                    device=random.choice(Ref.DEVICES),
                    ip=get_random_ip(country),
                    country=country,
                    mfa=random.choice(Ref.MFA_TYPES),
                    status=status,
                    session_id=session_id
                ))
        
        # Inject anomalies
        for user in anomaly_users:
            if random.random() < self.config.impossible_travel_rate:
                anomalies[user].append(self._inject_impossible_travel(user, all_logins))
            
            if random.random() < self.config.vpn_mismatch_rate:
                anomalies[user].append(self._inject_vpn_mismatch(user, all_logins))
        
        all_logins.sort(key=lambda x: x.ts)
        return all_logins, dict(anomalies)
    
    def _inject_impossible_travel(self, user: str, logins: List[OktaLogin]) -> str:
        """Inject impossible travel anomaly"""
        ts1 = random_timestamp(self.config.start_date, self.config.end_date - timedelta(minutes=20))
        ts2 = ts1 + timedelta(minutes=random.randint(1, 5))
        
        c1 = random.choice(['USA', 'UK'])
        c2 = random.choice(['Japan', 'Singapore'])
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts1, random.choice(Ref.DEVICES),
            get_random_ip(c1), c1, random.choice(Ref.MFA_TYPES),
            'SUCCESS', str(uuid.uuid4())
        ))
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts2, random.choice(Ref.DEVICES),
            get_random_ip(c2), c2, random.choice(Ref.MFA_TYPES),
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
            str(uuid.uuid4()), user, ts1, random.choice(Ref.DEVICES),
            vpn_ip, 'USA', random.choice(Ref.MFA_TYPES), 'SUCCESS', str(uuid.uuid4())
        ))
        
        logins.append(OktaLogin(
            str(uuid.uuid4()), user, ts2, random.choice(Ref.DEVICES),
            vpn_ip, 'India', random.choice(Ref.MFA_TYPES), 'SUCCESS', str(uuid.uuid4())
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
    
    def generate(self, anomaly_users: Set[str]) -> Tuple[List[SaviyntRequest], Dict[str, List[str]]]:
        """Generate access requests with anomalies"""
        all_requests = []
        anomalies = defaultdict(list)
        
        # Normal requests
        for user in self.users:
            hr = self.hr_map[user]
            start = hr.join_date
            end = hr.termination_date or self.config.end_date
            
            num_requests = random.randint(self.config.min_requests, self.config.max_requests)
            
            for _ in range(num_requests):
                ts = random_timestamp(start, end)
                
                # Movers get elevated roles
                if hr.move_date1 and ts > hr.move_date1:
                    role = random.choice(['Developer', 'Admin'])
                else:
                    role = random.choice(['Reader', 'Editor'])
                
                all_requests.append(SaviyntRequest(
                    req_id=str(uuid.uuid4()),
                    user=user,
                    ts=ts,
                    app=random.choice(Ref.APPS),
                    role=role,
                    status=random.choice(['APPROVED', 'REJECTED', 'PENDING']),
                    approver=random.choice(self.users),
                    justification=random.choice(Ref.JUSTIFICATIONS)
                ))
        
        # Inject orphan request anomalies
        for user in anomaly_users:
            if random.random() < self.config.orphan_request_rate:
                hr = self.hr_map[user]
                req_id = str(uuid.uuid4())
                ts = random_timestamp(hr.join_date, hr.termination_date or self.config.end_date)
                
                all_requests.append(SaviyntRequest(
                    req_id=req_id,
                    user=user,
                    ts=ts,
                    app=random.choice(Ref.APPS),
                    role='Developer',
                    status='APPROVED',
                    approver=random.choice(self.users),
                    justification='Emergency'
                ))
                
                anomalies[user].append(
                    ANOMALY_TEMPLATES[AnomalyType.ORPHAN_REQUEST].format(req_id=req_id)
                )
        
        all_requests.sort(key=lambda x: x.ts)
        return all_requests, dict(anomalies)


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function"""
    # Set random seeds for reproducibility
    random.seed(42)
    
    # Create configuration
    config = Config(
        num_users=50,
        anomaly_rate=0.03,
        session_duration_hrs=8
    )
    
    # Generate data
    generator = DataGenerator(config)
    data = generator.generate_all()
    
    # Print summary
    generator.print_summary(data)
    
    # Export to CSV
    generator.export_csv(data)


if __name__ == "__main__":
    main()