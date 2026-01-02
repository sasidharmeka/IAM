import pandas as pd
import os

INPUT_FILE_NAME = r"C:\Users\sasi0\OneDrive\Desktop\IAM PySpark\data\ad_group_events.csv"

# Mapping rules for realistic IAM automation
ACTION_TO_SERVICE = {
    "privilege_escalation": "iam_service",
    "add_member": "svc_saviynt",
    "remove_member": "svc_saviynt"
}

GROUP_TO_SERVICE = {
    "HR": "workday_service",
    "Workday": "workday_service",
    "Finance": "finance_bot",
    "DBA": "dba_automation",
    "DevOps": "devops_automation"
}

DEFAULT_SERVICE = "automation_engine"


def assign_correct_service_account(row):
    initiator = row["initiator"]

    # If it's already a service account → leave it unchanged
    if not initiator.startswith("user"):
        return initiator

    # Rule 1 — Action-based routing
    if row["action"] in ACTION_TO_SERVICE:
        return ACTION_TO_SERVICE[row["action"]]

    # Rule 2 — Group-based routing
    if row["group"] in GROUP_TO_SERVICE:
        return GROUP_TO_SERVICE[row["group"]]

    # Rule 3 — fallback
    return DEFAULT_SERVICE


def replace_initiators(file_path):
    if not os.path.exists(file_path):
        print("ERROR: File not found.")
        return

    df = pd.read_csv(file_path)

    print("Original count of human initiators:", df["initiator"].str.startswith("user").sum())

    df["initiator"] = df.apply(assign_correct_service_account, axis=1)

    # Save results back
    df.to_csv(file_path, index=False)

    print("\nUpdated! New distribution of initiators:")
    print(df["initiator"].value_counts().head(10))

    print("\nSample updated rows:")
    print(df.head())


if __name__ == "__main__":
    replace_initiators(INPUT_FILE_NAME)
