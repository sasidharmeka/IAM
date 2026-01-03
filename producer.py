import os
import csv
import json
import time
from google.cloud import pubsub_v1

# This producer reads multiple CSVs under `data/` and publishes each row to a specific
# Pub/Sub topic based on the CSV/source. Configure topics via env vars (optional).
PROJECT_ID = os.getenv("PROJECT_ID")
# Optional override topic names for each source
TOPIC_OKTA = os.getenv("TOPIC_OKTA", "okta-topic")
TOPIC_AD = os.getenv("TOPIC_AD", "ad-topic")
TOPIC_APP = os.getenv("TOPIC_APP", "app-topic")
TOPIC_SAV = os.getenv("TOPIC_SAV", "saviynt-topic")
TOPIC_HR = os.getenv("TOPIC_HR", "hrlifecycle-topic")

DATA_DIR = os.getenv("DATA_DIR", "data")

# Map CSV filename -> (source_key, topic_id)
CSV_MAP = {
    "okta_logins.csv": ("okta", TOPIC_OKTA),
    "ad_group_events.csv": ("ad", TOPIC_AD),
    "app_usage.csv": ("app_usage", TOPIC_APP),
    "saviynt_requests.csv": ("saviynt", TOPIC_SAV),
    "hr_lifecycle.csv": ("hrlifecycle", TOPIC_HR),
}


def publish_file(publisher, project_id: str, csv_path: str, source: str, topic_id: str):
    topic_path = f"projects/{project_id}/topics/{topic_id}"
    print(f"Publishing rows from {csv_path} to topic {topic_path} (source={source})")
    count = 0
    with open(csv_path, newline='', encoding='utf-8', errors='replace') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            payload = json.dumps(row, default=str).encode("utf-8")
            # publish with source attribute so consumers can route
            future = publisher.publish(topic_path, data=payload, source=source)
            _ = future.result()
            count += 1
            if count % 100 == 0:
                print(f"  published {count} rows...")
            time.sleep(0.01)
    print(f"  done: published {count} messages for {source}")


def main():
    if not PROJECT_ID:
        raise EnvironmentError("PROJECT_ID environment variable is required")

    publisher = pubsub_v1.PublisherClient()

    # Iterate configured CSV files
    total = 0
    for fname, (source, topic) in CSV_MAP.items():
        path = os.path.join(DATA_DIR, fname)
        if not os.path.isfile(path):
            print(f"Skipping missing file: {path}")
            continue
        publish_file(publisher, PROJECT_ID, path, source, topic)
        total += 1

    print(f"Published rows from {total} CSV sources.")
    #


if __name__ == "__main__":
    main()
