# consumer.py
import os
import json
import time
import tempfile
import logging
from datetime import datetime
from typing import List, Dict

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from google.cloud import pubsub_v1, storage

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)7s %(message)s"
)
log = logging.getLogger("consumer")

# ---------------- Env ----------------
PROJECT_ID = os.getenv("PROJECT_ID")
BUCKET_NAME = os.getenv("BUCKET_NAME")

PARQUET_ROW_GROUP = int(os.getenv("PARQUET_ROW_GROUP", "100000"))
MAX_MESSAGES = int(os.getenv("MAX_MESSAGES", "1000"))
PULL_TIMEOUT = float(os.getenv("PER_PULL_TIMEOUT", "10"))

# Per-source subscriptions
SOURCE_SUB_MAP = {
    "okta": os.getenv("SUB_OKTA"),
    "ad": os.getenv("SUB_AD"),
    "app_usage": os.getenv("SUB_APP"),
    "saviynt": os.getenv("SUB_SAV"),
    "hrlifecycle": os.getenv("SUB_HR"),
}

if not PROJECT_ID or not BUCKET_NAME:
    raise EnvironmentError("PROJECT_ID and BUCKET_NAME must be set")

# ---------------- Pub/Sub ----------------
def pull_messages(sub_path: str, max_messages: int) -> List[Dict]:
    subscriber = pubsub_v1.SubscriberClient()
    response = subscriber.pull(
        subscription=sub_path,
        max_messages=max_messages,
        timeout=PULL_TIMEOUT
    )

    rows = []
    ack_ids = []

    for rm in response.received_messages:
        ack_ids.append(rm.ack_id)
        payload = rm.message.data.decode("utf-8")

        try:
            obj = json.loads(payload)
        except Exception:
            obj = {"raw": payload}

        # Attach attributes
        for k, v in rm.message.attributes.items():
            obj[f"attr_{k}"] = v

        rows.append(obj)

    if ack_ids:
        subscriber.acknowledge(subscription=sub_path, ack_ids=ack_ids)

    return rows

# ---------------- Storage ----------------
def write_parquet_and_upload(rows: List[Dict], source: str):
    if not rows:
        log.info(f"No data for source={source}")
        return

    df = pd.DataFrame(rows)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".parquet") as tmp:
        table = pa.Table.from_pandas(df)
        pq.write_table(table, tmp.name, row_group_size=PARQUET_ROW_GROUP)

        gcs_path = f"source/{source}/{timestamp}.parquet"
        client = storage.Client()
        bucket = client.bucket(BUCKET_NAME)
        bucket.blob(gcs_path).upload_from_filename(tmp.name)

    log.info(f"Uploaded {len(df)} rows → gs://{BUCKET_NAME}/{gcs_path}")

# ---------------- Main ----------------
def main():
    processed_any = False

    for source, sub in SOURCE_SUB_MAP.items():
        if not sub:
            continue

        processed_any = True

        sub_path = (
            sub if sub.startswith("projects/")
            else f"projects/{PROJECT_ID}/subscriptions/{sub}"
        )

        log.info(f"Processing source={source}")
        rows = pull_messages(sub_path, MAX_MESSAGES)
        write_parquet_and_upload(rows, source)

    if not processed_any:
        raise RuntimeError(
            "No subscriptions configured. Set SUB_OKTA / SUB_AD / etc."
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.warning("Interrupted by user")
    except Exception as e:
        log.exception(f"Fatal error: {e}")
        raise
