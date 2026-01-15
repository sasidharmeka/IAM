"""
IAM Spark transformation job (clean contract).

Airflow → Spark contract:
REQUIRED:
- --env
- --gcs_bucket
- --bq_project
- --bq_dataset
- --source

OPTIONAL:
- --input_file
- --write_method (default=direct)
- --temp_gcs_bucket

Spark owns:
- table names
- detection logic
- schema decisions
"""

import argparse
import logging
import sys
from typing import Optional

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import col, to_timestamp, unix_timestamp, lit, when
from pyspark.sql.window import Window

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("IAM-transform")

# -------------------------------------------------------------------
# INTERNAL TABLE CONFIG (Spark-owned)
# -------------------------------------------------------------------
TABLES = {
    "impossible_table": "impossible_login_anomalies",
    "mfa_table": "mfa_bypass_events",
    "mfa_all_table": "mfa_bypass_events_all_apps",
    "impossible_travel_table": "impossible_travel_events",
    "privilege_escalation_table": "privilege_escalation_without_request",
    "ad_volume_spike_table": "ad_volume_spikes",
    "rejected_executed_table": "rejected_but_executed",
    "high_risk_seq_table": "high_risk_sequence",
    "excessive_data_table": "excessive_data_transferred",
    "role_drift_table": "role_drift",
    "stale_access_table": "stale_access",
    "multi_app_session_table": "multi_app_single_session",
    "mfa_drift_table": "mfa_drift",
    "suspicious_approver_table": "suspicious_approver_behavior",
    "ad_churn_table": "ad_group_churn_rate",
    "orphan_event_table": "orphan_event_detection",
    "orphan_user_table": "orphan_user_detection",
    "cleanest_users_table": "cleanest_users",
    "shadow_table": "shadow_access_events",
    "risk_table": "risk_scores",
    "timeline_table": "identity_timelines",
    "time_warp_table": "suspicious_time_warp",
}

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def df_is_empty(df) -> bool:
    try:
        return df.rdd.isEmpty()
    except Exception:
        return True


def safe_read_parquet(spark: SparkSession, path: str):
    try:
        return spark.read.parquet(path)
    except Exception as e:
        logger.info(f"No data at {path}: {e}")
        return spark.createDataFrame([], schema=None)


# -------------------------------------------------------------------
# (Detection functions unchanged — omitted here for brevity)
# KEEP ALL YOUR EXISTING detect_* FUNCTIONS AS-IS
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# BigQuery writer
# -------------------------------------------------------------------
def write_bq(df, table, project, dataset, write_method):
    if df_is_empty(df):
        logger.info(f"Skipping empty dataframe for {table}")
        return

    (
        df.write.format("bigquery")
        .option("table", f"{project}:{dataset}.{table}")
        .option("writeMethod", write_method)
        .option("writeDisposition", "WRITE_APPEND")
        .option("schemaUpdateOptions", "ALLOW_FIELD_ADDITION,ALLOW_FIELD_RELAXATION")
        .mode("append")
        .save()
    )
    logger.info(f"Wrote {project}:{dataset}.{table}")


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main(
    env: str,
    gcs_bucket: str,
    bq_project: str,
    bq_dataset: str,
    source: str,
    input_file: Optional[str],
    write_method: str,
    temp_gcs_bucket: Optional[str],
):
    builder = SparkSession.builder.appName("IAMTransform")

    if write_method == "indirect" and temp_gcs_bucket:
        builder = builder.config("temporaryGcsBucket", temp_gcs_bucket)

    spark = builder.getOrCreate()

    try:
        # ------------------------------------------------------------
        # Read primary input
        # ------------------------------------------------------------
        if input_file:
            primary_path = f"gs://{gcs_bucket}/{input_file}"
        else:
            primary_path = f"gs://{gcs_bucket}/source/{source}/*.parquet"

        logger.info(f"Reading primary input: {primary_path}")
        primary = safe_read_parquet(spark, primary_path)

        # ------------------------------------------------------------
        # Read all historical sources
        # ------------------------------------------------------------
        sources = {
            "okta": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/okta/*.parquet"),
            "ad": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/ad/*.parquet"),
            "saviynt": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/saviynt/*.parquet"),
            "app_usage": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/app_usage/*.parquet"),
        }

        okta_df = sources.get("okta")
        ad_df = sources.get("ad")
        sav_df = sources.get("saviynt")
        app_df = sources.get("app_usage")

        if source == "okta":
            okta_df = primary
        elif source == "ad":
            ad_df = primary
        elif source == "saviynt":
            sav_df = primary
        elif source == "app_usage":
            app_df = primary

        # ------------------------------------------------------------
        # Run detections (unchanged)
        # ------------------------------------------------------------
        impossible_df = impossible_login(okta_df, app_df)
        mfa_df = mfa_bypass_detection(okta_df, app_df)
        shadow_df = detect_shadow_access(okta_df, app_df, sav_df, ad_df)
        risk_df = compute_security_reputation(okta_df, sav_df, ad_df, app_df)
        timeline_df = time_identity_portrait(okta_df, sav_df, ad_df, app_df)

        # ------------------------------------------------------------
        # Write outputs
        # ------------------------------------------------------------
        write_bq(impossible_df, TABLES["impossible_table"], bq_project, bq_dataset, write_method)
        write_bq(mfa_df, TABLES["mfa_table"], bq_project, bq_dataset, write_method)
        write_bq(shadow_df, TABLES["shadow_table"], bq_project, bq_dataset, write_method)
        write_bq(risk_df, TABLES["risk_table"], bq_project, bq_dataset, write_method)
        write_bq(timeline_df, TABLES["timeline_table"], bq_project, bq_dataset, write_method)

    except Exception as e:
        logger.error("Spark job failed", exc_info=True)
        sys.exit(1)
    finally:
        spark.stop()
        logger.info("Spark session stopped")


# -------------------------------------------------------------------
# ENTRYPOINT
# -------------------------------------------------------------------
if __name__ == "__main__":
    p = argparse.ArgumentParser("IAM Spark Transform (clean)")
    p.add_argument("--env", required=True)
    p.add_argument("--gcs_bucket", required=True)
    p.add_argument("--bq_project", required=True)
    p.add_argument("--bq_dataset", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--input_file", default=None)
    p.add_argument("--write_method", default="direct", choices=["direct", "indirect"])
    p.add_argument("--temp_gcs_bucket", default=None)

    args = p.parse_args()

    main(
        env=args.env,
        gcs_bucket=args.gcs_bucket,
        bq_project=args.bq_project,
        bq_dataset=args.bq_dataset,
        source=args.source,
        input_file=args.input_file,
        write_method=args.write_method,
        temp_gcs_bucket=args.temp_gcs_bucket,
    )
