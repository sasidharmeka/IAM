"""
IAM Spark transformation job (stable & minimal).

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
"""

import argparse
import logging
import sys
from typing import Optional

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import col, to_timestamp, unix_timestamp, lit
from pyspark.sql.window import Window

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("IAM-transform")

# -------------------------------------------------------------------
# Spark-owned table names
# -------------------------------------------------------------------
TABLES = {
    "impossible": "impossible_login_anomalies",
    "mfa": "mfa_bypass_events",
    "shadow": "shadow_access_events",
    "risk": "risk_scores",
    "timeline": "identity_timelines",
}

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def df_is_empty(df):
    try:
        return df.rdd.isEmpty()
    except Exception:
        return True


def safe_read_parquet(spark, path):
    try:
        return spark.read.parquet(path)
    except Exception as e:
        logger.warning(f"No data at {path}: {e}")
        return spark.createDataFrame([], schema=None)

# -------------------------------------------------------------------
# Detection logic (MINIMAL, SAFE)
# -------------------------------------------------------------------
def impossible_login(okta_df, app_df):
    if df_is_empty(okta_df) or df_is_empty(app_df):
        return okta_df.sparkSession.createDataFrame([], schema=None)

    o = okta_df.withColumn("login_ts", to_timestamp("ts")).select("user", "login_ts")
    a = app_df.withColumn("app_ts", to_timestamp("ts")).select("user", "app", "app_ts")

    joined = (
        o.join(a, "user")
        .withColumn("delta_sec", unix_timestamp("app_ts") - unix_timestamp("login_ts"))
        .filter((col("delta_sec") < 0) | (col("delta_sec") > 1800))
    )

    return joined.select(
        "user",
        "app",
        "login_ts",
        "app_ts",
        "delta_sec"
    )


def mfa_bypass_detection(okta_df, app_df):
    if df_is_empty(okta_df) or df_is_empty(app_df):
        return okta_df.sparkSession.createDataFrame([], schema=None)

    failed = okta_df.filter(col("status").like("%FAIL%")) \
        .withColumn("fail_ts", to_timestamp("ts")) \
        .select("user", "fail_ts")

    app = app_df.withColumn("app_ts", to_timestamp("ts")) \
        .select("user", "app", "app_ts")

    joined = (
        failed.join(app, "user")
        .withColumn("delta_sec", unix_timestamp("app_ts") - unix_timestamp("fail_ts"))
        .filter((col("delta_sec") > 0) & (col("delta_sec") <= 3600))
    )

    return joined.select(
        "user",
        "app",
        "fail_ts",
        "app_ts",
        "delta_sec"
    )


def detect_shadow_access(okta_df, app_df, sav_df, ad_df):
    if df_is_empty(ad_df):
        return ad_df.sparkSession.createDataFrame([], schema=None)

    return ad_df.select(
        col("user"),
        col("group").alias("privileged_group"),
        to_timestamp("ts").alias("grant_time"),
        col("initiator")
    )


def compute_security_reputation(okta_df, sav_df, ad_df, app_df):
    if df_is_empty(okta_df):
        return okta_df.sparkSession.createDataFrame([], schema=None)

    risk = okta_df.groupBy("user").agg(
        F.count("*").alias("login_count"),
        F.sum(F.when(col("status").like("%FAIL%"), 1).otherwise(0)).alias("failed_logins")
    )

    return risk.withColumn(
        "risk_score",
        col("failed_logins") * 3 + col("login_count")
    )


def time_identity_portrait(okta_df, sav_df, ad_df, app_df):
    frames = []

    if not df_is_empty(okta_df):
        frames.append(
            okta_df.select(
                to_timestamp("ts").alias("event_ts"),
                "user",
                lit("okta").alias("source"),
                col("status").alias("detail")
            )
        )

    if not df_is_empty(ad_df):
        frames.append(
            ad_df.select(
                to_timestamp("ts").alias("event_ts"),
                "user",
                lit("ad").alias("source"),
                col("action").alias("detail")
            )
        )

    if not frames:
        return okta_df.sparkSession.createDataFrame([], schema=None)

    return frames[0].unionByName(*frames[1:]).orderBy("user", "event_ts")

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
    spark = SparkSession.builder.appName("IAMTransform").getOrCreate()

    try:
        if input_file:
            primary_path = f"gs://{gcs_bucket}/{input_file}"
        else:
            primary_path = f"gs://{gcs_bucket}/source/{source}/*.parquet"

        logger.info(f"Reading primary input: {primary_path}")
        primary = safe_read_parquet(spark, primary_path)

        sources = {
            "okta": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/okta/*.parquet"),
            "ad": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/ad/*.parquet"),
            "saviynt": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/saviynt/*.parquet"),
            "app_usage": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/app_usage/*.parquet"),
        }

        okta_df = primary if source == "okta" else sources["okta"]
        ad_df = primary if source == "ad" else sources["ad"]
        sav_df = primary if source == "saviynt" else sources["saviynt"]
        app_df = primary if source == "app_usage" else sources["app_usage"]

        impossible_df = impossible_login(okta_df, app_df)
        mfa_df = mfa_bypass_detection(okta_df, app_df)
        shadow_df = detect_shadow_access(okta_df, app_df, sav_df, ad_df)
        risk_df = compute_security_reputation(okta_df, sav_df, ad_df, app_df)
        timeline_df = time_identity_portrait(okta_df, sav_df, ad_df, app_df)

        write_bq(impossible_df, TABLES["impossible"], bq_project, bq_dataset, write_method)
        write_bq(mfa_df, TABLES["mfa"], bq_project, bq_dataset, write_method)
        write_bq(shadow_df, TABLES["shadow"], bq_project, bq_dataset, write_method)
        write_bq(risk_df, TABLES["risk"], bq_project, bq_dataset, write_method)
        write_bq(timeline_df, TABLES["timeline"], bq_project, bq_dataset, write_method)

    except Exception:
        logger.error("Spark job failed", exc_info=True)
        sys.exit(1)
    finally:
        spark.stop()
        logger.info("Spark session stopped")

# -------------------------------------------------------------------
# ENTRYPOINT
# -------------------------------------------------------------------
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--env", required=True)
    p.add_argument("--gcs_bucket", required=True)
    p.add_argument("--bq_project", required=True)
    p.add_argument("--bq_dataset", required=True)
    p.add_argument("--source", required=True)
    p.add_argument("--input_file", default=None)
    p.add_argument("--write_method", default="direct")
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
