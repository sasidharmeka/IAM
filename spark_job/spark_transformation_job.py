"""
IAM Spark transformation job.

Contract:
- Accepts `--input_file` (relative path under bucket, e.g. source/okta/20250101-...parquet)
- Accepts `--source` (okta|ad|saviynt|app_usage|hrlifecycle|anomaly_key)
- Reads the provided input file (if present) and historical data from other sources.
- Performs IAM-specific detection functions and writes Gold outputs to BigQuery.

This file is adapted from the notebook `copy_of_untitled7.py`.
"""

import argparse
import logging
import sys
from typing import Optional

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.functions import col, to_timestamp, unix_timestamp, lit, when
from pyspark.sql.window import Window

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("IAM-transform")


def has_column(df, name: str) -> bool:
    try:
        return name in df.columns
    except Exception:
        return False


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


# ----------------- Detection functions (extracted & simplified) -----------------
def detect_shadow_access(okta_df, app_df, sav_df, ad_df):
    # Normalize
    okta = okta_df.withColumnRenamed("user", "okta_user").withColumn("okta_ts", to_timestamp(col("ts"))) if not df_is_empty(okta_df) else okta_df
    app = app_df.withColumnRenamed("user", "app_user").withColumn("app_ts", to_timestamp(col("ts"))) if not df_is_empty(app_df) else app_df
    sav = sav_df.withColumnRenamed("user", "sav_user").withColumn("sav_ts", to_timestamp(col("ts"))) if not df_is_empty(sav_df) else sav_df
    ad = ad_df.withColumnRenamed("user", "ad_user").withColumn("ad_ts", to_timestamp(col("ts"))) if not df_is_empty(ad_df) else ad_df

    privileged_groups = ["Security-Admins", "DBA", "DevOps"]

    ad_recent = ad.filter((col("group").isin(privileged_groups))) if not df_is_empty(ad) else ad

    ad_shadow = ad_recent.alias("ad") \
        .join(sav.alias("sav"), col("ad.request_id") == col("sav.req_id"), "left_anti") \
        .select(col("ad.ad_user").alias("user"), col("ad.ad_ts").alias("time_of_privilege_grant"), col("ad.group").alias("privileged_group_gained"), col("ad.action"), col("ad.initiator").alias("granted_by"))

    # correlate with app usage within 24h
    active = app.alias("a").select(col("a.app_user"), col("a.app_ts"), col("a.app").alias("app_accessed")) if not df_is_empty(app) else app

    suspicious = ad_shadow.alias("s") \
        .join(active.alias("a"), (col("s.user") == col("a.app_user")) & (unix_timestamp(col("a.app_ts")) >= unix_timestamp(col("s.time_of_privilege_grant"))) & ((unix_timestamp(col("a.app_ts")) - unix_timestamp(col("s.time_of_privilege_grant"))) <= 86400), "inner") \
        .select("user", "privileged_group_gained", "app_accessed", "time_of_privilege_grant", col("a.app_ts").alias("time_of_app_access"), "granted_by")

    return suspicious


def impossible_login(okta_df, app_df):
    okta = okta_df.withColumnRenamed("user", "okta_user").withColumn("okta_ts", to_timestamp(col("ts"))) if not df_is_empty(okta_df) else okta_df
    app = app_df.withColumnRenamed("user", "app_user").withColumn("app_ts", to_timestamp(col("ts"))) if not df_is_empty(app_df) else app_df

    # CASE: join on session_id when available
    session_ok = okta.filter(col("session_id").isNotNull() & (col("session_id") != "")) if not df_is_empty(okta) else okta
    session_app = app.filter(col("session_id").isNotNull() & (col("session_id") != "")) if not df_is_empty(app) else app

    session_join = session_ok.alias("o").join(session_app.alias("a"), (col("o.session_id") == col("a.session_id")) & (col("o.okta_user") == col("a.app_user")), "inner") \
        .withColumn("time_diff_sec", unix_timestamp(col("a.app_ts")) - unix_timestamp(col("o.okta_ts"))) \
        .filter((col("time_diff_sec") < 0) | (col("time_diff_sec") > 1800)) \
        .select(col("o.okta_user").alias("user"), col("o.session_id"), col("a.app").alias("app_accessed"), col("o.okta_ts").alias("time_of_login"), col("a.app_ts").alias("time_of_app_access"), col("time_diff_sec"), col("a.duration").alias("app_usage_duration_sec"))

    # CASE: app without session_id -> join on user + window
    app_no_sid = app.filter(col("session_id").isNull() | (col("session_id") == "")) if not df_is_empty(app) else app
    timestamp_join = app_no_sid.alias("a").join(okta.alias("o"), (col("a.app_user") == col("o.okta_user")) & (abs(unix_timestamp(col("a.app_ts")) - unix_timestamp(col("o.okta_ts"))) <= 7200), "inner") \
        .withColumn("time_diff_sec", unix_timestamp(col("a.app_ts")) - unix_timestamp(col("o.okta_ts"))) \
        .filter((col("time_diff_sec") < 0) | (col("time_diff_sec") > 1800)) \
        .select(col("a.app_user").alias("user"), col("a.session_id"), col("a.app").alias("app_accessed"), col("o.okta_ts").alias("time_of_login"), col("a.app_ts").alias("time_of_app_access"), col("time_diff_sec"), col("a.duration").alias("app_usage_duration_sec"))

    # CASE: app with no matching login
    app_no_login = app_no_sid.alias("a").join(okta.alias("o"), (col("a.app_user") == col("o.okta_user")) & (abs(unix_timestamp(col("a.app_ts")) - unix_timestamp(col("o.okta_ts"))) <= 7200), "left") \
        .filter(col("o.okta_user").isNull()) \
        .select(col("a.app_user").alias("user"), col("a.session_id"), col("a.app").alias("app_accessed"), lit(None).cast("timestamp").alias("time_of_login"), col("a.app_ts").alias("time_of_app_access"), lit(None).cast("long").alias("time_diff_sec"), col("a.duration").alias("app_usage_duration_sec"))

    final = session_join.unionByName(timestamp_join).unionByName(app_no_login)
    return final


def mfa_bypass_detection(okta_df, app_df):
    okta = okta_df.withColumnRenamed("user", "okta_user").withColumn("okta_ts", to_timestamp(col("ts"))) if not df_is_empty(okta_df) else okta_df
    app = app_df.withColumnRenamed("user", "app_user").withColumn("app_ts", to_timestamp(col("ts"))) if not df_is_empty(app_df) else app_df

    failed_mfa = okta.filter((col("status") == "MFA_FAILED") | (col("status").like("%FAIL%"))).select(col("okta_user").alias("user"), col("okta_ts").alias("failed_mfa_ts"), col("status").alias("failure_reason"), col("session_id"))

    # bucket 1: session join
    failed_with_sid = failed_mfa.filter(col("session_id").isNotNull())
    app_with_sid = app.filter(col("session_id").isNotNull())
    join_sid = failed_with_sid.alias("f").join(app_with_sid.alias("a"), (col("f.session_id") == col("a.session_id")) & (unix_timestamp(col("a.app_ts")) > unix_timestamp(col("f.failed_mfa_ts"))) & ((unix_timestamp(col("a.app_ts")) - unix_timestamp(col("f.failed_mfa_ts"))) <= 3600), "inner") \
        .withColumn("seconds_after_failure", unix_timestamp(col("a.app_ts")) - unix_timestamp(col("f.failed_mfa_ts"))) \
        .select(col("f.user"), col("f.failed_mfa_ts").alias("mfa_failure_time"), col("f.failure_reason"), col("a.app").alias("app_accessed"), col("a.app_ts").alias("app_access_time"), col("seconds_after_failure"), col("a.session_id").alias("app_session_id"), col("a.duration").alias("app_usage_duration_sec"))

    # bucket 2/3: join and rank to reduce explosion
    failed_no_sid = failed_mfa.filter(col("session_id").isNull())
    join_okta_no_sid = failed_no_sid.alias("f").join(app.alias("a"), (col("f.user") == col("a.app_user")) & (unix_timestamp(col("a.app_ts")) > unix_timestamp(col("f.failed_mfa_ts"))) & ((unix_timestamp(col("a.app_ts")) - unix_timestamp(col("f.failed_mfa_ts"))) <= 3600), "inner").withColumn("seconds_after_failure", unix_timestamp(col("a.app_ts")) - unix_timestamp(col("f.failed_mfa_ts")))

    app_no_sid = app.filter(col("session_id").isNull())
    join_app_no_sid = failed_mfa.alias("f").join(app_no_sid.alias("a"), (col("f.user") == col("a.app_user")) & (unix_timestamp(col("a.app_ts")) > unix_timestamp(col("f.failed_mfa_ts"))) & ((unix_timestamp(col("a.app_ts")) - unix_timestamp(col("f.failed_mfa_ts"))) <= 3600), "inner").withColumn("seconds_after_failure", unix_timestamp(col("a.app_ts")) - unix_timestamp(col("f.failed_mfa_ts")))

    window_spec = Window.partitionBy("f.user", "f.failed_mfa_ts").orderBy("a.app_ts")

    bucket2_clean = join_okta_no_sid.withColumn("rank", F.row_number().over(window_spec)).filter(col("rank") == 1).drop("rank").select(col("f.user").alias("user"), col("f.failed_mfa_ts").alias("mfa_failure_time"), col("f.failure_reason").alias("failure_reason"), col("a.app").alias("app_accessed"), col("a.app_ts").alias("app_access_time"), col("seconds_after_failure"), lit(None).cast("string").alias("app_session_id"), col("a.duration").alias("app_usage_duration_sec"))

    bucket3_clean = join_app_no_sid.withColumn("rank", F.row_number().over(window_spec)).filter(col("rank") == 1).drop("rank").select(col("f.user").alias("user"), col("f.failed_mfa_ts").alias("mfa_failure_time"), col("f.failure_reason").alias("failure_reason"), col("a.app").alias("app_accessed"), col("a.app_ts").alias("app_access_time"), col("seconds_after_failure"), lit(None).cast("string").alias("app_session_id"), col("a.duration").alias("app_usage_duration_sec"))

    final = join_sid.unionByName(bucket2_clean).unionByName(bucket3_clean).orderBy("seconds_after_failure")
    return final


def compute_security_reputation(okta_df, sav_df, ad_df, app_df):
    # simplified risk scoring adapted from notebook
    okta = okta_df
    sav = sav_df
    ad = ad_df
    app = app_df

    okta_metrics = okta.groupBy("user").agg(F.countDistinct("country").alias("unique_countries"), F.sum(when(col("status") == "FAILED", 1).otherwise(0)).alias("failed_mfa"), F.sum(when(col("status") == "SUCCESS", 1).otherwise(0)).alias("success_mfa"), F.count("*").alias("total_logins")) if not df_is_empty(okta) else okta

    sav_metrics = sav.groupBy("user").agg(F.count("*").alias("access_requests")) if not df_is_empty(sav) else sav

    ad_metrics = ad.groupBy("user").agg(F.sum(when(col("action") == "privilege_escalation", 1).otherwise(0)).alias("privilege_escalations"), F.count("*").alias("ad_actions")) if not df_is_empty(ad) else ad

    unexplained_usage = app.alias("a").join(sav.alias("s"), (col("a.user") == col("s.user")) & (col("a.request_id") == col("s.req_id")), "left_anti").groupBy("user").agg(F.count("*").alias("unexplained_app_usage")) if not df_is_empty(app) else app

    combined = okta_metrics.join(sav_metrics, "user", "left").join(ad_metrics, "user", "left").join(unexplained_usage, "user", "left").fillna(0)

    risk_scores = combined.withColumn("risk_score", (lit(2) * col("failed_mfa")) + (lit(3) * col("privilege_escalations")) + (lit(5) * col("unexplained_app_usage")))

    top_10 = risk_scores.orderBy(col("risk_score").desc()).limit(100)
    return top_10


def time_identity_portrait(okta_df, sav_df, ad_df, app_df):
    okta_p = okta_df.select(to_timestamp(col("ts")).alias("event_ts"), col("user"), lit("Okta Login").alias("event_type"), F.concat_ws(" | ", F.concat_ws(": ", lit("Status"), col("status")), F.concat_ws(": ", lit("Country"), col("country")), F.concat_ws(": ", lit("IP"), col("ip")), F.concat_ws(": ", lit("MFA"), col("mfa"))).alias("details")) if not df_is_empty(okta_df) else okta_df

    # Simpler union: select basic columns
    sav_p = sav_df.select(to_timestamp(col("ts")).alias("event_ts"), col("user"), lit("SAV Request").alias("event_type"), F.concat_ws(" | ", col("app"), col("role"), col("status")).alias("details")) if not df_is_empty(sav_df) else sav_df
    ad_p = ad_df.select(to_timestamp(col("ts")).alias("event_ts"), col("user"), lit("AD Group Event").alias("event_type"), F.concat_ws(" | ", col("group"), col("action"), col("initiator")).alias("details")) if not df_is_empty(ad_df) else ad_df
    app_p = app_df.select(to_timestamp(col("ts")).alias("event_ts"), col("user"), lit("App Usage").alias("event_type"), F.concat_ws(" | ", col("app"), col("action"), col("data_mb")).alias("details")) if not df_is_empty(app_df) else app_df

    unioned = okta_p.unionByName(sav_p).unionByName(ad_p).unionByName(app_p)
    ordered = unioned.orderBy(col("user"), col("event_ts"))
    return ordered


def write_bq(frame, table, bq_project, bq_dataset, write_method):
    if df_is_empty(frame):
        logger.info(f"Skipping write to {table}: empty dataframe")
        return
    (
        frame.write.format("bigquery")
        .option("table", f"{bq_project}:{bq_dataset}.{table}")
        .option("writeMethod", write_method)
        .option("writeDisposition", "WRITE_APPEND")
        .option("schemaUpdateOptions", "ALLOW_FIELD_ADDITION,ALLOW_FIELD_RELAXATION")
        .mode("append")
        .save()
    )
    logger.info(f"Wrote table: {bq_project}:{bq_dataset}.{table}")


def main(
    env: str,
    gcs_bucket: str,
    bq_project: str,
    bq_dataset: str,
    input_file: Optional[str],
    source: str,
    write_method: str,
    temp_gcs_bucket: Optional[str],
    impossible_table: str,
    mfa_table: str,
    mfa_all_table: str,
    impossible_travel_table: str,
    privilege_escalation_table: str,
    ad_volume_spike_table: str,
    rejected_executed_table: str,
    high_risk_seq_table: str,
    excessive_data_table: str,
    role_drift_table: str,
    stale_access_table: str,
    multi_app_session_table: str,
    mfa_drift_table: str,
    suspicious_approver_table: str,
    ad_churn_table: str,
    orphan_event_table: str,
    orphan_user_table: str,
    cleanest_users_table: str,
    shadow_table: str,
    risk_table: str,
    timeline_table: str,
    time_warp_table: str,
):
    builder = SparkSession.builder.appName("IAMTransform")
    if write_method == "indirect" and temp_gcs_bucket:
        builder = builder.config("temporaryGcsBucket", temp_gcs_bucket)

    spark = builder.getOrCreate()

    try:
        # Read input file (single) or default to source prefix
        if input_file:
            input_path = f"gs://{gcs_bucket}/{input_file}"
        else:
            input_path = f"gs://{gcs_bucket}/source/{source}/*.parquet"

        logger.info(f"Reading primary input: {input_path}")
        primary = safe_read_parquet(spark, input_path)

        # Read historical sources (others). We attempt to read common source tables; missing sources become empty dfs
        sources = {
            "okta": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/okta/*.parquet"),
            "ad": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/ad/*.parquet"),
            "saviynt": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/saviynt/*.parquet"),
            "app_usage": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/app_usage/*.parquet"),
            "hrlifecycle": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/hrlifecycle/*.parquet"),
            "anomaly_key": safe_read_parquet(spark, f"gs://{gcs_bucket}/source/anomaly_key/*.parquet"),
        }

        # Decide which dataframes to use as primary mapping
        if source == "okta":
            okta_df = primary
            app_df = sources.get("app_usage")
            sav_df = sources.get("saviynt")
            ad_df = sources.get("ad")
        elif source == "app_usage":
            app_df = primary
            okta_df = sources.get("okta")
            sav_df = sources.get("saviynt")
            ad_df = sources.get("ad")
        elif source == "saviynt":
            sav_df = primary
            okta_df = sources.get("okta")
            app_df = sources.get("app_usage")
            ad_df = sources.get("ad")
        elif source == "ad":
            ad_df = primary
            okta_df = sources.get("okta")
            app_df = sources.get("app_usage")
            sav_df = sources.get("saviynt")
        else:
            # default: treat as app_usage-like
            app_df = primary
            okta_df = sources.get("okta")
            sav_df = sources.get("saviynt")
            ad_df = sources.get("ad")

        # Ensure variables exist
        okta_df = okta_df if 'okta_df' in locals() else spark.createDataFrame([], schema=None)
        app_df = app_df if 'app_df' in locals() else spark.createDataFrame([], schema=None)
        sav_df = sav_df if 'sav_df' in locals() else spark.createDataFrame([], schema=None)
        ad_df = ad_df if 'ad_df' in locals() else spark.createDataFrame([], schema=None)

        # Core detections
        impossible_df = impossible_login(okta_df, app_df) if not df_is_empty(okta_df) or not df_is_empty(app_df) else spark.createDataFrame([], schema=None)
        mfa_df = mfa_bypass_detection(okta_df, app_df) if not df_is_empty(okta_df) or not df_is_empty(app_df) else spark.createDataFrame([], schema=None)
        # best-effort for other detectors: call if available in globals()
        def call_fn(name):
            fn = globals().get(name)
            if not fn:
                return spark.createDataFrame([], schema=None)
            # try calling with up to 4 args, fallback on arity mismatch
            for args_try in [(okta_df, app_df, sav_df, ad_df), (okta_df, app_df, sav_df), (okta_df, app_df), (app_df, okta_df), (ad_df, sav_df)]:
                try:
                    return fn(*args_try)
                except TypeError:
                    continue
                except Exception as e:
                    logger.warning(f"Function {name} raised: {e}")
                    return spark.createDataFrame([], schema=None)
            return spark.createDataFrame([], schema=None)

        mfa_all_df = call_fn("mfa_bypass_detection_all_apps")
        impossible_travel_df = call_fn("impossible_travel")
        privilege_escalation_df = call_fn("privelege_escalation_without_request")
        ad_volume_spike_df = call_fn("volume_spike_detection")
        rejected_executed_df = call_fn("rejected_but_executed")
        high_risk_seq_df = call_fn("high_risk_sequence_analysis")
        excessive_data_df = call_fn("excessive_data_transferred")
        role_drift_df = call_fn("first_seen_last_seen_role")
        stale_access_df = call_fn("stale_access_detection")
        multi_app_session_df = call_fn("multi_app_single_session")
        mfa_drift_df = call_fn("mfa_drift")
        suspicious_approver_df = call_fn("suspicious_approver_behavior")
        ad_churn_df = call_fn("ad_group_churn_rate")
        orphan_event_df = call_fn("orphan_event_detection")
        orphan_user_df = call_fn("orphan_user_detection")
        cleanest_users_df = call_fn("find_cleanest_users")
        time_warp_df = call_fn("suspicious_cross_system_time_warp")
        shadow_df = detect_shadow_access(okta_df, app_df, sav_df, ad_df) if (not df_is_empty(ad_df)) else spark.createDataFrame([], schema=None)
        risk_df = compute_security_reputation(okta_df, sav_df, ad_df, app_df) if not df_is_empty(okta_df) else spark.createDataFrame([], schema=None)
        timeline_df = time_identity_portrait(okta_df, sav_df, ad_df, app_df) if not (df_is_empty(okta_df) and df_is_empty(sav_df) and df_is_empty(ad_df) and df_is_empty(app_df)) else spark.createDataFrame([], schema=None)

        # Write to BigQuery (Gold) — write only non-empty frames
        write_bq(impossible_df, impossible_table, bq_project, bq_dataset, write_method)
        write_bq(mfa_df, mfa_table, bq_project, bq_dataset, write_method)
        write_bq(mfa_all_df, mfa_all_table, bq_project, bq_dataset, write_method)
        write_bq(impossible_travel_df, impossible_travel_table, bq_project, bq_dataset, write_method)
        write_bq(privilege_escalation_df, privilege_escalation_table, bq_project, bq_dataset, write_method)
        write_bq(ad_volume_spike_df, ad_volume_spike_table, bq_project, bq_dataset, write_method)
        write_bq(rejected_executed_df, rejected_executed_table, bq_project, bq_dataset, write_method)
        write_bq(high_risk_seq_df, high_risk_seq_table, bq_project, bq_dataset, write_method)
        write_bq(excessive_data_df, excessive_data_table, bq_project, bq_dataset, write_method)
        write_bq(role_drift_df, role_drift_table, bq_project, bq_dataset, write_method)
        write_bq(stale_access_df, stale_access_table, bq_project, bq_dataset, write_method)
        write_bq(multi_app_session_df, multi_app_session_table, bq_project, bq_dataset, write_method)
        write_bq(mfa_drift_df, mfa_drift_table, bq_project, bq_dataset, write_method)
        write_bq(suspicious_approver_df, suspicious_approver_table, bq_project, bq_dataset, write_method)
        write_bq(ad_churn_df, ad_churn_table, bq_project, bq_dataset, write_method)
        write_bq(orphan_event_df, orphan_event_table, bq_project, bq_dataset, write_method)
        write_bq(orphan_user_df, orphan_user_table, bq_project, bq_dataset, write_method)
        write_bq(cleanest_users_df, cleanest_users_table, bq_project, bq_dataset, write_method)
        write_bq(shadow_df, shadow_table, bq_project, bq_dataset, write_method)
        write_bq(risk_df, risk_table, bq_project, bq_dataset, write_method)
        write_bq(timeline_df, timeline_table, bq_project, bq_dataset, write_method)
        write_bq(time_warp_df, time_warp_table, bq_project, bq_dataset, write_method)

    except Exception as e:
        logger.error(f"Job failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        try:
            spark.stop()
        except Exception:
            pass
        logger.info("Spark session stopped.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="IAM Spark transformations -> BigQuery")
    p.add_argument("--env", required=True)
    p.add_argument("--gcs_bucket", required=True)
    p.add_argument("--bq_project", required=True)
    p.add_argument("--bq_dataset", required=True)
    p.add_argument("--input_file", default=None, help="Optional single input file path under bucket")
    p.add_argument("--source", required=True, help="one of okta,ad,saviynt,app_usage,hrlifecycle,anomaly_key")
    p.add_argument("--write_method", default="direct", choices=["direct", "indirect"])
    p.add_argument("--temp_gcs_bucket", default=None)
    p.add_argument("--impossible_table", required=True)
    p.add_argument("--mfa_table", required=True)
    p.add_argument("--mfa_all_table", required=True)
    p.add_argument("--impossible_travel_table", required=True)
    p.add_argument("--privilege_escalation_table", required=True)
    p.add_argument("--ad_volume_spike_table", required=True)
    p.add_argument("--rejected_executed_table", required=True)
    p.add_argument("--high_risk_seq_table", required=True)
    p.add_argument("--excessive_data_table", required=True)
    p.add_argument("--role_drift_table", required=True)
    p.add_argument("--stale_access_table", required=True)
    p.add_argument("--multi_app_session_table", required=True)
    p.add_argument("--mfa_drift_table", required=True)
    p.add_argument("--suspicious_approver_table", required=True)
    p.add_argument("--ad_churn_table", required=True)
    p.add_argument("--orphan_event_table", required=True)
    p.add_argument("--orphan_user_table", required=True)
    p.add_argument("--cleanest_users_table", required=True)
    p.add_argument("--shadow_table", required=True)
    p.add_argument("--risk_table", required=True)
    p.add_argument("--timeline_table", required=True)
    p.add_argument("--time_warp_table", required=True)
    args = p.parse_args()

    main(
        env=args.env,
        gcs_bucket=args.gcs_bucket,
        bq_project=args.bq_project,
        bq_dataset=args.bq_dataset,
        input_file=args.input_file,
        source=args.source,
        write_method=args.write_method,
        temp_gcs_bucket=args.temp_gcs_bucket,
        impossible_table=args.impossible_table,
        mfa_table=args.mfa_table,
        mfa_all_table=args.mfa_all_table,
        impossible_travel_table=args.impossible_travel_table,
        privilege_escalation_table=args.privilege_escalation_table,
        ad_volume_spike_table=args.ad_volume_spike_table,
        rejected_executed_table=args.rejected_executed_table,
        high_risk_seq_table=args.high_risk_seq_table,
        excessive_data_table=args.excessive_data_table,
        role_drift_table=args.role_drift_table,
        stale_access_table=args.stale_access_table,
        multi_app_session_table=args.multi_app_session_table,
        mfa_drift_table=args.mfa_drift_table,
        suspicious_approver_table=args.suspicious_approver_table,
        ad_churn_table=args.ad_churn_table,
        orphan_event_table=args.orphan_event_table,
        orphan_user_table=args.orphan_user_table,
        cleanest_users_table=args.cleanest_users_table,
        shadow_table=args.shadow_table,
        risk_table=args.risk_table,
        timeline_table=args.timeline_table,
        time_warp_table=args.time_warp_table,
    )