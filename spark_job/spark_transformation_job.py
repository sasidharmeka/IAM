import argparse
import logging
import sys

from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.window import Window

# ===============================================================
# LOGGING
# ===============================================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("iam-spark")

# ===============================================================
# BIGQUERY WRITE HELPER
# ===============================================================
def write_bq(df, project, dataset, table):
    if df is None:
        logger.warning(f"{table}: dataframe is None, skipping")
        return

    if df.rdd.isEmpty():
        logger.warning(f"{table}: empty dataframe, skipping")
        return

    (
        df.write
        .format("bigquery")
        .option("table", f"{project}:{dataset}.{table}")
        .mode("append")
        .save()
    )

    logger.info(f"✅ WROTE → {project}:{dataset}.{table}")

# ===============================================================
# DETECTIONS
# ===============================================================

def impossible_login(okta_df, app_df):
    okta = okta_df.withColumn("okta_ts", to_timestamp("ts"))
    app  = app_df.withColumn("app_ts", to_timestamp("ts"))

    joined = (
        okta.join(app, "user")
        .withColumn("delta_sec", unix_timestamp("app_ts") - unix_timestamp("okta_ts"))
        .filter((col("delta_sec") < 0) | (col("delta_sec") > 1800))
    )

    return joined.select("user", "app", "okta_ts", "app_ts", "delta_sec")


def mfa_bypass_detection(okta_df, app_df):
    failed = okta_df.filter(col("status").like("%FAIL%")) \
        .withColumn("fail_ts", to_timestamp("ts"))

    app = app_df.withColumn("app_ts", to_timestamp("ts"))

    return (
        failed.join(app, "user")
        .withColumn("delta_sec", unix_timestamp("app_ts") - unix_timestamp("fail_ts"))
        .filter((col("delta_sec") > 0) & (col("delta_sec") <= 3600))
        .select("user", "app", "fail_ts", "app_ts", "delta_sec")
    )


def mfa_bypass_detection_all_apps(okta_df, app_df):
    return mfa_bypass_detection(okta_df, app_df)


def impossible_travel(okta_df, app_df):
    w = Window.partitionBy("user").orderBy("ts")
    enriched = (
        okta_df
        .withColumn("ts", to_timestamp("ts"))
        .withColumn("prev_ts", lag("ts").over(w))
        .withColumn("delta_sec", unix_timestamp("ts") - unix_timestamp("prev_ts"))
        .filter((col("country").isNotNull()) & (col("delta_sec") <= 3600))
    )

    return enriched


def detect_shadow_access(okta_df, app_df, sav_df, ad_df):
    ad = ad_df.withColumn("ad_ts", to_timestamp("ts"))
    sav = sav_df.withColumn("sav_ts", to_timestamp("ts"))

    ad_shadow = ad.join(
        sav,
        (ad.user == sav.user) & (ad.request_id == sav.req_id),
        "left_anti"
    )

    return ad_shadow


def privelege_escalation_without_request(ad_df, sav_df):
    ad = ad_df.withColumn("ad_ts", to_timestamp("ts"))
    sav = sav_df.withColumn("sav_ts", to_timestamp("ts"))

    return ad.join(
        sav,
        (ad.user == sav.user) & (ad.request_id == sav.req_id),
        "left_anti"
    )


def volume_spike_detection(ad_df):
    ad = ad_df.withColumn("ts", to_timestamp("ts"))
    daily = ad.groupBy(to_date("ts").alias("date"), "action").count()

    w = Window.partitionBy("action").orderBy("date").rowsBetween(-7, -1)
    return daily.withColumn("rolling_avg", avg("count").over(w)) \
                .filter(col("count") > col("rolling_avg") * 3)


def rejected_but_executed(ad_df, sav_df):
    ad = ad_df.withColumn("ad_ts", to_timestamp("ts"))
    sav = sav_df.withColumn("sav_ts", to_timestamp("ts"))

    return ad.join(
        sav,
        (ad.user == sav.user) & (ad.request_id == sav.req_id) &
        (sav.status.isin("REJECTED", "DENIED")),
        "inner"
    )


def high_risk_sequence_analysis(app_df):
    w = Window.partitionBy("user").orderBy("ts")
    app = app_df.withColumn("prev_app", lag("app").over(w)) \
                .withColumn("next_app", lead("app").over(w))

    return app.filter(
        (col("prev_app") == "GitHub") &
        (col("app") == "Snowflake") &
        (col("next_app") == "Databricks")
    )


def excessive_data_transferred(app_df):
    app = app_df.withColumn("date", to_date("ts"))
    daily = app.groupBy("user", "date").agg(sum("data_mb").alias("total_mb"))

    w = Window.partitionBy("user").orderBy("date").rowsBetween(-7, -1)
    return daily.withColumn("avg_mb", avg("total_mb").over(w)) \
                .filter(col("total_mb") > col("avg_mb") * 3)


def first_seen_last_seen_role(sav_df):
    return sav_df.groupBy("user").agg(
        first("role").alias("first_role"),
        last("role").alias("last_role")
    )


def stale_access_detection(app_df, sav_df):
    sav = sav_df.withColumn("sav_ts", to_timestamp("ts"))
    return sav.filter(
        unix_timestamp(current_timestamp()) - unix_timestamp("sav_ts") > 45 * 86400
    )


def multi_app_single_session(app_df, okta_df):
    return (
        app_df.groupBy("user", "session_id")
        .agg(countDistinct("app").alias("app_count"))
        .filter(col("app_count") > 4)
    )


def mfa_drift(okta_df, app_df):
    return okta_df.groupBy("user", "mfa").count()


def suspicious_approver_behavior(sav_df):
    return sav_df.groupBy("approver").count().filter(col("count") > 25)


def ad_group_churn_rate(ad_df):
    ad = ad_df.withColumn("date", to_date("ts"))
    return ad.groupBy("user").count()


def orphan_event_detection(okta_df, sav_df, ad_df, app_df):
    return app_df.join(okta_df, "user", "left_anti")


def orphan_user_detection(okta_df, sav_df, ad_df, app_df):
    return app_df.join(okta_df, "user", "left_anti")


def find_cleanest_users(okta_df, sav_df, ad_df, app_df):
    return okta_df.groupBy("user").count().orderBy("count").limit(10)


def compute_security_reputation(okta_df, sav_df, ad_df, app_df):
    return okta_df.groupBy("user").agg(count("*").alias("risk_score"))


def time_identity_portriat(okta_df, sav_df, ad_df, app_df):
    return (
        okta_df.select("user", "ts")
        .union(sav_df.select("user", "ts"))
        .union(ad_df.select("user", "ts"))
        .union(app_df.select("user", "ts"))
    )


def suspicious_cross_system_time_warp(sav_df, ad_df, app_df):
    return sav_df.join(ad_df, "user").join(app_df, "user")


# ===============================================================
# MAIN
# ===============================================================
def main(env, gcs_bucket, bq_project, bq_dataset, source):

    spark = SparkSession.builder.appName(f"IAM-{env}").getOrCreate()
    base = f"gs://{gcs_bucket}/source"

    okta_df = spark.read.parquet(f"{base}/okta/*.parquet")
    ad_df   = spark.read.parquet(f"{base}/ad/*.parquet")
    app_df  = spark.read.parquet(f"{base}/app_usage/*.parquet")
    sav_df  = spark.read.parquet(f"{base}/saviynt/*.parquet")

    detections = [
        ("impossible_login_anomalies", impossible_login(okta_df, app_df)),
        ("mfa_bypass_events", mfa_bypass_detection(okta_df, app_df)),
        ("mfa_bypass_events_all_apps", mfa_bypass_detection_all_apps(okta_df, app_df)),
        ("impossible_travel_events", impossible_travel(okta_df, app_df)),
        ("shadow_access_events", detect_shadow_access(okta_df, app_df, sav_df, ad_df)),
        ("privilege_escalation_without_request", privelege_escalation_without_request(ad_df, sav_df)),
        ("ad_volume_spikes", volume_spike_detection(ad_df)),
        ("rejected_but_executed", rejected_but_executed(ad_df, sav_df)),
        ("high_risk_sequence", high_risk_sequence_analysis(app_df)),
        ("excessive_data_transferred", excessive_data_transferred(app_df)),
        ("role_drift", first_seen_last_seen_role(sav_df)),
        ("stale_access", stale_access_detection(app_df, sav_df)),
        ("multi_app_single_session", multi_app_single_session(app_df, okta_df)),
        ("mfa_drift", mfa_drift(okta_df, app_df)),
        ("suspicious_approver_behavior", suspicious_approver_behavior(sav_df)),
        ("ad_group_churn_rate", ad_group_churn_rate(ad_df)),
        ("orphan_event_detection", orphan_event_detection(okta_df, sav_df, ad_df, app_df)),
        ("orphan_user_detection", orphan_user_detection(okta_df, sav_df, ad_df, app_df)),
        ("cleanest_users", find_cleanest_users(okta_df, sav_df, ad_df, app_df)),
        ("risk_scores", compute_security_reputation(okta_df, sav_df, ad_df, app_df)),
        ("identity_timelines", time_identity_portriat(okta_df, sav_df, ad_df, app_df)),
        ("suspicious_time_warp", suspicious_cross_system_time_warp(sav_df, ad_df, app_df)),
    ]

    for table, df in detections:
        logger.info(f"🚀 Running detection → {table}")
        write_bq(df, bq_project, bq_dataset, table)

    spark.stop()


# ===============================================================
# ENTRYPOINT
# ===============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True)
    parser.add_argument("--gcs_bucket", required=True)
    parser.add_argument("--bq_project", required=True)
    parser.add_argument("--bq_dataset", required=True)
    parser.add_argument("--source", required=True)

    args = parser.parse_args()
    main(**vars(args))
