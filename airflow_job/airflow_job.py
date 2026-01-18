from airflow import DAG
from airflow.utils.dates import days_ago
from airflow.operators.empty import EmptyOperator
from airflow.providers.google.cloud.operators.dataproc import DataprocSubmitJobOperator

from datetime import timedelta

# -------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------
ENV = "dev"
GCS_BUCKET = "iam-raw-bucket"
BQ_PROJECT = "my-bq-project"
BQ_DATASET = "iam_analytics"
REGION = "us-central1"
CLUSTER_NAME = "iam-spark-cluster"

SPARK_MAIN = "gs://iam-code-bucket/jobs/iam_transform.py"

DEFAULT_ARGS = {
    "owner": "data-eng",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}

# -------------------------------------------------------------------
# DAG
# -------------------------------------------------------------------
with DAG(
    dag_id="iam_daily_transform",
    default_args=DEFAULT_ARGS,
    start_date=days_ago(1),
    schedule_interval="@daily",
    catchup=True,
    max_active_runs=1,
    tags=["iam", "spark", "secure"],
) as dag:

    start = EmptyOperator(task_id="start")

    # ---------------------------------------------------------------
    # INGESTION DAGS (already exist, represented as sensors or markers)
    # ---------------------------------------------------------------
    okta_done = EmptyOperator(task_id="okta_ingested")
    app_done = EmptyOperator(task_id="app_usage_ingested")
    ad_done = EmptyOperator(task_id="ad_ingested")

    # ---------------------------------------------------------------
    # SPARK TRANSFORMATION (STRICT)
    # ---------------------------------------------------------------
    spark_transform = DataprocSubmitJobOperator(
        task_id="iam_spark_transform",
        region=REGION,
        project_id=BQ_PROJECT,
        job={
            "placement": {"cluster_name": CLUSTER_NAME},
            "pyspark_job": {
                "main_python_file_uri": SPARK_MAIN,
                "args": [
                    "--env={{ var.value.env }}",
                    "--gcs_bucket=" + GCS_BUCKET,
                    "--bq_project=" + BQ_PROJECT,
                    "--bq_dataset=" + BQ_DATASET,
                    "--execution_date={{ ds_nodash }}",
                ],
            },
        },
    )

    end = EmptyOperator(task_id="end")

    # ---------------------------------------------------------------
    # DEPENDENCIES (THIS IS CRITICAL)
    # ---------------------------------------------------------------
    start >> [okta_done, app_done, ad_done]
    [okta_done, app_done] >> spark_transform
    spark_transform >> end
