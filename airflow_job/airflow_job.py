from datetime import datetime, timedelta
import uuid
import json
import logging
import traceback

from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import ShortCircuitOperator, PythonOperator
from airflow.providers.google.cloud.operators.dataproc import DataprocCreateBatchOperator
from airflow.providers.google.cloud.sensors.gcs import GCSObjectsWithPrefixExistenceSensor

from google.cloud import storage

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Helper: decide whether Spark should run (NO XCOM NEEDED)
# -------------------------------------------------------------------
def should_process_source(source: str, **context):
    """
    Returns True if there are NEW parquet files for this execution date
    that are not yet marked as processed.
    """
    try:
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-iam-proj")
        execution_date = context["ds_nodash"]
        prefix = f"source/{source}/{execution_date}"

        metadata_blob_name = f"metadata/{source}_processed.json"

        client = storage.Client()
        bucket = client.bucket(gcs_bucket)

        blobs = [
            b.name for b in bucket.list_blobs(prefix=prefix)
            if b.name.endswith(".parquet")
        ]

        if not blobs:
            logger.info(f"No parquet files found for {source} on {execution_date}")
            return False

        processed = set()
        meta_blob = bucket.blob(metadata_blob_name)
        if meta_blob.exists():
            data = json.loads(meta_blob.download_as_text())
            processed = set(data.get("processed_files", []))

        new_files = [b for b in blobs if b not in processed]

        if not new_files:
            logger.info(f"All files already processed for {source} on {execution_date}")
            return False

        logger.info(
            f"{len(new_files)} new file(s) found for {source}. Proceeding with Spark."
        )
        return True

    except Exception:
        logger.error("Failure in should_process_source", exc_info=True)
        raise


# -------------------------------------------------------------------
# Helper: mark all files for that day as processed (AFTER Spark success)
# -------------------------------------------------------------------
def mark_files_processed(source: str, **context):
    try:
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-iam-proj")
        execution_date = context["ds_nodash"]
        prefix = f"source/{source}/{execution_date}"

        metadata_blob_name = f"metadata/{source}_processed.json"

        client = storage.Client()
        bucket = client.bucket(gcs_bucket)

        blobs = [
            b.name for b in bucket.list_blobs(prefix=prefix)
            if b.name.endswith(".parquet")
        ]

        if not blobs:
            logger.info("No files to mark as processed.")
            return

        processed = []
        meta_blob = bucket.blob(metadata_blob_name)
        if meta_blob.exists():
            processed = json.loads(meta_blob.download_as_text()).get("processed_files", [])

        updated = sorted(set(processed).union(set(blobs)))

        meta_blob.upload_from_string(
            json.dumps({"processed_files": updated}, indent=2),
            content_type="application/json",
        )

        logger.info(f"Marked {len(blobs)} files as processed for {source}")

    except Exception:
        logger.error("Failure in mark_files_processed", exc_info=True)
        raise


# -------------------------------------------------------------------
# DAG DEFINITION
# -------------------------------------------------------------------
default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 12, 14),
}

SOURCES = Variable.get(
    "sources",
    default_var=["okta", "ad", "saviynt", "app_usage", "hrlifecycle", "anomaly_key"],
    deserialize_json=True,
)

MAIN_PY_URI = "gs://{bucket}/spark-job/spark_transformation_job.py"

for source in SOURCES:
    dag_id = f"iam_{source}_ingest_dag"

    dag = DAG(
        dag_id=dag_id,
        default_args=default_args,
        schedule_interval="0 * * * *",
        catchup=False,
        max_active_runs=1,
        tags=["iam", "spark", source],
    )

    with dag:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-iam-proj")
        bq_project = Variable.get("bq_project")
        bq_dataset = Variable.get("bq_dataset", default_var=f"IAM_data_{env}")

        # 1️⃣ Sensor: wait for any files
        wait_for_files = GCSObjectsWithPrefixExistenceSensor(
            task_id=f"wait_for_files_{source}",
            bucket=gcs_bucket,
            prefix=f"source/{source}/{{{{ ds_nodash }}}}",
            poke_interval=60,
            timeout=900,
            mode="poke",
        )

        # 2️⃣ Decide if Spark should run
        gate = ShortCircuitOperator(
            task_id=f"should_run_{source}",
            python_callable=should_process_source,
            op_kwargs={"source": source},
        )

        # 3️⃣ Spark job (reads directly from GCS)
        spark_args = [
            f"--env={env}",
            f"--gcs_bucket={gcs_bucket}",
            f"--bq_project={bq_project}",
            f"--bq_dataset={bq_dataset}",
            f"--source={source}",
            "--write_method=direct",
        ]

        pyspark = DataprocCreateBatchOperator(
            task_id=f"run_spark_{source}",
            batch_id=f"iam-{source}-{{{{ ds_nodash }}}}-{uuid.uuid4().hex[:6]}",
            project_id=bq_project,
            region=Variable.get("dataproc_region", default_var="us-central1"),
            batch={
                "pyspark_batch": {
                    "main_python_file_uri": MAIN_PY_URI.format(bucket=gcs_bucket),
                    "args": spark_args,
                },
                "runtime_config": {"version": "2.2"},
            },
        )

        # 4️⃣ Mark processed (ONLY after Spark success)
        mark_done = PythonOperator(
            task_id=f"mark_done_{source}",
            python_callable=mark_files_processed,
            op_kwargs={"source": source},
            trigger_rule="all_success",
        )

        wait_for_files >> gate >> pyspark >> mark_done

    globals()[dag_id] = dag
