from datetime import datetime, timedelta
import uuid
import json

from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import PythonOperator
from airflow.exceptions import AirflowSkipException
from airflow.providers.google.cloud.operators.dataproc import DataprocCreateBatchOperator
from airflow.providers.google.cloud.sensors.gcs import GCSObjectsWithPrefixExistenceSensor

from google.cloud import storage


# -------------------------------------------------------------------
# FILE SELECTION (NO SHORT CIRCUIT OPERATOR)
# -------------------------------------------------------------------
def check_and_select_file(source: str, **context):
    """
    Select exactly one unprocessed parquet file for a source.
    Pushes the selected file to XCom.
    Raises AirflowSkipException if nothing to process.
    """
    gcs_bucket = Variable.get("gcs_bucket")
    execution_date = context["ds_nodash"]
    prefix = f"source/{source}/{execution_date}"

    client = storage.Client()
    bucket = client.bucket(gcs_bucket)

    candidates = sorted(
        blob.name
        for blob in bucket.list_blobs(prefix=prefix)
        if blob.name.endswith(".parquet")
    )

    if not candidates:
        raise AirflowSkipException(f"No parquet files found for {source} on {execution_date}")

    selected_file = candidates[-1]

    meta_blob = bucket.blob(f"metadata/{source}_processed.json")
    processed = []

    if meta_blob.exists():
        processed = json.loads(meta_blob.download_as_text()).get("processed_files", [])

    if selected_file in processed:
        raise AirflowSkipException(f"{selected_file} already processed")

    context["ti"].xcom_push(key="selected_file", value=selected_file)
    print(f"Selected parquet file: {selected_file}")


# -------------------------------------------------------------------
# MARK FILE AS PROCESSED (AFTER SPARK SUCCESS)
# -------------------------------------------------------------------
def mark_file_processed(source: str, **context):
    gcs_bucket = Variable.get("gcs_bucket")
    ti = context["ti"]
    selected_file = ti.xcom_pull(
        task_ids=f"select_file_{source}",
        key="selected_file"
    )

    if not selected_file:
        print("No file to mark.")
        return

    client = storage.Client()
    bucket = client.bucket(gcs_bucket)
    meta_blob = bucket.blob(f"metadata/{source}_processed.json")

    processed = []
    if meta_blob.exists():
        processed = json.loads(meta_blob.download_as_text()).get("processed_files", [])

    if selected_file not in processed:
        processed.append(selected_file)
        meta_blob.upload_from_string(
            json.dumps({"processed_files": processed}, indent=2),
            content_type="application/json",
        )
        print(f"Marked {selected_file} as processed.")


# -------------------------------------------------------------------
# DAG CONFIG
# -------------------------------------------------------------------
default_args = {
    "owner": "airflow",
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 12, 14),
}

SOURCES = Variable.get(
    "sources",
    default_var=["okta", "ad", "saviynt", "app_usage", "hrlifecycle"],
    deserialize_json=True,
)

MAIN_PY_URI = "gs://{bucket}/spark-job/spark_transformation_job.py"


# -------------------------------------------------------------------
# DAG PER SOURCE
# -------------------------------------------------------------------
for source in SOURCES:
    dag_id = f"iam_{source}_ingest_dag"

    with DAG(
        dag_id=dag_id,
        default_args=default_args,
        schedule_interval="0 * * * *",
        catchup=False,
        tags=["iam", source],
    ) as dag:

        env = Variable.get("env")
        gcs_bucket = Variable.get("gcs_bucket")
        bq_project = Variable.get("bq_project")
        bq_dataset = Variable.get("bq_dataset")
        tables = Variable.get("tables", deserialize_json=True)

        # ------------------------------------------------------------
        # SENSOR
        # ------------------------------------------------------------
        wait_for_file = GCSObjectsWithPrefixExistenceSensor(
            task_id=f"wait_for_file_{source}",
            bucket=gcs_bucket,
            prefix=f"source/{source}/{{{{ ds_nodash }}}}",
            poke_interval=30,
            timeout=300,
            mode="poke",
        )

        # ------------------------------------------------------------
        # FILE SELECTION
        # ------------------------------------------------------------
        select_file = PythonOperator(
            task_id=f"select_file_{source}",
            python_callable=check_and_select_file,
            op_kwargs={"source": source},
        )

        # ------------------------------------------------------------
        # SPARK JOB
        # ------------------------------------------------------------
        spark_args = [
            "--env={{ var.value.env }}",
            "--gcs_bucket={{ var.value.gcs_bucket }}",
            "--bq_project={{ var.value.bq_project }}",
            "--bq_dataset={{ var.value.bq_dataset }}",
            "--input_file={{ ti.xcom_pull(task_ids='select_file_" + source + "', key='selected_file') }}",
            f"--source={source}",
            f"--impossible_table={tables['impossible_table']}",
            f"--mfa_table={tables['mfa_table']}",
            f"--shadow_table={tables['shadow_table']}",
            f"--risk_table={tables['risk_table']}",
            f"--timeline_table={tables['timeline_table']}",
        ]

        batch = {
            "pyspark_batch": {
                "main_python_file_uri": MAIN_PY_URI.format(bucket=gcs_bucket),
                "args": spark_args,
            },
            "runtime_config": {"version": "2.2"},
        }

        run_spark = DataprocCreateBatchOperator(
            task_id=f"run_spark_{source}",
            batch=batch,
            batch_id=f"iam-{source}-{uuid.uuid4().hex[:8]}",
            project_id=bq_project,
            region=Variable.get("dataproc_region", "us-central1"),
        )

        # ------------------------------------------------------------
        # MARK PROCESSED
        # ------------------------------------------------------------
        mark_processed = PythonOperator(
            task_id=f"mark_processed_{source}",
            python_callable=mark_file_processed,
            op_kwargs={"source": source},
        )

        # ------------------------------------------------------------
        # DAG FLOW
        # ------------------------------------------------------------
        wait_for_file >> select_file >> run_spark >> mark_processed

    globals()[dag_id] = dag
