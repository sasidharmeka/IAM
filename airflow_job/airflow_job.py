from datetime import datetime, timedelta
import uuid
import json

from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import ShortCircuitOperator, PythonOperator
from airflow.providers.google.cloud.operators.dataproc import DataprocCreateBatchOperator
from airflow.providers.google.cloud.sensors.gcs import GCSObjectsWithPrefixExistenceSensor

from google.cloud import storage


def check_and_mark_file(source: str, **context):
    """Select exactly one unprocessed parquet for `source` and push to XCom.

    NOTE: this no longer marks the file as processed. Marking is deferred to
    a downstream task that runs after the Spark job succeeds so we don't
    skip files when Spark fails.

    Looks under: gs://{gcs_bucket}/source/{source}/{ds_nodash}-*.parquet
    Tracks processed files in: metadata/{source}_processed.json
    """
    env = Variable.get("env", default_var="dev")
    gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")

    execution_date = context["ds_nodash"]
    prefix = f"source/{source}/{execution_date}"

    metadata_blob_name = f"metadata/{source}_processed.json"

    client = storage.Client()
    bucket = client.bucket(gcs_bucket)

    candidates = [
        blob.name
        for blob in bucket.list_blobs(prefix=prefix)
        if blob.name.endswith(".parquet")
    ]

    if not candidates:
        print(f"No parquet files found under prefix: {prefix}")
        return False

    candidates.sort()
    selected_file = candidates[-1]
    print(f"Selected parquet file for {source}: {selected_file}")

    meta_blob = bucket.blob(metadata_blob_name)
    processed_files = []

    if meta_blob.exists():
        try:
            raw = meta_blob.download_as_text()
            data = json.loads(raw)
            if isinstance(data, dict) and "processed_files" in data:
                processed_files = data["processed_files"]
            elif isinstance(data, list):
                processed_files = data
            else:
                print("Warning: metadata format unexpected, treating as empty list.")
        except Exception as e:
            print(f"Warning: could not parse existing metadata: {e}")

    if selected_file in processed_files:
        print(f"{selected_file} already processed for {source}. Skipping Spark job.")
        return False

    # Do NOT mark processed here. Push selected file to XCom and allow downstream
    # tasks (the Spark job + a dedicated marker) to decide when to mark it.
    context["ti"].xcom_push(key="selected_file", value=selected_file)
    print(f"Selected {selected_file} for processing (will mark after Spark succeeds)")
    return True


def mark_file_processed(source: str, **context):
    """Append the selected file to metadata/{source}_processed.json after successful run."""
    env = Variable.get("env", default_var="dev")
    gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")

    ti = context["ti"]
    selected_file = ti.xcom_pull(task_ids=f"check_if_already_processed_{source}", key="selected_file")
    if not selected_file:
        print("No selected_file in XCom; nothing to mark.")
        return

    metadata_blob_name = f"metadata/{source}_processed.json"
    client = storage.Client()
    bucket = client.bucket(gcs_bucket)
    meta_blob = bucket.blob(metadata_blob_name)

    processed_files = []
    if meta_blob.exists():
        try:
            raw = meta_blob.download_as_text()
            data = json.loads(raw)
            if isinstance(data, dict) and "processed_files" in data:
                processed_files = data["processed_files"]
            elif isinstance(data, list):
                processed_files = data
        except Exception as e:
            print(f"Warning: could not parse existing metadata: {e}")

    if selected_file in processed_files:
        print(f"{selected_file} already present in metadata for {source}; nothing to do.")
        return

    processed_files.append(selected_file)
    out = json.dumps({"processed_files": processed_files}, indent=2)
    meta_blob.upload_from_string(out, content_type="application/json")
    print(f"Marked {selected_file} as processed in {metadata_blob_name}")


default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 12, 14),
}

SOURCES = Variable.get("sources", default_var=None, deserialize_json=True) or [
    "okta",
    "ad",
    "saviynt",
    "app_usage",
    "hrlifecycle",
    "anomaly_key",
]

MAIN_PY_URI = "gs://{bucket}/spark-job/spark_transformation_job.py"

for source in SOURCES:
    dag_id = f"iam_{source}_ingest_dag"
    dag = DAG(dag_id=dag_id, default_args=default_args, schedule_interval="0 * * * *", catchup=False)

    with dag:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
        bq_project = Variable.get("bq_project", default_var="authentic-codex-475613-p1")
        bq_dataset = Variable.get("bq_dataset", default_var=f"IAM_data_{env}")
        tables = Variable.get("tables", deserialize_json=True)

        write_method = Variable.get("write_method", default_var="direct")
        temp_gcs_bucket = Variable.get("temp_gcs_bucket", default_var="")

        impossible_table = tables.get("impossible_table", "impossible_login_anomalies")
        mfa_table = tables.get("mfa_table", "mfa_bypass_events")
        shadow_table = tables.get("shadow_table", "shadow_access_events")
        risk_table = tables.get("risk_table", "risk_scores")
        timeline_table = tables.get("timeline_table", "identity_timelines")
        # Additional tables from notebook detectors
        mfa_all_table = tables.get("mfa_all_table", "mfa_bypass_events_all_apps")
        impossible_travel_table = tables.get("impossible_travel_table", "impossible_travel_events")
        privilege_escalation_table = tables.get("privilege_escalation_table", "privilege_escalation_without_request")
        ad_volume_spike_table = tables.get("ad_volume_spike_table", "ad_volume_spikes")
        rejected_executed_table = tables.get("rejected_executed_table", "rejected_but_executed")
        high_risk_seq_table = tables.get("high_risk_seq_table", "high_risk_sequence")
        excessive_data_table = tables.get("excessive_data_table", "excessive_data_transferred")
        role_drift_table = tables.get("role_drift_table", "role_drift")
        stale_access_table = tables.get("stale_access_table", "stale_access")
        multi_app_session_table = tables.get("multi_app_session_table", "multi_app_single_session")
        mfa_drift_table = tables.get("mfa_drift_table", "mfa_drift")
        suspicious_approver_table = tables.get("suspicious_approver_table", "suspicious_approver_behavior")
        ad_churn_table = tables.get("ad_churn_table", "ad_group_churn_rate")
        orphan_event_table = tables.get("orphan_event_table", "orphan_event_detection")
        orphan_user_table = tables.get("orphan_user_table", "orphan_user_detection")
        cleanest_users_table = tables.get("cleanest_users_table", "cleanest_users")
        time_warp_table = tables.get("time_warp_table", "suspicious_time_warp")

        file_sensor = GCSObjectsWithPrefixExistenceSensor(
            task_id=f"check_file_arrival_{source}",
            bucket=gcs_bucket,
            prefix=f"source/{source}/{{{{ ds_nodash }}}}",
            google_cloud_conn_id="google_cloud_default",
            timeout=300,
            poke_interval=30,
            mode="poke",
        )

        check_new_file = ShortCircuitOperator(
            task_id=f"check_if_already_processed_{source}",
            python_callable=check_and_mark_file,
            op_kwargs={"source": source},
        )

        main_py_uri = MAIN_PY_URI.format(bucket=gcs_bucket)

        spark_args = [
            f"--env={env}",
            f"--gcs_bucket={gcs_bucket}",
            f"--bq_project={bq_project}",
            f"--bq_dataset={bq_dataset}",
            f"--input_file={{{{ ti.xcom_pull(task_ids='check_if_already_processed_{source}', key='selected_file') }}}}",
            f"--source={source}",
            f"--impossible_table={impossible_table}",
            f"--mfa_table={mfa_table}",
            f"--mfa_all_table={mfa_all_table}",
            f"--impossible_travel_table={impossible_travel_table}",
            f"--privilege_escalation_table={privilege_escalation_table}",
            f"--ad_volume_spike_table={ad_volume_spike_table}",
            f"--rejected_executed_table={rejected_executed_table}",
            f"--high_risk_seq_table={high_risk_seq_table}",
            f"--excessive_data_table={excessive_data_table}",
            f"--role_drift_table={role_drift_table}",
            f"--stale_access_table={stale_access_table}",
            f"--multi_app_session_table={multi_app_session_table}",
            f"--mfa_drift_table={mfa_drift_table}",
            f"--suspicious_approver_table={suspicious_approver_table}",
            f"--ad_churn_table={ad_churn_table}",
            f"--orphan_event_table={orphan_event_table}",
            f"--orphan_user_table={orphan_user_table}",
            f"--cleanest_users_table={cleanest_users_table}",
            f"--shadow_table={shadow_table}",
            f"--risk_table={risk_table}",
            f"--timeline_table={timeline_table}",
            f"--time_warp_table={time_warp_table}",
            f"--write_method={write_method}",
        ]

        if temp_gcs_bucket:
            spark_args.append(f"--temp_gcs_bucket={temp_gcs_bucket}")

        batch_details = {
            "pyspark_batch": {
                "main_python_file_uri": main_py_uri,
                "python_file_uris": [],
                "jar_file_uris": [],
                "args": spark_args,
            },
            "runtime_config": {"version": "2.2"},
            "environment_config": {
                "execution_config": {
                    "service_account": Variable.get("dataproc_service_account", default_var=""),
                    "network_uri": Variable.get("dataproc_network_uri", default_var=""),
                    "subnetwork_uri": Variable.get("dataproc_subnetwork_uri", default_var=""),
                }
            },
        }

        pyspark_task = DataprocCreateBatchOperator(
            task_id=f"run_spark_job_{source}",
            batch=batch_details,
            batch_id=f"IAM-batch-{source}-{str(uuid.uuid4())[:8]}",
            project_id=bq_project,
            region=Variable.get("dataproc_region", default_var="us-central1"),
            gcp_conn_id="google_cloud_default",
        )

        mark_task = PythonOperator(
            task_id=f"mark_processed_{source}",
            python_callable=mark_file_processed,
            op_kwargs={"source": source},
        )

        file_sensor >> check_new_file >> pyspark_task >> mark_task

    globals()[dag_id] = dag
