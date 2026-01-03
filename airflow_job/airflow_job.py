from datetime import datetime, timedelta
import uuid
import json
import logging

from airflow import DAG
from airflow.models import Variable
from airflow.operators.python import ShortCircuitOperator, PythonOperator
from airflow.providers.google.cloud.operators.dataproc import DataprocCreateBatchOperator
from airflow.providers.google.cloud.sensors.gcs import GCSObjectsWithPrefixExistenceSensor
from airflow.exceptions import AirflowSkipException

from google.cloud import storage

# Configure logging
logger = logging.getLogger(__name__)


def check_and_mark_file(source: str, **context):
    """Select exactly one unprocessed parquet for `source` and push to XCom.

    NOTE: this no longer marks the file as processed. Marking is deferred to
    a downstream task that runs after the Spark job succeeds so we don't
    skip files when Spark fails.

    Looks under: gs://{gcs_bucket}/source/{source}/{ds_nodash}-*.parquet
    Tracks processed files in: metadata/{source}_processed.json
    """
    logger.info(f"=" * 80)
    logger.info(f"Starting file check for source: {source}")
    logger.info(f"=" * 80)
    
    try:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
        
        logger.info(f"Environment: {env}")
        logger.info(f"GCS Bucket: {gcs_bucket}")

        execution_date = context["ds_nodash"]
        logger.info(f"Execution date (ds_nodash): {execution_date}")
        
        prefix = f"source/{source}/{execution_date}"
        logger.info(f"Searching for files with prefix: gs://{gcs_bucket}/{prefix}")

        metadata_blob_name = f"metadata/{source}_processed.json"
        logger.info(f"Metadata file location: gs://{gcs_bucket}/{metadata_blob_name}")

        client = storage.Client()
        bucket = client.bucket(gcs_bucket)

        # List all blobs with the prefix
        logger.info(f"Listing blobs in bucket with prefix: {prefix}")
        all_blobs = list(bucket.list_blobs(prefix=prefix))
        logger.info(f"Total blobs found: {len(all_blobs)}")
        
        # Log all files found (for debugging)
        for blob in all_blobs:
            logger.info(f"  Found blob: {blob.name}")

        candidates = [
            blob.name
            for blob in all_blobs
            if blob.name.endswith(".parquet")
        ]
        
        logger.info(f"Parquet files found: {len(candidates)}")
        for candidate in candidates:
            logger.info(f"  Candidate: {candidate}")

        if not candidates:
            logger.warning(f"No parquet files found under prefix: {prefix}")
            logger.warning(f"Expected file pattern: {prefix}-*.parquet or {prefix}/*.parquet")
            logger.warning("DAG will be skipped for this run")
            return False

        candidates.sort()
        selected_file = candidates[-1]
        logger.info(f"Selected file (last alphabetically): {selected_file}")

        # Check metadata
        meta_blob = bucket.blob(metadata_blob_name)
        processed_files = []

        if meta_blob.exists():
            logger.info(f"Metadata file exists, loading processed files...")
            try:
                raw = meta_blob.download_as_text()
                logger.info(f"Metadata content (first 500 chars): {raw[:500]}")
                
                data = json.loads(raw)
                if isinstance(data, dict) and "processed_files" in data:
                    processed_files = data["processed_files"]
                elif isinstance(data, list):
                    processed_files = data
                else:
                    logger.warning("Warning: metadata format unexpected, treating as empty list.")
                    logger.warning(f"Metadata type: {type(data)}")
                
                logger.info(f"Total processed files in metadata: {len(processed_files)}")
                logger.info(f"Last 5 processed files: {processed_files[-5:] if len(processed_files) >= 5 else processed_files}")
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error in metadata: {e}")
                logger.error(f"Raw metadata content: {raw}")
            except Exception as e:
                logger.error(f"Error loading metadata: {e}", exc_info=True)
        else:
            logger.info(f"Metadata file does not exist yet: {metadata_blob_name}")
            logger.info("This appears to be the first run for this source")

        # Check if already processed
        if selected_file in processed_files:
            logger.warning(f"File already processed: {selected_file}")
            logger.warning(f"This file is in the processed list. Skipping Spark job.")
            return False

        # Push to XCom
        context["ti"].xcom_push(key="selected_file", value=selected_file)
        logger.info(f"✓ File pushed to XCom: {selected_file}")
        logger.info(f"XCom key: 'selected_file'")
        logger.info(f"Proceeding to Spark job...")
        logger.info(f"=" * 80)
        
        return True
        
    except Exception as e:
        logger.error(f"FATAL ERROR in check_and_mark_file: {e}", exc_info=True)
        logger.error(f"Source: {source}")
        logger.error(f"Context keys: {context.keys()}")
        raise


def mark_file_processed(source: str, **context):
    """Append the selected file to metadata/{source}_processed.json after successful run."""
    logger.info(f"=" * 80)
    logger.info(f"Marking file as processed for source: {source}")
    logger.info(f"=" * 80)
    
    try:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
        
        logger.info(f"Environment: {env}")
        logger.info(f"GCS Bucket: {gcs_bucket}")

        ti = context["ti"]
        
        # Pull from XCom
        selected_file = ti.xcom_pull(
            task_ids=f"check_if_already_processed_{source}", 
            key="selected_file"
        )
        
        logger.info(f"XCom pull result: {selected_file}")
        
        if not selected_file:
            logger.warning("No selected_file in XCom; nothing to mark.")
            logger.warning("This could mean the check task returned False or failed")
            return

        logger.info(f"File to mark as processed: {selected_file}")

        metadata_blob_name = f"metadata/{source}_processed.json"
        logger.info(f"Metadata file: gs://{gcs_bucket}/{metadata_blob_name}")
        
        client = storage.Client()
        bucket = client.bucket(gcs_bucket)
        meta_blob = bucket.blob(metadata_blob_name)

        processed_files = []
        if meta_blob.exists():
            logger.info("Loading existing metadata...")
            try:
                raw = meta_blob.download_as_text()
                data = json.loads(raw)
                if isinstance(data, dict) and "processed_files" in data:
                    processed_files = data["processed_files"]
                elif isinstance(data, list):
                    processed_files = data
                logger.info(f"Existing processed files count: {len(processed_files)}")
            except Exception as e:
                logger.error(f"Error parsing existing metadata: {e}", exc_info=True)
        else:
            logger.info("No existing metadata file, creating new one")

        # Double-check before appending
        if selected_file in processed_files:
            logger.warning(f"File already in metadata: {selected_file}")
            logger.warning("Not adding duplicate entry")
            return

        # Append and save
        processed_files.append(selected_file)
        out = json.dumps({"processed_files": processed_files}, indent=2)
        
        logger.info(f"Uploading updated metadata with {len(processed_files)} files")
        meta_blob.upload_from_string(out, content_type="application/json")
        
        logger.info(f"✓ Successfully marked as processed: {selected_file}")
        logger.info(f"Total files now in metadata: {len(processed_files)}")
        logger.info(f"=" * 80)
        
    except Exception as e:
        logger.error(f"FATAL ERROR in mark_file_processed: {e}", exc_info=True)
        logger.error(f"Source: {source}")
        raise


def log_spark_job_start(source: str, **context):
    """Log when Spark job is about to start with all parameters."""
    logger.info(f"=" * 80)
    logger.info(f"SPARK JOB STARTING for source: {source}")
    logger.info(f"=" * 80)
    
    ti = context["ti"]
    selected_file = ti.xcom_pull(
        task_ids=f"check_if_already_processed_{source}", 
        key="selected_file"
    )
    
    logger.info(f"Input file: {selected_file}")
    logger.info(f"Execution date: {context['ds']}")
    logger.info(f"Execution date (nodash): {context['ds_nodash']}")
    logger.info(f"=" * 80)


default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "retries": 2,  # Increased retries
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 12, 14),
    "email_on_failure": False,  # Set to True and add emails if needed
    "email_on_retry": False,
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

logger.info(f"Creating DAGs for sources: {SOURCES}")

for source in SOURCES:
    dag_id = f"iam_{source}_ingest_dag"
    logger.info(f"Creating DAG: {dag_id}")
    
    dag = DAG(
        dag_id=dag_id, 
        default_args=default_args, 
        schedule_interval="0 * * * *", 
        catchup=False,
        max_active_runs=1,  # Prevent parallel runs
        tags=["iam", "ingest", source],  # Add tags for better organization
    )

    with dag:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
        bq_project = Variable.get("bq_project", default_var="authentic-codex-475613-p1")
        bq_dataset = Variable.get("bq_dataset", default_var=f"IAM_data_{env}")
        
        # Get tables with error handling
        try:
            tables = Variable.get("tables", deserialize_json=True)
        except Exception as e:
            logger.warning(f"Could not load tables variable: {e}, using defaults")
            tables = {}

        write_method = Variable.get("write_method", default_var="direct")
        temp_gcs_bucket = Variable.get("temp_gcs_bucket", default_var="")

        # Table mappings
        impossible_table = tables.get("impossible_table", "impossible_login_anomalies")
        mfa_table = tables.get("mfa_table", "mfa_bypass_events")
        shadow_table = tables.get("shadow_table", "shadow_access_events")
        risk_table = tables.get("risk_table", "risk_scores")
        timeline_table = tables.get("timeline_table", "identity_timelines")
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

        # File sensor with longer timeout and better logging
        file_sensor = GCSObjectsWithPrefixExistenceSensor(
            task_id=f"check_file_arrival_{source}",
            bucket=gcs_bucket,
            prefix=f"source/{source}/{{{{ ds_nodash }}}}",
            google_cloud_conn_id="google_cloud_default",
            timeout=600,  # Increased to 10 minutes
            poke_interval=60,  # Check every minute instead of 30 seconds
            mode="poke",
        )

        # Check for new files
        check_new_file = ShortCircuitOperator(
            task_id=f"check_if_already_processed_{source}",
            python_callable=check_and_mark_file,
            op_kwargs={"source": source},
        )

        # Log before Spark job
        log_spark_start = PythonOperator(
            task_id=f"log_spark_start_{source}",
            python_callable=log_spark_job_start,
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
            batch_id=f"IAM-batch-{source}-{{{{ ds_nodash }}}}-{str(uuid.uuid4())[:8]}",  # Include date for easier tracking
            project_id=bq_project,
            region=Variable.get("dataproc_region", default_var="us-central1"),
            gcp_conn_id="google_cloud_default",
        )

        # Mark file as processed
        mark_task = PythonOperator(
            task_id=f"mark_processed_{source}",
            python_callable=mark_file_processed,
            op_kwargs={"source": source},
            trigger_rule="all_success",  # Only mark if Spark job succeeded
        )

        # Define task dependencies
        file_sensor >> check_new_file >> log_spark_start >> pyspark_task >> mark_task

    globals()[dag_id] = dag

logger.info(f"Successfully created {len(SOURCES)} DAGs")