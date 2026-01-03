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
    # Print to stdout as well as logging (for debugging)
    print(f"=" * 80)
    print(f"Starting file check for source: {source}")
    print(f"=" * 80)
    
    logger.info(f"=" * 80)
    logger.info(f"Starting file check for source: {source}")
    logger.info(f"=" * 80)
    
    try:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
        
        print(f"Environment: {env}")
        print(f"GCS Bucket: {gcs_bucket}")
        logger.info(f"Environment: {env}")
        logger.info(f"GCS Bucket: {gcs_bucket}")

        execution_date = context.get("ds_nodash")
        if not execution_date:
            raise ValueError("ds_nodash not found in context")
            
        print(f"Execution date (ds_nodash): {execution_date}")
        logger.info(f"Execution date (ds_nodash): {execution_date}")
        
        prefix = f"source/{source}/{execution_date}"
        print(f"Searching for files with prefix: gs://{gcs_bucket}/{prefix}")
        logger.info(f"Searching for files with prefix: gs://{gcs_bucket}/{prefix}")

        metadata_blob_name = f"metadata/{source}_processed.json"
        print(f"Metadata file location: gs://{gcs_bucket}/{metadata_blob_name}")
        logger.info(f"Metadata file location: gs://{gcs_bucket}/{metadata_blob_name}")

        client = storage.Client()
        bucket = client.bucket(gcs_bucket)

        # List all blobs with the prefix
        print(f"Listing blobs in bucket with prefix: {prefix}")
        logger.info(f"Listing blobs in bucket with prefix: {prefix}")
        
        all_blobs = list(bucket.list_blobs(prefix=prefix))
        print(f"Total blobs found: {len(all_blobs)}")
        logger.info(f"Total blobs found: {len(all_blobs)}")
        
        # Log all files found (for debugging)
        for i, blob in enumerate(all_blobs):
            print(f"  Blob {i+1}: {blob.name}")
            logger.info(f"  Blob {i+1}: {blob.name}")

        candidates = [
            blob.name
            for blob in all_blobs
            if blob.name.endswith(".parquet")
        ]
        
        print(f"Parquet files found: {len(candidates)}")
        logger.info(f"Parquet files found: {len(candidates)}")
        
        for i, candidate in enumerate(candidates):
            print(f"  Candidate {i+1}: {candidate}")
            logger.info(f"  Candidate {i+1}: {candidate}")

        if not candidates:
            print(f"WARNING: No parquet files found under prefix: {prefix}")
            print(f"Expected file pattern: {prefix}-*.parquet or {prefix}/*.parquet")
            print("DAG will be skipped for this run")
            logger.warning(f"No parquet files found under prefix: {prefix}")
            logger.warning(f"Expected file pattern: {prefix}-*.parquet or {prefix}/*.parquet")
            logger.warning("DAG will be skipped for this run")
            return False

        candidates.sort()
        selected_file = candidates[-1]
        print(f"Selected file (last alphabetically): {selected_file}")
        logger.info(f"Selected file (last alphabetically): {selected_file}")

        # Check metadata
        meta_blob = bucket.blob(metadata_blob_name)
        processed_files = []

        if meta_blob.exists():
            print(f"Metadata file exists, loading processed files...")
            logger.info(f"Metadata file exists, loading processed files...")
            try:
                raw = meta_blob.download_as_text()
                print(f"Metadata content (first 500 chars): {raw[:500]}")
                logger.info(f"Metadata content (first 500 chars): {raw[:500]}")
                
                data = json.loads(raw)
                if isinstance(data, dict) and "processed_files" in data:
                    processed_files = data["processed_files"]
                elif isinstance(data, list):
                    processed_files = data
                else:
                    print(f"Warning: metadata format unexpected, treating as empty list.")
                    print(f"Metadata type: {type(data)}")
                    logger.warning("Warning: metadata format unexpected, treating as empty list.")
                    logger.warning(f"Metadata type: {type(data)}")
                
                print(f"Total processed files in metadata: {len(processed_files)}")
                logger.info(f"Total processed files in metadata: {len(processed_files)}")
                
                if len(processed_files) > 0:
                    print(f"Last 5 processed files: {processed_files[-5:]}")
                    logger.info(f"Last 5 processed files: {processed_files[-5:]}")
                
            except json.JSONDecodeError as e:
                print(f"JSON decode error in metadata: {e}")
                print(f"Raw metadata content: {raw}")
                logger.error(f"JSON decode error in metadata: {e}")
                logger.error(f"Raw metadata content: {raw}")
            except Exception as e:
                print(f"Error loading metadata: {e}")
                print(traceback.format_exc())
                logger.error(f"Error loading metadata: {e}", exc_info=True)
        else:
            print(f"Metadata file does not exist yet: {metadata_blob_name}")
            print("This appears to be the first run for this source")
            logger.info(f"Metadata file does not exist yet: {metadata_blob_name}")
            logger.info("This appears to be the first run for this source")

        # Check if already processed
        if selected_file in processed_files:
            print(f"WARNING: File already processed: {selected_file}")
            print(f"This file is in the processed list. Skipping Spark job.")
            logger.warning(f"File already processed: {selected_file}")
            logger.warning(f"This file is in the processed list. Skipping Spark job.")
            return False

        # Push to XCom
        ti = context.get("ti")
        if not ti:
            raise ValueError("Task Instance (ti) not found in context")
            
        ti.xcom_push(key="selected_file", value=selected_file)
        print(f"✓ File pushed to XCom: {selected_file}")
        print(f"XCom key: 'selected_file'")
        print(f"Proceeding to Spark job...")
        print(f"=" * 80)
        logger.info(f"✓ File pushed to XCom: {selected_file}")
        logger.info(f"XCom key: 'selected_file'")
        logger.info(f"Proceeding to Spark job...")
        logger.info(f"=" * 80)
        
        return True
        
    except Exception as e:
        print(f"FATAL ERROR in check_and_mark_file: {e}")
        print(f"Full traceback:")
        print(traceback.format_exc())
        print(f"Source: {source}")
        print(f"Context keys: {list(context.keys())}")
        logger.error(f"FATAL ERROR in check_and_mark_file: {e}", exc_info=True)
        logger.error(f"Source: {source}")
        logger.error(f"Context keys: {list(context.keys())}")
        raise


def mark_file_processed(source: str, **context):
    """Append the selected file to metadata/{source}_processed.json after successful run."""
    print(f"=" * 80)
    print(f"Marking file as processed for source: {source}")
    print(f"=" * 80)
    logger.info(f"=" * 80)
    logger.info(f"Marking file as processed for source: {source}")
    logger.info(f"=" * 80)
    
    try:
        env = Variable.get("env", default_var="dev")
        gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
        
        print(f"Environment: {env}")
        print(f"GCS Bucket: {gcs_bucket}")
        logger.info(f"Environment: {env}")
        logger.info(f"GCS Bucket: {gcs_bucket}")

        ti = context.get("ti")
        if not ti:
            raise ValueError("Task Instance (ti) not found in context")
        
        # Pull from XCom
        selected_file = ti.xcom_pull(
            task_ids=f"check_if_already_processed_{source}", 
            key="selected_file"
        )
        
        print(f"XCom pull result: {selected_file}")
        logger.info(f"XCom pull result: {selected_file}")
        
        if not selected_file:
            print("WARNING: No selected_file in XCom; nothing to mark.")
            print("This could mean the check task returned False or failed")
            logger.warning("No selected_file in XCom; nothing to mark.")
            logger.warning("This could mean the check task returned False or failed")
            return

        print(f"File to mark as processed: {selected_file}")
        logger.info(f"File to mark as processed: {selected_file}")

        metadata_blob_name = f"metadata/{source}_processed.json"
        print(f"Metadata file: gs://{gcs_bucket}/{metadata_blob_name}")
        logger.info(f"Metadata file: gs://{gcs_bucket}/{metadata_blob_name}")
        
        client = storage.Client()
        bucket = client.bucket(gcs_bucket)
        meta_blob = bucket.blob(metadata_blob_name)

        processed_files = []
        if meta_blob.exists():
            print("Loading existing metadata...")
            logger.info("Loading existing metadata...")
            try:
                raw = meta_blob.download_as_text()
                data = json.loads(raw)
                if isinstance(data, dict) and "processed_files" in data:
                    processed_files = data["processed_files"]
                elif isinstance(data, list):
                    processed_files = data
                print(f"Existing processed files count: {len(processed_files)}")
                logger.info(f"Existing processed files count: {len(processed_files)}")
            except Exception as e:
                print(f"Error parsing existing metadata: {e}")
                print(traceback.format_exc())
                logger.error(f"Error parsing existing metadata: {e}", exc_info=True)
        else:
            print("No existing metadata file, creating new one")
            logger.info("No existing metadata file, creating new one")

        # Double-check before appending
        if selected_file in processed_files:
            print(f"WARNING: File already in metadata: {selected_file}")
            print("Not adding duplicate entry")
            logger.warning(f"File already in metadata: {selected_file}")
            logger.warning("Not adding duplicate entry")
            return

        # Append and save
        processed_files.append(selected_file)
        out = json.dumps({"processed_files": processed_files}, indent=2)
        
        print(f"Uploading updated metadata with {len(processed_files)} files")
        logger.info(f"Uploading updated metadata with {len(processed_files)} files")
        meta_blob.upload_from_string(out, content_type="application/json")
        
        print(f"✓ Successfully marked as processed: {selected_file}")
        print(f"Total files now in metadata: {len(processed_files)}")
        print(f"=" * 80)
        logger.info(f"✓ Successfully marked as processed: {selected_file}")
        logger.info(f"Total files now in metadata: {len(processed_files)}")
        logger.info(f"=" * 80)
        
    except Exception as e:
        print(f"FATAL ERROR in mark_file_processed: {e}")
        print(f"Full traceback:")
        print(traceback.format_exc())
        print(f"Source: {source}")
        logger.error(f"FATAL ERROR in mark_file_processed: {e}", exc_info=True)
        logger.error(f"Source: {source}")
        raise


def log_spark_job_start(source: str, **context):
    """Log when Spark job is about to start with all parameters."""
    print(f"=" * 80)
    print(f"SPARK JOB STARTING for source: {source}")
    print(f"=" * 80)
    logger.info(f"=" * 80)
    logger.info(f"SPARK JOB STARTING for source: {source}")
    logger.info(f"=" * 80)
    
    ti = context.get("ti")
    if not ti:
        print("ERROR: Task Instance (ti) not found in context")
        logger.error("Task Instance (ti) not found in context")
        return
        
    selected_file = ti.xcom_pull(
        task_ids=f"check_if_already_processed_{source}", 
        key="selected_file"
    )
    
    print(f"Input file: {selected_file}")
    print(f"Execution date: {context.get('ds', 'NOT_FOUND')}")
    print(f"Execution date (nodash): {context.get('ds_nodash', 'NOT_FOUND')}")
    print(f"=" * 80)
    logger.info(f"Input file: {selected_file}")
    logger.info(f"Execution date: {context.get('ds', 'NOT_FOUND')}")
    logger.info(f"Execution date (nodash): {context.get('ds_nodash', 'NOT_FOUND')}")
    logger.info(f"=" * 80)


default_args = {
    "owner": "airflow",
    "depends_on_past": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
    "start_date": datetime(2024, 12, 14),
    "email_on_failure": False,
    "email_on_retry": False,
}

# Get sources with proper error handling
try:
    SOURCES = Variable.get("sources", default_var=None, deserialize_json=True)
    if not SOURCES:
        SOURCES = ["okta", "ad", "saviynt", "app_usage", "hrlifecycle", "anomaly_key"]
        print(f"WARNING: 'sources' variable not found, using defaults: {SOURCES}")
except Exception as e:
    SOURCES = ["okta", "ad", "saviynt", "app_usage", "hrlifecycle", "anomaly_key"]
    print(f"ERROR getting sources variable: {e}, using defaults: {SOURCES}")

MAIN_PY_URI = "gs://{bucket}/spark-job/spark_transformation_job.py"

print(f"Creating DAGs for sources: {SOURCES}")
logger.info(f"Creating DAGs for sources: {SOURCES}")

for source in SOURCES:
    dag_id = f"iam_{source}_ingest_dag"
    print(f"Creating DAG: {dag_id}")
    logger.info(f"Creating DAG: {dag_id}")
    
    try:
        dag = DAG(
            dag_id=dag_id, 
            default_args=default_args, 
            schedule_interval="0 * * * *", 
            catchup=False,
            max_active_runs=1,
            tags=["iam", "ingest", source],
        )

        with dag:
            env = Variable.get("env", default_var="dev")
            gcs_bucket = Variable.get("gcs_bucket", default_var="airflow-IAM-proj")
            bq_project = Variable.get("bq_project", default_var="authentic-codex-475613-p1")
            bq_dataset = Variable.get("bq_dataset", default_var=f"IAM_data_{env}")
            
            # Get tables with SAFE error handling
            tables = {}
            try:
                tables = Variable.get("tables", deserialize_json=True)
                if not isinstance(tables, dict):
                    print(f"WARNING: 'tables' variable is not a dict, using empty dict")
                    tables = {}
            except Exception as e:
                print(f"WARNING: Could not load 'tables' variable: {e}, using defaults")

            write_method = Variable.get("write_method", default_var="direct")
            temp_gcs_bucket = Variable.get("temp_gcs_bucket", default_var="")

            # Table mappings with defaults
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

            # File sensor
            file_sensor = GCSObjectsWithPrefixExistenceSensor(
                task_id=f"check_file_arrival_{source}",
                bucket=gcs_bucket,
                prefix=f"source/{source}/{{{{ ds_nodash }}}}",
                google_cloud_conn_id="google_cloud_default",
                timeout=600,
                poke_interval=60,
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
                batch_id=f"iam-batch-{source}-{{{{ ds_nodash }}}}-{str(uuid.uuid4())[:8]}",
                project_id=bq_project,
                region=Variable.get("dataproc_region", default_var="us-central1"),
                gcp_conn_id="google_cloud_default",
            )

            # Mark file as processed
            mark_task = PythonOperator(
                task_id=f"mark_processed_{source}",
                python_callable=mark_file_processed,
                op_kwargs={"source": source},
                trigger_rule="all_success",
            )

            # Define task dependencies..s
            file_sensor >> check_new_file >> log_spark_start >> pyspark_task >> mark_task

        globals()[dag_id] = dag
        print(f"✓ Successfully created DAG: {dag_id}")
        logger.info(f"✓ Successfully created DAG: {dag_id}")
        
    except Exception as e:
        print(f"ERROR creating DAG {dag_id}: {e}")
        print(traceback.format_exc())
        logger.error(f"ERROR creating DAG {dag_id}: {e}", exc_info=True)

print(f"Finished creating {len(SOURCES)} DAGs")
logger.info(f"Finished creating {len(SOURCES)} DAGs")