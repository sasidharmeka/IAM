<!-- Copilot / AI agent instructions for the IAM PySpark repo -->

# Quick orientation

This repository implements a small data pipeline: Pub/Sub producer -> Pub/Sub consumer -> GCS (parquet) -> Airflow sensor -> Dataproc Serverless Spark job -> BigQuery. Key entrypoints and integrations are listed below so an AI agent can be productive immediately.

## Big picture (core flow)
- Producer: publishes JSON messages to a Pub/Sub topic from CSV ([producer.py](producer.py)).
- Consumer: pulls from Pub/Sub, batches messages into a Parquet file and uploads to GCS under `source-<BRANCH>/<timestamp>-data.parquet` ([consumer.py](consumer.py)).
- Airflow: `airflow_job/airflow_job.py` watches GCS by prefix, checks `metadata/processed_files.json`, and triggers a Dataproc Serverless batch when a new file is detected.
- Spark job: `spark_jobs/spark_transformation_job.py` reads `gs://{gcs_bucket}/source-{env}/*.parquet`, transforms, and appends results to BigQuery tables using either `direct` or `indirect` write methods.

## Important files to inspect
- [producer.py](producer.py) — CLI publisher; expects `PROJECT_ID` and `TOPIC_ID` env vars.
- [consumer.py](consumer.py) — long-running puller; expects `PROJECT_ID`, `BUCKET_NAME`, and `SUBSCRIPTION_ID` / `SUBSCRIPTION_FULL`.
- [spark_jobs/spark_transformation_job.py](spark_jobs/spark_transformation_job.py) — Spark transforms and BigQuery writes. Observe `--write_method` behavior and `temporaryGcsBucket` usage.
- [airflow_job/airflow_job.py](airflow_job/airflow_job.py) — Airflow DAG; variables read from Airflow `Variable` and metadata handling for `metadata/processed_files.json`.
- `variables/dev/variables.json` and `variables/prod/variables.json` — example variable maps for Airflow (tables, dataset names).

## Project-specific conventions & patterns
- GCS layout: source files are uploaded to `gs://<bucket>/source-<env>/<timestamp>-data.parquet`. Airflow sensors use prefix `source-<env>/{ds_nodash}-` to detect runs.
- Metadata: Airflow writes `metadata/processed_files.json` (either a list or an object with `processed_files`) to avoid re-processing files — preserve this pattern when modifying ingestion semantics.
- BigQuery writes: Spark uses `.mode('append')` and `writeDisposition=WRITE_APPEND` plus `schemaUpdateOptions=ALLOW_FIELD_ADDITION,ALLOW_FIELD_RELAXATION` to allow gentle schema evolution.
- `write_method` semantics: `indirect` requires a `temp_gcs_bucket`; otherwise the job falls back to `direct` and logs a warning. Keep this behavior if adding new write options.
- Local output: `consumer.py` prefers the Windows OneDrive workspace path when present (`C:\Users\sasi0\OneDrive\Desktop\IAM PySpark`) — tests and local runs will write there by default.

## Dev / debug workflows (concrete commands)
- Publish sample messages locally:

  PROJECT_ID=your-project TOPIC_ID=topic-id python producer.py

- Run the consumer locally (writes parquet and uploads to GCS):

  PROJECT_ID=your-project BUCKET_NAME=your-bucket SUBSCRIPTION_ID=sub-id python consumer.py

- Run the Spark job locally (requires pyspark and BigQuery connector):

  python spark_jobs/spark_transformation_job.py \
    --env=dev \
    --gcs_bucket=my-bucket \
    --bq_project=my-project \
    --bq_dataset=IAM_data_dev \
    --transformed_table=transformed \
    --route_insights_table=route_insights \
    --origin_insights_table=origin_insights \
    --route_summarization_table=route_summary \
    --sales_summarization_table=sales_summary \
    --input_format=parquet --write_method=direct

Note: local Spark runs need the `spark-bigquery` connector and proper GCP credentials; running the job in Dataproc is the primary CI/production path.

## External dependencies & integration points
- Google Cloud Pub/Sub — `producer.py`, `consumer.py`.
- Google Cloud Storage — `consumer.py` uploads; `airflow_job.py` reads/writes metadata and Spark reads via `gs://` paths.
- Dataproc Serverless / Spark BigQuery connector — invoked by Airflow DAG in `airflow_job/airflow_job.py`.
- BigQuery — final sinks; expect `WRITE_APPEND` semantics and schema evolution options.

## Environment variables & Airflow variables to be aware of
- Environment variables used by scripts: `PROJECT_ID`, `TOPIC_ID`, `BUCKET_NAME`, `SUBSCRIPTION_ID` / `SUBSCRIPTION_FULL`, `BRANCH`, `PARQUET_ROW_GROUP`, etc. See top of `consumer.py` for full list.
- Airflow variables used in `airflow_job/airflow_job.py`: `env`, `gcs_bucket`, `bq_project`, `bq_dataset`, `tables` (JSON), `input_format`, `write_method`, `temp_gcs_bucket`.

## When editing / adding features — quick checks an agent should do
- Maintain the `source-<env>/` naming and timestamped filenames to keep Airflow sensor compatibility.
- If changing BigQuery write behavior, update both the Spark CLI help and `airflow_job.py` to pass matching `--write_method` semantics.
- Preserve use of `metadata/processed_files.json` or migrate thoughtfully (update DAG and sensor behavior accordingly).

If anything above is unclear or you want more detail on CI, secrets handling, or Dataproc runtime config, tell me which area to expand. 
