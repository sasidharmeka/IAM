IAM PySpark Pipeline
=====================

Overview
--------
This repository implements a small IAM-focused batch pipeline:
- Producer -> Pub/Sub -> Consumer writes Parquet to GCS under `gs://{bucket}/source/{source}/{timestamp}-data.parquet`.
- Airflow per-source DAGs detect new files, mark them in `metadata/{source}_processed.json`, then launch a Dataproc Serverless PySpark batch.
- The Spark job (`spark_jobs/spark_transformation_job.py`) accepts a single `--input_file` (or a `--source` prefix), runs ~20 IAM detection functions (impossible logins, MFA bypasses, shadow access, risk scores, timelines, etc.) and writes Gold tables to BigQuery.

Key files
---------
- `spark_jobs/spark_transformation_job.py` — Spark entrypoint, CLI contract and BigQuery writes.
- `airflow_job/airflow_job.py` — DAG factory creating `iam_<source>_ingest_dag` for each source; selects one unprocessed file and passes it via XCom.
- `consumer.py` — Pub/Sub consumer that writes parquet to `source/<source>/` (or fallback `source/<branch>/`).
- `variables/dev/variables.json`, `variables/prod/variables.json` — example Airflow variables mapping BigQuery table names.

BigQuery tables produced
-----------------------
(These are the `tables` keys used by the DAG -> Spark args)
- impossible_table
- mfa_table
- mfa_all_table
- impossible_travel_table
- privilege_escalation_table
- ad_volume_spike_table
- rejected_executed_table
- high_risk_seq_table
- excessive_data_table
- role_drift_table
- stale_access_table
- multi_app_session_table
- mfa_drift_table
- suspicious_approver_table
- ad_churn_table
- orphan_event_table
- orphan_user_table
- cleanest_users_table
- shadow_table
- risk_table
- timeline_table
- time_warp_table

Quick deployment checklist
-------------------------
1. Upload Spark job to GCS (used by Airflow):

```bash
# run from repo root
GS_BUCKET=your-bucket
gsutil cp spark_jobs/spark_transformation_job.py gs://$GS_BUCKET/spark-job/spark_transformation_job.py
```

2. Set Airflow Variables (import `variables/dev/variables.json` or `variables/prod/variables.json`) — ensure `tables` JSON contains the keys above.
3. Ensure service accounts and permissions:
   - Airflow SA: GCS list/read/write for `source/*` and `metadata/*`.
   - Dataproc SA: BigQuery write + GCS access.
   - CI/deploy SA: permission to upload objects to target bucket (if using CI).

Smoke test
----------
1. Upload a small Parquet to the dev bucket:
```bash
gsutil cp test.parquet gs://$GS_BUCKET/source/okta/20250101-test-data.parquet
```
2. Trigger `iam_okta_ingest_dag` in Airflow UI or via CLI and watch logs until Dataproc batch completes.
3. Verify the expected BigQuery tables have appended rows.

CI / GitHub Actions
-------------------
- The DAG expects `gs://{gcs_bucket}/spark-job/spark_transformation_job.py`. Ensure your CI uploads this file during releases.
- Store the service account key in GitHub Secrets (e.g., `GCP_SA_KEY`) and provide required repo variables (`GCS_BUCKET`, `BQ_PROJECT`, `BQ_DATASET`).

Next steps I can take
---------------------
- Add a CI job to upload the Spark job to GCS and optionally run a smoke test against a staging bucket.
- Generate an Airflow variables import file (JSON) tailored to your dev/prod values.
- Scaffold unit tests for a subset of detector functions.

