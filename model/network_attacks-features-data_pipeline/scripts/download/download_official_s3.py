import os
import time
import hashlib
import subprocess
import datetime
import pandas as pd

S3_BUCKET = "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms"
TARGET_DIR = "C:/CyberSecurityNetworkingAttackPredictionModel/data/raw/cse_cic_ids2018"
MANIFEST_PATH = "C:/CyberSecurityNetworkingAttackPredictionModel/data/metadata/download_manifest.csv"

FILES_TO_DOWNLOAD = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv"
]

def compute_sha256(filepath):
    print(f"  Computing SHA-256 for {os.path.basename(filepath)}...")
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024 * 8):
            h.update(chunk)
    return h.hexdigest()

def main():
    os.makedirs(TARGET_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    manifest_records = []

    print("=" * 80)
    print("       CSE-CIC-IDS2018 OFFICIAL S3 DATASET INGESTION & VERIFICATION       ")
    print("=" * 80)

    for fname in FILES_TO_DOWNLOAD:
        local_path = os.path.join(TARGET_DIR, fname)
        s3_uri = f"{S3_BUCKET}/{fname}"
        print(f"\n[TARGET] {fname}")
        
        # Check if already fully downloaded
        if os.path.exists(local_path) and os.path.getsize(local_path) > 10 * 1024 * 1024:
            size_mb = os.path.getsize(local_path) / (1024 * 1024)
            print(f"  File already exists locally ({size_mb:.2f} MB). Skipping S3 transfer.")
            status = "VERIFIED_EXISTING"
            dl_time = datetime.datetime.fromtimestamp(os.path.getmtime(local_path), tz=datetime.timezone.utc).isoformat()
        else:
            print(f"  Executing AWS S3 Copy from {s3_uri}...")
            cmd = ["aws", "s3", "cp", "--no-sign-request", s3_uri, local_path]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"  [ERROR] Download failed: {res.stderr}")
                status = f"FAILED: {res.stderr.strip()}"
                dl_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
            else:
                size_mb = os.path.getsize(local_path) / (1024 * 1024)
                print(f"  [SUCCESS] Download completed ({size_mb:.2f} MB).")
                status = "SUCCESS"
                dl_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Compute hash if file exists
        if os.path.exists(local_path):
            fsize = os.path.getsize(local_path)
            sha = compute_sha256(local_path)
            print(f"  SHA-256: {sha}")
        else:
            fsize = 0
            sha = "N/A"

        manifest_records.append({
            "filename": fname,
            "s3_uri": s3_uri,
            "local_path": local_path,
            "size_bytes": fsize,
            "sha256": sha,
            "download_status": status,
            "download_timestamp": dl_time,
            "source_verified": "AWS Open Data Registry (s3://cse-cic-ids2018)"
        })

    df_manifest = pd.DataFrame(manifest_records)
    df_manifest.to_csv(MANIFEST_PATH, index=False)
    print(f"\nSaved download manifest to: {MANIFEST_PATH}")

if __name__ == "__main__":
    main()
