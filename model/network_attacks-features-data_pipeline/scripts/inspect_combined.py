import pandas as pd
import pyarrow.parquet as pq

df_comb = pd.read_parquet("data/combined_multidomain_dataset.parquet")
print("=== COMBINED MULTIDOMAIN DATASET ===")
print("Shape:", df_comb.shape)
print("Columns:", list(df_comb.columns))
if "dataset" in df_comb.columns:
    print("Dataset dist:\n", df_comb["dataset"].value_counts())
if "mitre_stage_code" in df_comb.columns:
    print("Stage code dist:\n", df_comb["mitre_stage_code"].value_counts().sort_index())
if "session" in df_comb.columns:
    print("Session dist:\n", df_comb["session"].value_counts())
if "raw_attack_type" in df_comb.columns:
    print("Raw attack type top 15:\n", df_comb["raw_attack_type"].value_counts().head(15))
