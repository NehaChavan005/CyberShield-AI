import pandas as pd
import os

# Get project base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Dataset folder
DATASET_DIR = os.path.join(BASE_DIR, "data")

# Output file
OUTPUT_FILE = os.path.join(DATASET_DIR, "final_dataset.csv")

# Standard columns for the project
COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "port",
    "packet_size",
    "request_rate",
    "failed_logins",
    "malware_signature",
    "traffic_type",
    "attack_type",
    "label"
]


def normalize_columns(df, source_name):
    """Normalize dataset columns to match project schema"""

    df.columns = [c.lower() for c in df.columns]

    column_map = {
        "src_ip": "source_ip",
        "dst_ip": "destination_ip",
        "protocol_type": "protocol",
        "service": "protocol",
        "attack": "attack_type",
        "attack_cat": "attack_type",
        "class": "label",
    }

    df.rename(columns={k: v for k, v in column_map.items() if k in df.columns}, inplace=True)

    # Ensure all required columns exist
    for col in COLUMNS:
        if col not in df.columns:
            if col == "label":
                df[col] = 0
            elif col in ["traffic_type", "attack_type", "malware_signature"]:
                df[col] = "none"
            else:
                df[col] = None

    df = df[COLUMNS]

    df["dataset_source"] = source_name

    return df


def load_and_prepare():
    datasets = []

    # Load Synthetic Dataset
    try:
        synthetic_path = os.path.join(DATASET_DIR, "cyber_attacks_dataset.csv")

        synthetic = pd.read_csv(synthetic_path)

        synthetic = normalize_columns(synthetic, "synthetic")

        datasets.append(synthetic)

        print(f"Loaded synthetic dataset: {synthetic.shape}")

    except Exception as e:
        print("Synthetic dataset missing:", e)

    # Load KDD Dataset
    try:
        kdd_path = os.path.join(DATASET_DIR, "kddcup99.csv")

        kdd = pd.read_csv(
            kdd_path,
            on_bad_lines="skip",   # Skip corrupted rows
            low_memory=False
        )

        kdd = normalize_columns(kdd, "kddcup99")

        datasets.append(kdd)

        print(f"Loaded KDD dataset: {kdd.shape}")

    except Exception as e:
        print("KDD dataset missing or corrupted:", e)

    # Merge datasets
    if datasets:
        final_dataset = pd.concat(datasets, ignore_index=True)

        final_dataset.to_csv(OUTPUT_FILE, index=False)

        print("\nFinal dataset created successfully")
        print("Total records:", final_dataset.shape[0])
        print("Saved to:", OUTPUT_FILE)

    else:
        print("No datasets loaded.")


if __name__ == "__main__":
    load_and_prepare()