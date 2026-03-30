import os
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(BASE_DIR, "data", "final_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "cybershield_model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "model", "encoders.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model", "features.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model", "feature_metadata.json")


def load_data():
    df = pd.read_csv(DATA_PATH)
    print("Dataset loaded:", df.shape)
    return df


def preprocess_and_encode(df):
    # Drop helper column if present
    df.drop(columns=["dataset_source"], inplace=True, errors="ignore")

    # Define columns to exclude from encoding (keep as-is or engineer separately)
    exclude_cols = ["timestamp", "source_ip", "destination_ip"]

    # Determine feature columns (exclude label)
    feature_cols = [c for c in df.columns if c != "label"]

    # Determine categorical columns (object dtype) excluding excluded ones
    categorical = [c for c in feature_cols if df[c].dtype == "object" and c not in exclude_cols]
    numeric = [c for c in feature_cols if c not in categorical]

    encoders = {}

    # Fit separate OrdinalEncoder per categorical column
    for col in categorical:
        oe = OrdinalEncoder(dtype=int)
        values = df[[col]].astype(str).fillna("__MISSING__")
        oe.fit(values)
        df[col] = oe.transform(values).astype(int)
        # Save classes list for this column
        encoders[col] = {"classes": oe.categories_[0].astype(str).tolist()}

    # For numeric columns, coerce types
    for col in numeric:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    metadata = {
        "feature_columns": feature_cols,
        "categorical": categorical,
        "numeric": numeric,
        "excluded": exclude_cols
    }

    return df, encoders, metadata


def train():
    df = load_data()

    df, encoders, metadata = preprocess_and_encode(df)

    X = df.drop("label", axis=1)
    y = df["label"]

    expected_columns = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nModel Evaluation\n")
    print(classification_report(y_test, predictions))

    # Save artifacts
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(encoders, ENCODER_PATH)
    joblib.dump(expected_columns, FEATURES_PATH)
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print("\nModel saved to:", MODEL_PATH)
    print("Encoders saved to:", ENCODER_PATH)
    print("Features saved to:", FEATURES_PATH)
    print("Metadata saved to:", METADATA_PATH)


if __name__ == "__main__":
    train()
