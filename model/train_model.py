import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "final_dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "model", "cybershield_model.pkl")

def load_data():
    df = pd.read_csv(DATA_PATH)
    print("Dataset loaded:", df.shape)
    return df

def preprocess(df):
    df = df.drop(columns=["timestamp","source_ip","destination_ip"], errors="ignore")

    label_encoders = {}

    for col in df.select_dtypes(include="object").columns:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le

    return df, label_encoders

def train():
    df = load_data()

    df, encoders = preprocess(df)

    X = df.drop("label", axis=1)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=10,
        random_state=42
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nModel Evaluation\n")
    print(classification_report(y_test, predictions))

    joblib.dump(model, MODEL_PATH)

    print("\nModel saved to:", MODEL_PATH)

if __name__ == "__main__":
    train()