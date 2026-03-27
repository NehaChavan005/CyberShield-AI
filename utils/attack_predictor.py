import os
import joblib
import pandas as pd
from genai.threat_explainer import explain_threat
from genai.llm_report import generate_llm_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "model", "cybershield_model.pkl")


# Load model once
model = joblib.load(MODEL_PATH)


def preprocess_input(data):

    df = pd.DataFrame([data])

    drop_cols = ["timestamp", "source_ip", "destination_ip"]

    df = df.drop(columns=drop_cols, errors="ignore")

    for col in df.select_dtypes(include="object").columns:
        df[col] = df[col].astype("category").cat.codes

    return df


def predict_attack(network_data):

    processed = preprocess_input(network_data)

    prediction = model.predict(processed)[0]

    attack_type = network_data.get("attack_type", "unknown")

    explanation = explain_threat(prediction, attack_type, network_data)

    llm_report = generate_llm_report(explanation)

    return {
        "prediction": int(prediction),
        "attack_type": attack_type,
        "ai_analysis": explanation,
        "llm_security_report": llm_report
    }