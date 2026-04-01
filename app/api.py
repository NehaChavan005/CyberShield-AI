import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from auth.api import get_current_user
from auth.security import create_access_token
from auth.store import authenticate_user
from utils.attack_predictor import predict_attack


app = FastAPI(title="CyberShield-AI API", version="1.0.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class PredictionRequest(BaseModel):
    source_ip: str | None = None
    destination_ip: str | None = None
    protocol: str
    port: int
    packet_size: int
    request_rate: int
    failed_logins: int
    malware_signature: str = "none"
    traffic_type: str = "normal"
    attack_type: str = "none"
    suspicious_pid: int | None = None
    suspicious_process_name: str | None = None
    auto_remediate: bool = False


@app.get("/health")
def healthcheck():
    return {"status": "ok"}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = authenticate_user(payload.username, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    return {
        "access_token": create_access_token(user["username"]),
        "token_type": "bearer",
        "user": user,
    }


@app.post("/predict")
def protected_predict(
    payload: PredictionRequest,
    current_user: dict = Depends(get_current_user),
):
    request_payload = payload.model_dump()
    auto_remediate = request_payload.pop("auto_remediate", False)
    result = predict_attack(request_payload, auto_remediate=auto_remediate)
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])

    return {"user": current_user, "result": result}
