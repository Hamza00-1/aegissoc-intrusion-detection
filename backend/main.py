import io
import json
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = BASE_DIR / "ml_model" / "saved_models"
MODEL_PATH = MODEL_DIR / "best_model.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
METADATA_PATH = MODEL_DIR / "metadata.json"
FRONTEND_DIR = BASE_DIR / "frontend"

DEFAULT_FEATURES = [
    "duration",
    "protocol_type",
    "src_bytes",
    "dst_bytes",
    "num_failed_logins",
    "count",
    "srv_count",
    "serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
]

PROTOCOL_MAP = {"tcp": 0, "udp": 1, "icmp": 2, "0": 0, "1": 1, "2": 2}
PROTOCOL_NAMES = {0: "TCP", 1: "UDP", 2: "ICMP"}

app = FastAPI(
    title="AegisSOC API",
    description="Multi-class AI API for network intrusion detection",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = None
scaler = None
metadata = {}


class TrafficRecord(BaseModel):
    duration: float = Field(0.5, ge=0)
    protocol_type: str | int = "tcp"
    src_bytes: float = Field(450, ge=0)
    dst_bytes: float = Field(1200, ge=0)
    num_failed_logins: int = Field(0, ge=0)
    count: int = Field(24, ge=0)
    srv_count: int = Field(18, ge=0)
    serror_rate: float = Field(0.05, ge=0, le=1)
    rerror_rate: float = Field(0.02, ge=0, le=1)
    same_srv_rate: float = Field(0.8, ge=0, le=1)
    diff_srv_rate: float = Field(0.08, ge=0, le=1)
    dst_host_count: int = Field(65, ge=0)
    dst_host_srv_count: int = Field(45, ge=0)


def load_json(path):
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


@app.on_event("startup")
def load_ml_assets():
    global model, scaler, metadata
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        metadata = load_json(METADATA_PATH)
        print("Model, scaler, and metadata loaded successfully.")
    except Exception as exc:
        print(f"Could not load ML assets. Train the model first. Details: {exc}")


def ensure_model_loaded():
    if model is None or scaler is None:
        raise HTTPException(
            status_code=503,
            detail="ML assets are missing. Run ml_model/generate_data.py and ml_model/train.py first.",
        )


def normalize_protocol(value):
    key = str(value).strip().lower()
    if key not in PROTOCOL_MAP:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported protocol_type '{value}'. Use tcp, udp, icmp, 0, 1, or 2.",
        )
    return PROTOCOL_MAP[key]


def prepare_frame(df):
    features = metadata.get("features", DEFAULT_FEATURES)
    working = df.copy()

    if "protocol_type" in working.columns:
        working["protocol_type"] = working["protocol_type"].apply(normalize_protocol)

    missing = [feature for feature in features if feature not in working.columns]
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required columns: {missing}")

    X = working[features].apply(pd.to_numeric, errors="coerce")
    if X.isnull().any().any():
        bad_columns = X.columns[X.isnull().any()].tolist()
        raise HTTPException(status_code=400, detail=f"Invalid numeric values in columns: {bad_columns}")

    return working, X


def risk_level(label, confidence):
    if label == "Normal":
        return "Low"
    if label in {"DoS", "Exploit", "Generic Attack"} and confidence >= 70:
        return "Critical"
    if label in {"Reconnaissance", "Brute Force"} or confidence >= 55:
        return "High"
    return "Medium"


def predict_frame(df):
    ensure_model_loaded()
    original, X = prepare_frame(df)
    X_scaled = scaler.transform(X)
    predictions = model.predict(X_scaled)

    probabilities = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X_scaled)

    results = []
    for index, prediction in enumerate(predictions):
        if probabilities is not None:
            confidence = round(float(max(probabilities[index])) * 100, 2)
        else:
            confidence = 100.0

        protocol_value = int(X.iloc[index]["protocol_type"])
        label = str(prediction)
        results.append(
            {
                "id": int(original.index[index]),
                "protocol": PROTOCOL_NAMES.get(protocol_value, str(protocol_value)),
                "src_bytes": float(X.iloc[index]["src_bytes"]),
                "dst_bytes": float(X.iloc[index]["dst_bytes"]),
                "attack_type": label,
                "is_attack": label != "Normal",
                "confidence": confidence,
                "risk_level": risk_level(label, confidence),
            }
        )

    attack_breakdown = {}
    for result in results:
        attack_breakdown[result["attack_type"]] = attack_breakdown.get(result["attack_type"], 0) + 1

    threats_detected = sum(1 for result in results if result["is_attack"])
    best_accuracy = metadata.get("best_accuracy", metadata.get("best_weighted_f1"))
    return {
        "total_analyzed": len(results),
        "threats_detected": threats_detected,
        "attack_breakdown": attack_breakdown,
        "model_info": {
            "best_model": metadata.get("best_model", "Unknown"),
            "best_accuracy": best_accuracy,
            "classes": metadata.get("classes", []),
        },
        "data": results,
    }


@app.get("/", include_in_schema=False)
def serve_frontend():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/style.css", include_in_schema=False)
def serve_css():
    return FileResponse(FRONTEND_DIR / "style.css")


@app.get("/script.js", include_in_schema=False)
def serve_js():
    return FileResponse(FRONTEND_DIR / "script.js")


@app.get("/health")
def read_root():
    return {"message": "AegisSOC multi-class intrusion detection API is running."}


@app.get("/metadata")
def get_metadata():
    return {
        "features": metadata.get("features", DEFAULT_FEATURES),
        "classes": metadata.get("classes", []),
        "best_model": metadata.get("best_model"),
        "model_scores": metadata.get("model_scores", []),
    }


@app.post("/predict-single")
def predict_single(record: TrafficRecord):
    payload = record.model_dump() if hasattr(record, "model_dump") else record.dict()
    df = pd.DataFrame([payload])
    return predict_frame(df)


@app.post("/predict")
async def predict_network_traffic(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
        return predict_frame(df)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
