import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier


DATA_PATH = "data/network_traffic.csv"
MODEL_DIR = "saved_models"
FEATURES = [
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


def train_and_evaluate():
    if not os.path.exists(DATA_PATH):
        print(f"Dataset not found at {DATA_PATH}. Please run generate_data.py first.")
        return

    print("Loading multi-class cybersecurity dataset...")
    df = pd.read_csv(DATA_PATH)
    X = df[FEATURES]
    y = df["label"]
    class_names = sorted(y.unique().tolist())

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=2500, class_weight="balanced"),
        "K-Nearest Neighbors": KNeighborsClassifier(n_neighbors=7),
        "Naive Bayes": GaussianNB(),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, class_weight="balanced", random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=180,
            max_depth=18,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
    }

    best_model_name = ""
    best_accuracy = -1
    best_model = None
    scores = []

    print("\n--- Training Models ---")
    for name, model in models.items():
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)

        accuracy = accuracy_score(y_test, y_pred)
        scores.append(
            {
                "model": name,
                "accuracy": round(float(accuracy), 4),
            }
        )

        print(f"\n[{name}]")
        print(f"Accuracy: {accuracy * 100:.2f}%")

        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_model_name = name
            best_model = model
            best_predictions = y_pred

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(best_model, os.path.join(MODEL_DIR, "best_model.pkl"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

    metadata = {
        "project": "AI-Powered Network Intrusion Detection System",
        "features": FEATURES,
        "classes": class_names,
        "best_model": best_model_name,
        "best_accuracy": round(float(best_accuracy), 4),
        "model_scores": sorted(scores, key=lambda item: item["accuracy"], reverse=True),
        "confusion_matrix": confusion_matrix(y_test, best_predictions, labels=class_names).tolist(),
        "protocol_mapping": {"tcp": 0, "udp": 1, "icmp": 2},
    }

    with open(os.path.join(MODEL_DIR, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nBest model: {best_model_name} with accuracy {best_accuracy * 100:.2f}%.")
    print(f"Saved model, scaler, and metadata to {MODEL_DIR}/")


if __name__ == "__main__":
    train_and_evaluate()
