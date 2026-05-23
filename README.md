# AegisSOC - AI-Powered Network Intrusion Detection System

AegisSOC is a professional cybersecurity machine learning app that predicts network traffic classes, not just normal vs attack.

## Prediction Classes

- Normal
- DoS
- Exploit
- Reconnaissance
- Generic Attack
- Brute Force

## What The Project Demonstrates

1. Data generation/preprocessing for network intrusion detection.
2. Training and comparison of multiple supervised ML models.
3. Best-model selection using accuracy score.
4. Saved ML assets for deployment.
5. FastAPI backend for real-time prediction.
6. Web dashboard for single-record prediction and CSV batch analysis.

## Models Compared

- Logistic Regression
- K-Nearest Neighbors
- Naive Bayes
- Decision Tree
- Random Forest

The system saves the best model in `ml_model/saved_models/best_model.pkl` and writes model metadata to `ml_model/saved_models/metadata.json`.

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

Generate the multi-class dataset:

```bash
cd ml_model
python generate_data.py
```

Train and compare the models:

```bash
python train.py
```

Start the API:

```bash
cd ../backend
uvicorn main:app --reload
```

Open the frontend from the backend:

```text
http://127.0.0.1:8000
```

Or open the frontend file directly:

```text
frontend/index.html
```

Use `ml_model/data/sample_network_logs.csv` for a quick batch demo.

## Free Deployment On Render

This project is prepared for a single free Render web service.

1. Push the `SOC-Dashboard` folder to GitHub.
2. Open Render and create a new Web Service from that repository.
3. Use these settings:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - Plan: Free
4. After deployment, open the Render URL. The frontend is served by FastAPI at `/`.

The included `render.yaml` can also be used as a Render Blueprint.

## Dataset Note

For a class project, this version uses a generated IDS-style dataset so the full app runs immediately. For the final report, you can say the same pipeline is designed for Kaggle datasets such as UNSW-NB15 or CIC-IDS2017 after column mapping and preprocessing.