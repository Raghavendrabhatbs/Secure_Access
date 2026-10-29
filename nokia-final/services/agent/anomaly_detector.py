"""
Nokia SSH Agentic AI — Anomaly Detection
Uses scikit-learn Isolation Forest to detect
abnormal SSH session behavior.
Trained on historical sessions from PostgreSQL.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import psycopg2
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

MODEL_PATH = os.path.join(os.path.dirname(__file__), "anomaly_model.pkl")

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
POSTGRES_DB   = os.getenv("POSTGRES_DB", "nokia_ssh")
POSTGRES_USER = os.getenv("POSTGRES_USER", "nokia")
POSTGRES_PASS = os.getenv("POSTGRES_PASSWORD", "nokia123")

def get_db():
    return psycopg2.connect(
        host=POSTGRES_HOST, port=POSTGRES_PORT,
        dbname=POSTGRES_DB, user=POSTGRES_USER,
        password=POSTGRES_PASS
    )

def extract_features(hour, day_of_week, duration_seconds,
                     total_commands, sudo_count, has_history_clear,
                     has_dangerous_cmd, commands_per_minute):
    return np.array([[
        hour, day_of_week, duration_seconds, total_commands,
        sudo_count, has_history_clear, has_dangerous_cmd, commands_per_minute
    ]])

def load_training_data():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT login_time,
                   COALESCE(duration_seconds, 0),
                   COALESCE(total_commands, 0),
                   commands
            FROM sessions
            WHERE login_time IS NOT NULL
            ORDER BY login_time DESC
            LIMIT 1000
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[ANOMALY] DB error: {e}")
        return pd.DataFrame()

    records = []
    for login_time, duration, total_cmds, commands in rows:
        if commands is None:
            commands = []
        if isinstance(commands, str):
            try:
                commands = json.loads(commands)
            except Exception:
                commands = []

        sudo_count = sum(1 for c in commands if "sudo" in str(c).lower())
        has_history_clear = int(any("history -c" in str(c).lower() for c in commands))
        has_dangerous = int(any(
            p in str(c).lower() for c in commands
            for p in ["rm -rf", "chmod 777", "passwd", "useradd", "history -c"]
        ))
        duration = float(duration)
        total_cmds = int(total_cmds)
        commands_per_minute = (total_cmds / (duration / 60)) if duration > 0 else 0

        records.append({
            "hour": login_time.hour,
            "day_of_week": login_time.weekday(),
            "duration_seconds": duration,
            "total_commands": total_cmds,
            "sudo_count": sudo_count,
            "has_history_clear": has_history_clear,
            "has_dangerous_cmd": has_dangerous,
            "commands_per_minute": round(commands_per_minute, 2),
        })

    return pd.DataFrame(records)

def train_model():
    from sklearn.ensemble import IsolationForest
    print("[ANOMALY] Loading training data from PostgreSQL...")
    df = load_training_data()

    if len(df) < 5:
        print(f"[ANOMALY] Only {len(df)} sessions found. Using default model.")
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(np.zeros((10, 8)))
        joblib.dump(model, MODEL_PATH)
        return model

    print(f"[ANOMALY] Training on {len(df)} sessions...")
    model = IsolationForest(
        contamination=0.1,
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(df.values)
    joblib.dump(model, MODEL_PATH)
    print(f"[ANOMALY] Model trained and saved to {MODEL_PATH}")
    return model

def load_model():
    if os.path.exists(MODEL_PATH):
        print(f"[ANOMALY] Loading saved model from {MODEL_PATH}")
        return joblib.load(MODEL_PATH)
    print("[ANOMALY] No saved model. Training new model...")
    return train_model()

def score_session(model, features):
    if model is None:
        return {"score": 0.0, "is_anomaly": False, "label": "NORMAL", "confidence": "low"}

    score = float(model.decision_function(features)[0])
    prediction = model.predict(features)[0]
    is_anomaly = bool(prediction == -1)

    if score < -0.5:
        label = "HIGHLY_ANOMALOUS"
        confidence = "high"
    elif score < -0.3:
        label = "ANOMALOUS"
        confidence = "medium"
    elif score < -0.1:
        label = "SUSPICIOUS"
        confidence = "low"
    else:
        label = "NORMAL"
        confidence = "high"

    return {
        "score": round(score, 4),
        "is_anomaly": is_anomaly,
        "label": label,
        "confidence": confidence,
    }

def score_live_session(model, hour, day_of_week, duration_seconds,
                        total_commands, sudo_count=0, has_history_clear=0,
                        has_dangerous_cmd=0, commands_per_minute=0.0):
    features = extract_features(
        hour, day_of_week, duration_seconds, total_commands,
        sudo_count, has_history_clear, has_dangerous_cmd, commands_per_minute
    )
    return score_session(model, features)

if __name__ == "__main__":
    print("Nokia SSH Anomaly Detector — Self Test")
    print("=" * 50)

    model = load_model()

    test_cases = [
        {
            "label": "Normal session (9am, 5 commands, 3 min)",
            "params": dict(hour=9, day_of_week=1, duration_seconds=180,
                           total_commands=5, sudo_count=0,
                           has_history_clear=0, has_dangerous_cmd=0,
                           commands_per_minute=1.7),
            "expected_anomaly": False,
        },
        {
            "label": "Normal session (2pm, 8 commands, 5 min)",
            "params": dict(hour=14, day_of_week=3, duration_seconds=300,
                           total_commands=8, sudo_count=1,
                           has_history_clear=0, has_dangerous_cmd=0,
                           commands_per_minute=1.6),
            "expected_anomaly": False,
        },
        {
            "label": "Suspicious (3am login, 50 commands)",
            "params": dict(hour=3, day_of_week=0, duration_seconds=2700,
                           total_commands=50, sudo_count=5,
                           has_history_clear=1, has_dangerous_cmd=1,
                           commands_per_minute=11.1),
            "expected_anomaly": True,
        },
        {
            "label": "Suspicious (midnight, history cleared)",
            "params": dict(hour=0, day_of_week=6, duration_seconds=600,
                           total_commands=20, sudo_count=3,
                           has_history_clear=1, has_dangerous_cmd=1,
                           commands_per_minute=2.0),
            "expected_anomaly": True,
        },
    ]

    print()
    passed = 0
    for case in test_cases:
        result = score_live_session(model, **case["params"])
        status = "✅" if result["is_anomaly"] == case["expected_anomaly"] else "⚠️"
        if result["is_anomaly"] == case["expected_anomaly"]:
            passed += 1
        print(f"{status} {case['label']}")
        print(f"   Score     : {result['score']}")
        print(f"   Label     : {result['label']}")
        print(f"   Is Anomaly: {result['is_anomaly']}")
        print()

    print("=" * 50)
    print(f"Results: {passed}/4 passed")
    print("Self test complete!")
