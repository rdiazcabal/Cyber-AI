import numpy as np
from sklearn.ensemble import IsolationForest


def event_to_features(event: dict) -> list:
    severity = float(event.get("severity", 0) or 0)

    event_name = str(event.get("eventName", ""))
    service = str(event.get("service", ""))
    source_ip = str(event.get("source_ip", event.get("sourceIPAddress", "")))
    user = str(event.get("user", ""))

    return [
        severity,
        len(event_name),
        len(service),
        len(source_ip),
        len(user),
        1 if "CreateAccessKey" in event_name else 0,
        1 if "AttachUserPolicy" in event_name else 0,
        1 if "ConsoleLogin" in event_name else 0
    ]


def detect_anomalies(events: list) -> dict:
    if not events:
        return {
            "anomaly_score": 0,
            "anomalies": []
        }

    if len(events) < 3:
        return {
            "anomaly_score": 0,
            "anomalies": [],
            "note": "At least 3 events are recommended for ML anomaly detection."
        }

    X = np.array([event_to_features(e) for e in events])

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )

    predictions = model.fit_predict(X)
    scores = model.decision_function(X)

    anomalies = []

    for index, prediction in enumerate(predictions):
        if prediction == -1:
            anomalies.append({
                "index": index,
                "event": events[index],
                "score": float(scores[index])
            })

    anomaly_score = min(100, len(anomalies) * 25)

    return {
        "anomaly_score": anomaly_score,
        "anomalies": anomalies
    }