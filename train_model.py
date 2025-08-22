import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from pathlib import Path

FEATURE_COLS = [
    "hour","is_off_hours","is_private_ip","event_suspicious_keyword",
    "evt_failed_ssh","evt_port_scan","evt_rdp","evt_dns","evt_login",
    "evt_file","evt_web404","ip_count_in_batch"
]

def load_training_features(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # ensure all feature columns exist (robustness)
    for c in FEATURE_COLS:
        if c not in df.columns:
            df[c] = 0
    return df

if __name__ == "__main__":
    feats = load_training_features("../data/training_features.csv")
    X = feats[FEATURE_COLS]
    y = feats["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("=== Classification Report ===")
    print(classification_report(y_test, y_pred, digits=3))

    Path("../models").mkdir(parents=True, exist_ok=True)
    dump(clf, "../models/threat_classifier.joblib")
    print("Saved model to ../models/threat_classifier.joblib")
