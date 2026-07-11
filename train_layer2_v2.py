import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

print("Loading enhanced data...")
df = pd.read_parquet('data/enhanced_dataset.parquet')


df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
print("Shape after cleaning:", df.shape)

X = df.drop('Label', axis=1)
y = df['Label']


X_benign = X[y == 'Benign']
print(f"Training on {X_benign.shape[0]} benign samples")

scaler = StandardScaler()
X_benign_scaled = scaler.fit_transform(X_benign)

print("Training Isolation Forest v2...")
iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
iso_forest.fit(X_benign_scaled)

X_scaled_full = scaler.transform(X)
anomaly_predictions = iso_forest.predict(X_scaled_full)

results_df = pd.DataFrame({
    'true_label': y.values,
    'predicted_anomaly': anomaly_predictions
})

print("\n--- Detection Summary per attack type (v2 - with new features) ---")
for label in y.unique():
    subset = results_df[results_df['true_label'] == label]
    flagged = (subset['predicted_anomaly'] == -1).sum()
    total = len(subset)
    pct = (flagged / total * 100) if total > 0 else 0
    print(f"{label:30s}: {flagged}/{total} flagged as anomaly ({pct:.1f}%)")

joblib.dump(iso_forest, 'layer2_model_v2.pkl')
joblib.dump(scaler, 'layer2_scaler_v2.pkl')
print("\nLayer 2 v2 model saved!")
