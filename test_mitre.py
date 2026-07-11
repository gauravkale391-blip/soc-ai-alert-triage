import pandas as pd
import numpy as np
import joblib
from mitre_mapping import get_mitre_info
from sklearn.model_selection import train_test_split


model = joblib.load('layer1_model.pkl')
le = joblib.load('label_encoder.pkl')


df = pd.read_parquet('data/final_dataset.parquet')
df = df.replace([np.inf, -np.inf], np.nan).dropna()

X = df.drop('Label', axis=1)
y = df['Label']

attack_mask= y  != 'Benign'
X_attacks = X[attack_mask]
sample = X_attacks.sample(10, random_state=42)
predictions = model.predict(sample)
probabilities = model.predict_proba(sample)
confidence_scores = probabilities.max(axis=1)


predicted_labels = le.inverse_transform(predictions)

print("Sample Alert Report:\n" + "="*60)
for i, (label, conf) in enumerate(zip(predicted_labels, confidence_scores)):
    mitre = get_mitre_info(label)
    print(f"\nAlert #{i+1}")
    print(f"  Attack Type   : {label}")
    print(f"  Confidence    : {conf:.2f}")
    print(f"  MITRE ID      : {mitre['technique']}")
    print(f"  Technique     : {mitre['name']}")
    print(f"  Tactic        : {mitre['tactic']}")
