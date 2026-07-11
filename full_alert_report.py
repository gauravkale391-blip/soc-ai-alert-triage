import pandas as pd
import numpy as np
import joblib
from mitre_mapping import get_mitre_info
from threat_intel import check_ip_reputation
import random


model = joblib.load('layer1_model.pkl')
le = joblib.load('label_encoder.pkl')


df = pd.read_parquet('data/final_dataset.parquet')
df = df.replace([np.inf, -np.inf], np.nan).dropna()

X = df.drop('Label', axis=1)
y = df['Label']


attack_mask = y != 'Benign'
X_attacks = X[attack_mask]
y_attacks = y[attack_mask]

sample_idx = X_attacks.groupby(y_attacks).apply(lambda x: x.sample(1, random_state=42)).index.get_level_values(1)
sample = X_attacks.loc[sample_idx][:5]  

predictions = model.predict(sample)
probabilities = model.predict_proba(sample)
confidence_scores = probabilities.max(axis=1)
predicted_labels = le.inverse_transform(predictions)

# 
demo_ips = ['185.220.101.45', '45.155.205.233', '8.8.8.8', '103.224.182.245', '1.1.1.1']

print("="*70)
print("SOC ALERT TRIAGE REPORT")
print("="*70)

for i, (label, conf) in enumerate(zip(predicted_labels, confidence_scores)):
    mitre = get_mitre_info(label)
    ip = demo_ips[i % len(demo_ips)]
    
    print(f"\n--- ALERT #{i+1} ---")
    print(f"Attack Type    : {label}")
    print(f"Confidence     : {conf:.2f}")
    print(f"Source IP      : {ip}")
    print(f"MITRE Technique: {mitre['technique']} - {mitre['name']}")
    print(f"MITRE Tactic   : {mitre['tactic']}")
    
    
    ti = check_ip_reputation(ip)
    if 'error' not in ti:
        print(f"Threat Intel   : {ti['malicious']} vendors flagged malicious, {ti['harmless']} flagged clean")
        print(f"IP Location    : {ti['country']} ({ti['as_owner']})")
    else:
        print(f"Threat Intel   : Could not fetch ({ti['error']})")

print("\n" + "="*70)
