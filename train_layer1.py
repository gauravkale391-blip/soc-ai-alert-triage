import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import joblib

print("Loading data...")
df = pd.read_parquet('data/final_dataset.parquet')


df = df.replace([np.inf, -np.inf], np.nan)
df = df.dropna()
print("Shape after cleaning:", df.shape)


X = df.drop('Label', axis=1)
y = df['Label']


le = LabelEncoder()
y_encoded = le.fit_transform(y)
print("\nClasses:", le.classes_)


X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"\nTrain size: {X_train.shape[0]}, Test size: {X_test.shape[0]}")


print("\nTraining model...मोठा आहे)")
model = RandomForestClassifier(
    n_estimators=100, 
    random_state=42, 
    n_jobs=-1,  
    class_weight='balanced'  # class imbalancष
)
model.fit(X_train, y_train)
print("\nEvaluating model...")
y_pred = model.predict(X_test)
print("\n", classification_report(y_test, y_pred, target_names=le.classes_))


probabilities = model.predict_proba(X_test)
confidence_scores = probabilities.max(axis=1)
print(f"\nAverage confidence: {confidence_scores.mean():.3f}")
print(f"Low confidence (<0.7) cases: {(confidence_scores < 0.7).sum()} out of {len(confidence_scores)}")

# Model आणि encoder save कर - पुढे dasाा
joblib.dump(model, 'layer1_model.pkl')
joblib.dump(le, 'label_encoder.pkl')
print("\nModel saved as layer1_model.pkl")
