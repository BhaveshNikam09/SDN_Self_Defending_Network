# -*- coding: utf-8 -*-
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler  # --- NEW ---
import joblib

labeled_csv_path = 'auto_labeled_flow_stats.csv'
print("--- Starting Model Training with Feature Scaling ---")

# Load the dataset
df = pd.read_csv(labeled_csv_path)
print(f"Successfully loaded dataset with {len(df)} rows.")

# Select features
features = ['packet_count', 'byte_count']
X = df[features]
y = df['label']

# --- NEW: Feature Scaling ---
scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

# --- NEW: Save the scaler ---
scaler_filename = 'scaler.joblib'
joblib.dump(scaler, scaler_filename)
print(f" scaler saved to {scaler_filename}")


X_normal_scaled = X_scaled[y == 0]

model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)

print("Training the Isolation Forest model on SCALED normal traffic data...")
model.fit(X_normal_scaled)
print("Model training complete.")

# Save the retrained model
model_filename = 'ddos_model.joblib'
joblib.dump(model, model_filename)
print(f"Retrained model saved to {model_filename}")

y_pred_raw = model.predict(X_scaled)
y_pred_mapped = pd.Series(y_pred_raw).replace({1: 0, -1: 1}) # Map back to 0/1

from sklearn.metrics import classification_report
print("\n--- Model Evaluation ---")
print(classification_report(y, y_pred_mapped, target_names=['Normal (0)', 'Attack (1)']))