#!/usr/bin/env python3
"""
Train ML Model on Real Collected Data
Run: python3 train_real_model.py
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import sys
import os

def train_model():
    """Train the model on real collected data"""
    
    data_file = 'ddos_training_data.csv'
    
    print("="*70)
    print("  TRAINING MODEL ON REAL DATA")
    print("="*70)
    
    # Check if data file exists
    if not os.path.exists(data_file):
        print(f"\n❌ Error: '{data_file}' not found!")
        print("\nRun data collection first:")
        print("  ryu-manager controller/data_collection_controller.py")
        return None
    
    # Load data
    print(f"\n📂 Loading data from: {data_file}")
    df = pd.read_csv(data_file)
    print(f"✓ Loaded {len(df)} samples")
    
    # Check class distribution
    print("\n" + "="*70)
    print("  CLASS DISTRIBUTION")
    print("="*70)
    label_counts = df['label'].value_counts().sort_index()
    labels = {0: 'Normal', 1: 'SYN Flood', 2: 'ICMP Flood', 3: 'UDP Flood'}
    
    print()
    for label, name in labels.items():
        count = label_counts.get(label, 0)
        percentage = (count / len(df)) * 100 if len(df) > 0 else 0
        bar = '█' * int(percentage / 2)
        status = "✓" if count >= 100 else "⚠"
        print(f"  {status} {label}. {name:12s}: {count:4d} ({percentage:5.1f}%) {bar}")
    
    # Check minimum samples
    min_samples = label_counts.min() if len(label_counts) > 0 else 0
    if min_samples < 50:
        print(f"\n⚠ Warning: Some classes have < 50 samples!")
        print("  Recommend collecting more data for better accuracy.")
        response = input("\nContinue training anyway? (y/n): ")
        if response.lower() != 'y':
            return None
    
    # Prepare features
    features = ['packet_count', 'byte_count', 'syn_count', 'fin_count',
                'rst_count', 'ack_count', 'icmp_count', 'udp_count', 'duration_sec']
    
    X = df[features]
    y = df['label']
    
    # Handle missing values
    X = X.fillna(0)
    
    # Split data
    print("\n" + "="*70)
    print("  TRAIN/TEST SPLIT")
    print("="*70)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"  Training samples: {len(X_train)}")
    print(f"  Testing samples:  {len(X_test)}")
    
    # Train model
    print("\n" + "="*70)
    print("  TRAINING MODEL")
    print("="*70)
    print("\n  Training Random Forest... (this may take a minute)")
    
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    print("  ✓ Training complete!")
    
    # Evaluate
    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    
    print(f"\n  Training Accuracy:  {train_score*100:.2f}%")
    print(f"  Testing Accuracy:   {test_score*100:.2f}%")
    
    if test_score < 0.85:
        print("\n  ⚠ Accuracy < 85%. Consider collecting more data.")
    elif test_score >= 0.95:
        print("\n  🎉 Excellent accuracy!")
    
    # Predictions
    y_pred = model.predict(X_test)
    
    # Classification report
    print("\n" + "="*70)
    print("  CLASSIFICATION REPORT")
    print("="*70)
    target_names = ['Normal', 'SYN Flood', 'ICMP Flood', 'UDP Flood']
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    # Confusion matrix
    print("="*70)
    print("  CONFUSION MATRIX")
    print("="*70)
    cm = confusion_matrix(y_test, y_pred)
    print("\n  Rows=Actual | Columns=Predicted\n")
    print("              Normal  SYN  ICMP  UDP")
    for i, row in enumerate(cm):
        print(f"  {target_names[i]:12s}  {row[0]:3d}   {row[1]:3d}   {row[2]:3d}   {row[3]:3d}")
    
    # Feature importance
    print("\n" + "="*70)
    print("  FEATURE IMPORTANCE")
    print("="*70)
    importances = pd.DataFrame({
        'feature': features,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print()
    for _, row in importances.iterrows():
        bar = '█' * int(row['importance'] * 50)
        print(f"  {row['feature']:15s}: {row['importance']:.4f}  {bar}")
    
    # Save model
    model_filename = 'intelligent_ddos_model_3attacks.joblib'
    joblib.dump(model, model_filename)
    
    print("\n" + "="*70)
    print("  MODEL SAVED")
    print("="*70)
    print(f"\n  ✅ Saved to: {model_filename}")
    print(f"  📊 Trained on {len(df)} samples")
    print(f"  🎯 Test accuracy: {test_score*100:.2f}%")
    
    print("\n" + "="*70)
    print("  NEXT STEPS")
    print("="*70)
    print("\n  1. Update controller config (Line 49-52):")
    print("     File: controller/base_controller.py")
    print("     Change:")
    print("       config = {")
    print("           'model_path': 'intelligent_ddos_model_3attacks.joblib',")
    print("           'prediction_interval': 5")
    print("       }")
    print("\n  2. Update attack detection (Line 11-16):")
    print("     File: detection/attack_detection.py")
    print("     Change:")
    print("       ATTACK_TYPES = {")
    print("           0: 'Normal',")
    print("           1: 'SYN Flood',")
    print("           2: 'ICMP Flood',")
    print("           3: 'UDP Flood'  # ← ADD THIS LINE")
    print("       }")
    print("\n  3. Start controller:")
    print("     ryu-manager --observe-links controller/base_controller.py")
    print("\n" + "="*70 + "\n")
    
    return model

if __name__ == "__main__":
    model = train_model()
    
    if model:
        print("✅ Training successful!\n")
    else:
        print("❌ Training failed!\n")
        sys.exit(1)