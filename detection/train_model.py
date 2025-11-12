import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import seaborn as sns
import matplotlib.pyplot as plt

# 1. Load your labeled dataset
print("Loading 'labeled_flow_data.csv'...")
df = pd.read_csv('labeled_flow_data.csv')

# Make sure there are no missing values
df.fillna(0, inplace=True)

# 2. Define your features (X) and your target (y)
features = [
    'packet_count', 'byte_count', 'syn_count', 'fin_count', 
    'rst_count', 'ack_count', 'icmp_count', 'duration_sec'
]
X = df[features]
y = df['label']

# 3. Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
print("Data split into training and testing sets.")

# 4. Initialize and train the model
print("Training the RandomForest model...")
# class_weight='balanced' helps the model learn better from imbalanced datasets
model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)
print("Model training complete.")

# 5. Evaluate the model's performance
print("\n--- Model Evaluation ---")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'SYN Flood', 'ICMP Flood']))

# Display a confusion matrix to see the results visually
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', xticklabels=['Benign', 'SYN Flood', 'ICMP Flood'], yticklabels=['Benign', 'SYN Flood', 'ICMP Flood'])
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.title('Confusion Matrix')
plt.show()

# 6. Save the trained model to a file
model_filename = 'intelligent_ddos_model.joblib'
joblib.dump(model, model_filename)
print(f"\n✅ Model saved successfully as '{model_filename}'")