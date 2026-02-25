import pandas as pd
import numpy as np8
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
df = pd.read_csv(r"C:\Users\abhuv\OneDrive\Documents\NPL\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
df.columns = df.columns.str.strip()
df.dropna(inplace=True)
df.drop_duplicates(inplace=True)
if "Label" not in df.columns:
    raise Exception("Label column not found in dataset")
required_features = ["Flow Duration","Total Fwd Packets","Total Backward Packets","Total Length of Fwd Packets","SYN Flag Count","ACK Flag Count","Destination Port"]
missing_features = [f for f in required_features if f not in df.columns]
if len(missing_features) > 0:
    raise Exception(f"Missing Features: {missing_features}")
X = df[required_features]
y = df["Label"]
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100,random_state=42,n_jobs=-1)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
if not os.path.exists("models"):
    os.makedirs("models")
joblib.dump(model, "models/ids_model.pkl")
joblib.dump(scaler, "models/scaler.pkl")
joblib.dump(label_encoder, "models/label_encoder.pkl")