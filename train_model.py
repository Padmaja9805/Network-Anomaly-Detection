import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.utils import resample

# =========================
# Load dataset
# =========================
df = pd.read_csv("dataset.csv")

# Assume last column is label
X = df.iloc[:, :-1]
y = df.iloc[:, -1]

# =========================
# Balance dataset (VERY IMPORTANT)
# =========================
data = pd.concat([X, y], axis=1)

class0 = data[data.iloc[:, -1] == 0]
class1 = data[data.iloc[:, -1] == 1]

min_size = min(len(class0), len(class1))

class0 = resample(class0, replace=False, n_samples=min_size, random_state=42)
class1 = resample(class1, replace=False, n_samples=min_size, random_state=42)

balanced = pd.concat([class0, class1])

X = balanced.iloc[:, :-1]
y = balanced.iloc[:, -1]

# =========================
# Train test split
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# =========================
# Scaling
# =========================
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# =========================
# Random Forest (STRONG MODEL)
# =========================
model = RandomForestClassifier(
    n_estimators=300,       # more trees
    max_depth=20,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# =========================
# Save Model and Scaler (CRITICAL)
# =========================
import joblib
joblib.dump(model, "model.pkl")
joblib.dump(scaler, "scaler.pkl")
print("✅ model.pkl and scaler.pkl saved!")

# =========================
# Prediction
# =========================
y_pred = model.predict(X_test)

# =========================
# Results
# =========================
print("\nAccuracy:", accuracy_score(y_test, y_pred))

print("\nConfusion Matrix:\n")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))
