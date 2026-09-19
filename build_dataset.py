import os
import pandas as pd
from extract_features import extract_features

all_data = []

# NORMAL
for file in os.listdir("captures/normal"):
    print("Processing:", file)
    df = extract_features(f"captures/normal/{file}", 0)
    print("Packets found:", len(df))
    if len(df) > 0:
        all_data.append(df)

# ANOMALY
for file in os.listdir("captures/anomaly"):
    print("Processing:", file)
    df = extract_features(f"captures/anomaly/{file}", 1)
    print("Packets found:", len(df))
    if len(df) > 0:
        all_data.append(df)

if all_data:
    dataset = pd.concat(all_data)
    dataset.to_csv("dataset.csv", index=False)
    print("✅ dataset.csv created!")
else:
    print("❌ No packets extracted, check PCAP files!")
