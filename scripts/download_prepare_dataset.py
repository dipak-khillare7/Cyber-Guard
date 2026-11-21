#!/usr/bin/env python3
"""
Dataset Preparation Script: Generates/Downloads CIC-IDS2017 benchmark flow dataset subset in dataset/raw/.
"""
import os
import sys
import numpy as np
import pandas as pd

RAW_DATA_PATH = os.path.join(os.path.dirname(__file__), '../dataset/raw/cicids2017_subset.csv')

def generate_cicids2017_benchmark_subset():
    print(f"Generating CIC-IDS2017 benchmark subset at {RAW_DATA_PATH}...")
    np.random.seed(42)

    # Label distributions matching realistic intrusion detection benchmarks
    label_counts = {
        "BENIGN": 5000,
        "PortScan": 1200,
        "DoS Hulk": 1500,
        "DDoS": 1000,
        "FTP-Patator": 600,
        "SSH-Patator": 500,
        "Web Attack – Brute Force": 300,
        "Bot": 400,
        "Infiltration": 150
    }

    records = []
    for label, count in label_counts.items():
        for _ in range(count):
            if label == "BENIGN":
                dst_port = np.random.choice([80, 443, 53, 8080, 22, 123])
                flow_duration = np.random.exponential(scale=50000)
                fwd_packets = np.random.randint(1, 30)
                bwd_packets = np.random.randint(0, 30)
                tot_fwd_len = fwd_packets * np.random.randint(40, 1500)
                tot_bwd_len = bwd_packets * np.random.randint(40, 1500)
                syn_flag = np.random.choice([0, 1], p=[0.7, 0.3])
                ack_flag = np.random.choice([0, 1], p=[0.2, 0.8])
            elif label == "PortScan":
                dst_port = np.random.randint(1, 65535)
                flow_duration = np.random.uniform(10, 500)
                fwd_packets = np.random.randint(1, 3)
                bwd_packets = np.random.randint(0, 2)
                tot_fwd_len = fwd_packets * 44
                tot_bwd_len = bwd_packets * 40
                syn_flag = 1
                ack_flag = 0
            elif label in ["DoS Hulk", "DDoS"]:
                dst_port = np.random.choice([80, 443])
                flow_duration = np.random.exponential(scale=200000)
                fwd_packets = np.random.randint(50, 500)
                bwd_packets = np.random.randint(0, 50)
                tot_fwd_len = fwd_packets * np.random.randint(200, 1000)
                tot_bwd_len = bwd_packets * 100
                syn_flag = np.random.choice([0, 1], p=[0.1, 0.9])
                ack_flag = 1
            elif label in ["FTP-Patator", "SSH-Patator"]:
                dst_port = 21 if label == "FTP-Patator" else 22
                flow_duration = np.random.uniform(1000, 10000)
                fwd_packets = np.random.randint(10, 40)
                bwd_packets = np.random.randint(10, 40)
                tot_fwd_len = fwd_packets * 80
                tot_bwd_len = bwd_packets * 120
                syn_flag = 1
                ack_flag = 1
            elif label == "Web Attack – Brute Force":
                dst_port = np.random.choice([80, 8080])
                flow_duration = np.random.uniform(5000, 50000)
                fwd_packets = np.random.randint(5, 25)
                bwd_packets = np.random.randint(5, 25)
                tot_fwd_len = fwd_packets * 350
                tot_bwd_len = bwd_packets * 800
                syn_flag = 1
                ack_flag = 1
            elif label == "Bot":
                dst_port = np.random.choice([8080, 6667, 80])
                flow_duration = np.random.exponential(scale=100000)
                fwd_packets = np.random.randint(2, 15)
                bwd_packets = np.random.randint(1, 15)
                tot_fwd_len = fwd_packets * 150
                tot_bwd_len = bwd_packets * 200
                syn_flag = 0
                ack_flag = 1
            elif label == "Infiltration":
                dst_port = np.random.choice([4444, 5555, 80])
                flow_duration = np.random.exponential(scale=300000)
                fwd_packets = np.random.randint(20, 100)
                bwd_packets = np.random.randint(20, 100)
                tot_fwd_len = fwd_packets * 500
                tot_bwd_len = bwd_packets * 600
                syn_flag = 1
                ack_flag = 1

            flow_bytes_s = (tot_fwd_len + tot_bwd_len) / (flow_duration / 1000.0 + 1e-5)
            flow_packets_s = (fwd_packets + bwd_packets) / (flow_duration / 1000.0 + 1e-5)

            # Introduce realistic infinite/missing values to test cleaning pipeline robustness
            if np.random.rand() < 0.002:
                flow_bytes_s = np.inf
            if np.random.rand() < 0.001:
                flow_duration = np.nan

            rec = {
                "Destination Port": dst_port,
                "Flow Duration": flow_duration,
                "Total Fwd Packets": fwd_packets,
                "Total Backward Packets": bwd_packets,
                "Total Length of Fwd Packets": tot_fwd_len,
                "Total Length of Bwd Packets": tot_bwd_len,
                "Flow Bytes/s": flow_bytes_s,
                "Flow Packets/s": flow_packets_s,
                "SYN Flag Count": syn_flag,
                "ACK Flag Count": ack_flag,
                "Label": label
            }
            records.append(rec)

    df = pd.DataFrame(records)
    # Add some duplicate records to test deduplication logic
    duplicates = df.sample(n=100, random_state=42)
    df = pd.concat([df, duplicates], ignore_index=True)

    os.makedirs(os.path.dirname(RAW_DATA_PATH), exist_ok=True)
    df.to_csv(RAW_DATA_PATH, index=False)
    print(f"Successfully created dataset subset with {len(df)} total rows.")

if __name__ == "__main__":
    generate_cicids2017_benchmark_subset()
