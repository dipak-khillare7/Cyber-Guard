# Machine Learning Model & Pipeline Documentation

## 1. Dataset Overview & Label Normalization

* **Dataset Name**: CIC-IDS2017 Benchmark Intrusion Detection Dataset (Flow Subset)
* **Dataset Source**: Canadian Institute for Cybersecurity (CIC), University of New Brunswick
* **Total Flow Records**: 10,750 ingested (10,650 after deduplication)
* **Feature Attributes**: 10 flow metrics (`Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd Packets`, `Total Length of Bwd Packets`, `Flow Bytes/s`, `Flow Packets/s`, `SYN Flag Count`, `ACK Flag Count`)

### Threat Label Mapping Table

| Raw Dataset Label | Standardized Threat Category | Class Percentage | Supported Status |
|---|---|---|---|
| `BENIGN` | `NORMAL` | 47.04% | Supported |
| `DoS Hulk` / `DDoS` | `DOS_DDOS` | 23.43% | Supported |
| `PortScan` | `PORT_SCAN` | 11.20% | Supported |
| `FTP-Patator` / `SSH-Patator` | `BRUTE_FORCE` | 10.38% | Supported |
| `Bot` | `BOTNET` | 3.76% | Supported |
| `Web Attack – Brute Force` | `WEB_ATTACK` | 2.80% | Supported |
| `Infiltration` | `INFILTRATION` | 1.40% | Supported |
| *N/A* | `DATA_EXFILTRATION` | 0.00% | Unsupported in raw dataset |
| *N/A* | `MALWARE` | 0.00% | Unsupported in raw dataset |
| *N/A* | `CREDENTIAL_ATTACK` | 0.00% | Unsupported in raw dataset |

---

## 2. Preprocessing & Zero-Leakage Pipeline

To strictly prevent data leakage:
1. **Deduplication**: 100 duplicate rows removed prior to splitting.
2. **Missing & Infinite Imputation**: Infinite values (`+inf`/`-inf`) and missing cells (`NaN`) replaced with feature medians.
3. **Stratified Split**: Data split into 70% Training (7,455 samples), 15% Validation (1,597 samples), and 15% Isolated Test set (1,598 samples) with `seed=42`.
4. **Scikit-Learn Pipeline**: `RobustScaler` fitted **ONLY** on the training set and applied via `ColumnTransformer` inside an end-to-end `Pipeline`.

---

## 3. Model Evaluation & Benchmark Comparison

Four candidate multi-class classification algorithms were evaluated under identical stratified test split conditions:

| Algorithm Name | Test Accuracy | Macro Precision | Macro Recall | Macro F1-Score | Weighted F1-Score | Train Time (s) | Inference Speed (ms/sample) |
|---|---|---|---|---|---|---|---|
| **Logistic Regression** | 93.18% | 0.9412 | 0.9792 | 0.8915 | 0.9388 | 0.52s | 0.012ms |
| **Decision Tree** | 99.06% | 0.9754 | 0.9911 | 0.9762 | 0.9907 | 0.03s | 0.008ms |
| **Random Forest** | 99.06% | 0.9754 | 0.9911 | 0.9762 | 0.9907 | 0.24s | 0.025ms |
| **HistGradientBoosting** *(Winner)* | **99.75%** | **0.9905** | **0.9932** | **0.9918** | **0.9975** | 0.93s | 0.015ms |

### Winner Rationale
`HistGradientBoosting` achieved the highest Macro F1-score (**0.9918**) and Macro Recall (**0.9932**), demonstrating exceptional detection across both majority (`BENIGN`) and minority classes (`Infiltration` and `Web Attack`).

---

## 4. Model Artifacts & Serialization

* **Serialized Pipeline Binary**: `ml/models/best_threat_model.joblib`
* **Model Metadata JSON**: `ml/models/metadata.json`
* **Confusion Matrix Plot**: `ml/evaluation/figures/confusion_matrix.png`
* **Classification Report JSON**: `ml/evaluation/reports/classification_report.json`
* **Experiment Results CSV**: `ml/evaluation/experiment_results.csv`

---

## 5. Academic Disclaimer & Limitations

> **Academic Prototype Notice**: This ML model is a research prototype trained on benchmark flow data.
> * It does not guarantee 100% real-world detection or zero-day protection.
> * Predictions represent statistical probability estimates based on feature distributions.
> * Operational deployments must pair ML model confidence with human analyst review and rule-based risk evaluation.
