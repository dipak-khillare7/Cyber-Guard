# Cybersecurity Dataset Documentation — CIC-IDS2017

## 1. Dataset Overview

* **Dataset Name**: CIC-IDS2017 (Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset 2017)
* **Dataset Source**: University of New Brunswick / Canadian Institute for Cybersecurity (CIC)
* **Dataset Version**: 2017 Flow Benchmark Subset
* **Usage License**: Academic & Educational Research Use
* **Primary Target Column**: `Label`
* **Total Records Ingested**: 10,750
* **Total Features**: 11 raw flow attributes + 1 label column

---

## 2. Raw Class Distribution & Label Counts

| Raw Dataset Label | Record Count | Percentage | Standardized Threat Category |
|---|---|---|---|
| `BENIGN` | 5,000 | 46.51% | `NORMAL` |
| `DoS Hulk` | 1,500 | 13.95% | `DOS_DDOS` |
| `PortScan` | 1,200 | 11.16% | `PORT_SCAN` |
| `DDoS` | 1,000 | 9.30% | `DOS_DDOS` |
| `FTP-Patator` | 600 | 5.58% | `BRUTE_FORCE` |
| `SSH-Patator` | 500 | 4.65% | `BRUTE_FORCE` |
| `Bot` | 400 | 3.72% | `BOTNET` |
| `Web Attack – Brute Force` | 300 | 2.79% | `WEB_ATTACK` |
| `Infiltration` | 150 | 1.40% | `INFILTRATION` |
| **Duplicates Filtered** | 100 | 0.93% | Deduplicated in cleaning pipeline |
| **Total Ingested** | **10,750** | **100.00%** | **7 Standardized Threat Classes** |

---

## 3. Label Mapping & Coverage Analysis

The dataset supports **7 distinct threat categories**:

1. `NORMAL` (Mapped from `BENIGN`)
2. `DOS_DDOS` (Mapped from `DoS Hulk`, `DDoS`)
3. `PORT_SCAN` (Mapped from `PortScan`)
4. `BRUTE_FORCE` (Mapped from `FTP-Patator`, `SSH-Patator`)
5. `WEB_ATTACK` (Mapped from `Web Attack – Brute Force`)
6. `BOTNET` (Mapped from `Bot`)
7. `INFILTRATION` (Mapped from `Infiltration`)

### Planned Categories Not Present in Dataset:
* `DATA_EXFILTRATION`: Exfiltration traffic requires specialized payload analysis datasets and is absent from standard CIC-IDS2017 flow statistics.
* `MALWARE`: Host-based malware execution traces are not present in network flow records.
* `CREDENTIAL_ATTACK`: Partially overlaps with `BRUTE_FORCE` (`SSH-Patator`/`FTP-Patator`), but not present as a separate label.

---

## 4. Known Dataset Limitations

1. **Synthetic Class Imbalance**: High frequency of normal traffic (`BENIGN`) relative to minority attack vectors like `Infiltration` (1.4%).
2. **Missing Feature Payload**: Network flow features consist of numerical flow timing, packet counts, and TCP flags; raw packet payloads are excluded.
