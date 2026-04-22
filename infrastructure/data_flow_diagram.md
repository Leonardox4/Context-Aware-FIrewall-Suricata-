# Model2 — Data Flow Diagrams

## Training Flow

```
CIC CSV (CICIDS2017 / CICIoT2023)
        |
        v
   [chunk_loader]  (optional, for large files)
        |
        v
   [cic_loader]  -->  flow rows + labels (attack/benign)
        |
        v
   [unified_schema]  -->  same feature names/types
        |
        v
   [Random Forest]  <--  train on labeled attacks (balanced weights)
        |
        v
   save RF + scaler
----------------------------------------------
Suricata eve.json (from PCAP or live)
        |
        v
   [suricata_loader]  -->  flow rows + has_alert
        |
        v
   [unified_schema]
        |
        v
   filter: benign only  -->  [Isolation Forest]
        |
        v
   save IF + scaler (or shared scaler)
```

**Recommended RF training (eve.json + ground-truth CSV):**  
eve.json → `iter_eve_chunks` (stream) → normalize_suricata_features + join with labels CSV (5-tuple or flow_key) → **incremental Parquet write** (training_dataset.parquet) → load Parquet → train/test split → scaler + RF fit → save artifacts. No full-dataset accumulation in RAM; cache allows skipping eve parse on reruns. Eval-only mode: load artifacts + (existing or built) eval Parquet → scale + predict → metrics only.

## Inference Flow

```
Suricata eve.json (live or file)
        |
        v
   [suricata_loader]  -->  flow rows
        |
        v
   [unified_schema]  -->  same features as training
        |
        v
   [scaler].transform
        |
        +----->  [Isolation Forest]  -->  anomaly_score (0-1)
        |
        +----->  [Random Forest]     -->  attack_probability (0-1)
        |
        +----->  alert_severity      -->  severity_score (0-1, from Suricata)
        |
        v
   [risk_engine]
        risk_score = w1*anomaly + w2*prob + w3*severity
        |
        v
   threshold check  -->  LOW / MEDIUM / HIGH
        |
        v
   [firewall_adapter_stub]  -->  ALLOW | ALERT | BLOCK
```

## Component Summary

| Component        | Input              | Output                    |
|-----------------|--------------------|---------------------------|
| cic_loader      | CIC CSV path       | List of (features, label) |
| suricata_loader | eve.json path     | List of (features, has_alert) |
| unified_schema  | Raw row/event      | Dict/vector of fixed features |
| Isolation Forest | Benign features  | Anomaly score 0–1         |
| Random Forest   | Labeled features   | Class probabilities       |
| risk_engine     | anomaly, prob, sev | risk_score, decision      |
