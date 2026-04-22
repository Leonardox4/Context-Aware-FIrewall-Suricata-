# Runtime Pipeline Overview

This document summarizes the end-to-end runtime pipeline and the roles of each
model and correlation stage.

## Stage-1: Binary Detection

Stage-1 is the primary decision engine for the firewall:

- **Models**:
  - Isolation Forest (anomaly detector)
  - Binary RandomForest classifier (benign vs attack)
- **Inputs**:
  - Canonical feature vector (24 canonical + 8 behavioral features).
- **Outputs**:
  - `stage1_prediction`: `"benign"` or `"attack"` (derived from decision LOW/MEDIUM/HIGH)
  - `stage1_confidence`: binary RF `malicious_probability` (P(attack))
- **Effect on firewall**:
  - `stage1_prediction == "benign"` → allow
  - `stage1_prediction == "attack"` → block (subject to ContextEngine overrides)

The RiskEngine combines anomaly score, binary probability, and optional
severity into a single `risk_score`, which is mapped to LOW/MEDIUM/HIGH and
then to allow/alert/block actions.

## Stage-2 Attack Classification

Stage-2 is an **optional** classifier used only for logging and telemetry. It
does **not** influence firewall decisions.

- **Model type**: `RandomForestClassifier`
- **Model path**: `models/stage2_attack_classifier.joblib`
- **Task**: Multi-class attack classification.
- **Classes**:
  - `Bot`
  - `Backdoor`
  - `DoS`
  - `DDoS`
  - `Bruteforce`
  - `Recon`
  - `WebAttacks`

### Inputs

- Uses the **same feature vector** that Stage-1 operates on (the scaled feature
  matrix for the current chunk).
- Runs **only** for rows where Stage-1 predicts `"attack"` (i.e. HIGH/MEDIUM
  decision classes).

### Outputs

- `stage2_attack_family`: one of the attack family labels above, or `null` when:
  - the Stage-2 model file is missing,
  - prediction fails,
  - or the flow is classified as benign by Stage-1.

### Training Stage-2

Stage-2 is optional. If you want non-null `stage2_attack_family` values, you must train and save the model.

The runtime looks for the model in:

1. `<artifacts_dir>/stage2_attack_classifier.joblib` (preferred)
2. `models/stage2_attack_classifier.joblib` (project-level fallback)

```bash
python training/RF_attack_Randomforest_training_pipeline.py \
  --eve /path/to/labeled_eve.json \
  --labels-csv /path/to/rf_labels.csv \
  --artifacts-in /path/to/artifacts_dir \
  --output-model /path/to/artifacts_dir/stage2_attack_classifier.joblib
```

Requirements:

- `--labels-csv` must include `attack_type` (or `attack_subclass`) for attack rows. The training script maps it into one of:
  `Bot`, `Backdoor`, `DoS`, `DDoS`, `Bruteforce`, `Recon`, `WebAttacks`.
- If your dataset uses different names, provide a mapping file:

```bash
python training/RF_attack_Randomforest_training_pipeline.py ... \
  --family-map-json /path/to/family_map.json
```

Where `family_map.json` is a JSON object like:

```json
{
  "portscan": "Recon",
  "sql_injection": "WebAttacks"
}
```

### Integration

The Stage-2 classifier is wired into `inference/runtime_scoring.py` as follows:

1. Stage-1 computes:
   - anomaly score (IF),
   - malicious_probability (binary RF),
   - risk_score and decision,
   - action (ALLOW/ALERT/BLOCK).
2. For each event where Stage-1 decision is `"attack"` (MEDIUM/HIGH), Stage-2:
   - takes the corresponding row from the scaled feature matrix,
   - predicts `stage2_attack_family`.
3. The result is **only** appended to the decision log; it does **not** change
   `decision` or `action`.

If `models/stage2_attack_classifier.joblib` does not exist, Stage-2 is treated
as disabled; the pipeline behaves exactly as before and logs
`stage2_attack_family = null`.

## Decision Logging

Decisions are written in JSONL format to:

- `logs/decisions.jsonl`

Each line is a single JSON object that includes, among other fields:

- `src_ip`, `dst_ip`, `dst_port`
- `stage1_prediction`: `"benign"` or `"attack"`
- `stage1_confidence`: float (binary RF `malicious_probability`)
- `stage2_attack_family`: attack family string or `null`
- `malicious_probability`: same as `stage1_confidence`
- `attack_type`: optional multiclass RF output (if `rf_multiclass.joblib` present)
- `attack_confidence`: optional multiclass RF max probability
- `anomaly_score`: IF anomaly score (0–1)
- `context_signals`: list of context event types that applied to this flow
- `decision`: `"block"`, `"alert"`, or `"allow"`
- Legacy:
  - `classification`: `"attack"` or `"benign"` (derived from decision)
  - `risk_score`
  - `action`
  - `model_source`

### Example (attack)

```json
{
  "timestamp": "...",
  "src_ip": "10.0.0.5",
  "dst_ip": "10.0.0.10",
  "dst_port": 80,

  "stage1_prediction": "attack",
  "stage1_confidence": 0.97,

  "stage2_attack_family": "DoS",

  "decision": "block"
}
```

### Example (benign)

```json
{
  "stage1_prediction": "benign",
  "stage1_confidence": 0.88,
  "stage2_attack_family": null,
  "decision": "allow"
}
```

