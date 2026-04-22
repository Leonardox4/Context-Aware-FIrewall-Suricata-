# CICIDS_1 Dataset Analysis Report

**Directory:** `Datasets/AttackHeavy/CICIDS2017_1`
**CSV files:** 1

## 1. Dataset Summary

| Metric | Value |
|--------|-------|
| Total flows/samples | 2,520,751 |
| Benign samples | 2,095,057 |
| Attack samples | 425,694 |
| Benign % | 83.11%
| Attack % | 16.89%

## 2. Per-file Summary

| File | Rows | Benign | Attack | Missing labels |
|------|------|--------|--------|----------------|
| cicids2017_cleaned.csv | 2,520,751 | 2,095,057 | 425,694 | 0 |

## 3. Attack Breakdown

| Attack type | Count | % of total | % of attacks |
|-------------|-------|------------|--------------|
| DoS | 193,745 | 7.69% | 45.51% |
| DDoS | 128,014 | 5.08% | 30.07% |
| Port Scanning | 90,694 | 3.60% | 21.30% |
| Brute Force | 9,150 | 0.36% | 2.15% |
| Web Attacks | 2,143 | 0.09% | 0.50% |
| Bots | 1,948 | 0.08% | 0.46% |
| **Total attacks** | **425,694** | **16.89%** | 100% |

## 4. Data Quality

- **Missing/empty labels:** 0
- **Schema consistency:** All files have same columns.

## 5. Preprocessing Recommendations

1. **Binary label:** Map 'Normal Traffic' / BENIGN → 0, all other attack types → 1.
2. **Stratified split:** Stratify by label and optionally by attack type.
3. **Class imbalance:** Use `class_weight='balanced'` or oversample minority (attacks).
4. **Attack type:** Normalize strings (strip, consistent case) for reproducibility.
5. **Model2 alignment:** Map CICIDS columns to unified schema (see ingestion/unified_schema normalize_cic_features).
