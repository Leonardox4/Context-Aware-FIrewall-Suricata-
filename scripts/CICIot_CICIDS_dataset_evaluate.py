#!/usr/bin/env python3

import pandas as pd
import sys
from collections import Counter
from pathlib import Path

CHUNK_SIZE = 200000  # adjust if needed


# ---------- label column detection ----------
def find_label_column(columns):
    candidates = [
        "Label", "label",
        "Attack", "attack",
        "Class", "class",
        "Category", "category"
    ]

    for c in candidates:
        if c in columns:
            return c

    raise ValueError("Could not find label column in dataset.")


# ---------- normalize labels ----------
def normalize_label(val):
    v = str(val).strip().lower()

    if v in ["benign", "normal", "background", "0"]:
        return "benign"

    return v


# ---------- evaluate dataset ----------
def evaluate_dataset(file_list):
    total = 0
    benign = 0
    attack_counts = Counter()
    label_col = None

    for file_path in file_list:
        print(f"\nProcessing: {file_path}")

        try:
            for chunk in pd.read_csv(file_path, chunksize=CHUNK_SIZE):
                # Clean column names (IMPORTANT for CICIDS)
                chunk.columns = chunk.columns.str.strip()

                if label_col is None:
                    label_col = find_label_column(chunk.columns)

                labels = chunk[label_col].apply(normalize_label)

                total += len(labels)
                benign += (labels == "benign").sum()

                for val in labels:
                    if val != "benign":
                        attack_counts[val] += 1

        except Exception as e:
            print(f"[WARNING] Skipping {file_path}: {e}")

    if total == 0:
        print("No data processed.")
        return

    attack_total = total - benign

    print("\n==============================")
    print("DATASET SUMMARY")
    print("==============================")
    print(f"Total flows : {total:,}")
    print(f"Benign      : {benign:,} ({benign/total*100:.2f}%)")
    print(f"Attack      : {attack_total:,} ({attack_total/total*100:.2f}%)")

    if attack_counts:
        print("\nATTACK BREAKDOWN")
        print("------------------------------")
        for k, v in attack_counts.most_common():
            print(f"{k:<20} {v:,} ({v/total*100:.2f}%)")


# ---------- main ----------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python dataset_evaluate.py *.csv")
        sys.exit(1)

    # Expand file list safely
    files = [str(Path(f)) for f in sys.argv[1:]]

    evaluate_dataset(files)