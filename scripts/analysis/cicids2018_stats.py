import pandas as pd
from pathlib import Path
from collections import Counter
import argparse

CHUNK_SIZE = 500000


def analyze_file(file_path):

    benign = 0
    attack = 0
    subclasses = Counter()

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        # remove duplicate header rows inside file
        chunk = chunk[chunk["Label"] != "Label"]

        labels = chunk["Label"]

        benign_count = (labels == "Benign").sum()
        attack_count = len(labels) - benign_count

        benign += benign_count
        attack += attack_count

        attack_labels = labels[labels != "Benign"]
        subclasses.update(attack_labels)

    return benign, attack, subclasses


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("csv_dir")
    args = parser.parse_args()

    csv_dir = Path(args.csv_dir)

    csv_files = sorted(csv_dir.glob("*.csv"))

    if not csv_files:
        print("No CSV files found")
        return

    print("\n============================")
    print(" CICIDS2018 DAILY STATISTICS")
    print("============================\n")

    for file in csv_files:

        benign, attack, subclasses = analyze_file(file)

        total = benign + attack
        ratio = (attack / total) * 100 if total else 0

        print(f"{file.name}")
        print("-" * 60)

        print(f"Total flows : {total:,}")
        print(f"Benign      : {benign:,}")
        print(f"Attack      : {attack:,}")
        print(f"Attack %    : {ratio:.2f}%")

        print("\nAttack subclasses:")

        if attack == 0:
            print("  None")

        else:
            for attack_type, count in subclasses.most_common():
                print(f"  {attack_type:30} {count:,}")

        print("\n")


if __name__ == "__main__":
    main()
