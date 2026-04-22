import pandas as pd
import glob
import os

OUTPUT_FILE = "attack_merged.csv"
CHUNK_SIZE = 200_000  # adjust based on RAM

files = sorted(glob.glob("attack_*.csv"))

if not files:
    raise ValueError("No attack CSV files found")

print(f"[+] Found {len(files)} attack files")

# Step 1: Extract canonical columns from first file
base_df = pd.read_csv(files[0], nrows=5)
columns = list(base_df.columns)

print(f"[+] Canonical schema ({len(columns)} columns):")
print(columns)

# Step 2: Initialize output
if os.path.exists(OUTPUT_FILE):
    os.remove(OUTPUT_FILE)

# Step 3: Process each file safely
for file in files:
    print(f"[+] Processing: {file}")

    for chunk in pd.read_csv(file, chunksize=CHUNK_SIZE):
        # Remove accidental duplicate header rows
        chunk = chunk[chunk.columns]
        chunk = chunk[chunk.iloc[:,0] != chunk.columns[0]]

        # Align schema
        chunk = chunk.reindex(columns=columns)

        # Optional: enforce types (safe fallback)
        chunk = chunk.convert_dtypes()

        # Drop completely empty rows
        chunk = chunk.dropna(how='all')

        # Append
        chunk.to_csv(
            OUTPUT_FILE,
            mode='a',
            header=not os.path.exists(OUTPUT_FILE),
            index=False
        )

print("[+] Merge complete!")

# Step 4: Final validation
df = pd.read_csv(OUTPUT_FILE, nrows=1000)
print("\n[VALIDATION]")
print("Shape sample:", df.shape)
print("Nulls per column:\n", df.isnull().sum())
