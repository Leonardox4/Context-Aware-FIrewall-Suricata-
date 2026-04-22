import pandas as pd
import glob
import os
from concurrent.futures import ProcessPoolExecutor

OUTPUT_FILE = "benign_flow_merged.csv"
CHUNK_SIZE = 100_000
# Only these columns to keep the memory footprint tiny
COLS_TO_KEEP = [
    'dataset_day', 'timestamp', 'event_type', 'src_ip', 'dst_ip',
    'src_port', 'dst_port', 'proto', 'flow_id', 'label', 'attack_type'
]

def process_single_file(file):
    """Worker function to filter a single file."""
    temp_output = f"temp_{os.path.basename(file)}"
    total_in_file = 0

    print(f"[*] Core assigned to: {file}")

    try:
        # Usecols lambda handles messy whitespace in headers across different datasets
        reader = pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False,
            usecols=lambda x: x.strip() in COLS_TO_KEEP
        )

        for chunk in reader:
            chunk.columns = chunk.columns.str.strip()
            # Keep ONLY 'flow'
            mask = chunk['event_type'].astype(str).str.strip().str.lower() == 'flow'
            flow_chunk = chunk[mask].copy()

            if not flow_chunk.empty:
                total_in_file += len(flow_chunk)
                flow_chunk.to_csv(
                    temp_output,
                    mode='a',
                    index=False,
                    header=not os.path.exists(temp_output)
                )
        return temp_output, total_in_file
    except Exception as e:
        print(f"[!] Error on {file}: {e}")
        return None, 0

def main():
    benign_files = glob.glob("benign_*.csv")
    print(f"[+] Starting Parallel Extraction on {len(benign_files)} files...")

    # 1. Parallel Processing
    results = []
    with ProcessPoolExecutor() as executor:
        results = list(executor.map(process_single_file, sorted(benign_files)))

    # 2. Final Consolidation
    print("\n[*] Consolidation phase: Merging temp files...")
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    final_count = 0
    first_file = True

    for temp_file, count in results:
        if temp_file and os.path.exists(temp_file):
            # Append temp file to master using shell for speed
            # Using 'header' logic to ensure only one header exists
            df_temp = pd.read_csv(temp_file)
            df_temp.to_csv(OUTPUT_FILE, mode='a', index=False, header=first_file)
            first_file = False
            final_count += count
            os.remove(temp_file) # Clean up

    print(f"\n[DONE] Created {OUTPUT_FILE}")
    print(f"[+] Total clean Benign flows extracted: {final_count}")

if __name__ == "__main__":
    main()
