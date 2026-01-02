import csv
import json
import pandas as pd
from pathlib import Path

DATASET_PATH = Path("cve_cisa_epss_enriched_dataset.csv")
CACHE_PATH = Path("nvd_response_cache.json")
OUTPUT_PATH = Path("cve_cisa_epss_enriched_dataset_with_nvd.csv")

def detect_delimiter(path: Path) -> str:
    """Guess the delimiter of the CSV file (defaults to comma)."""
    try:
        sample = path.read_text(encoding="utf-8", errors="ignore")[:8192]
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return ","

def enrich_csv():
    print("\n" + "="*70)
    print("CVE Dataset Enricher with NVD Cache")
    print("="*70)
    
    # Load cache
    print(f"\n📂 Loading cache from {CACHE_PATH}...")
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as handle:
            cache = json.load(handle)
            print(f"✓ Cache loaded: {len(cache)} CVE entries")
    except Exception as e:
        print(f"[ERROR] Failed to load cache: {e}")
        return
    
    # Load dataset with detected delimiter
    print(f"\n📄 Loading dataset from {DATASET_PATH}...")
    delim = detect_delimiter(DATASET_PATH)
    print(f"   Detected delimiter: '{delim}'")
    try:
        df = pd.read_csv(DATASET_PATH, sep=delim, engine="python")
        print(f"✓ Dataset loaded: {len(df)} rows, {len(df.columns)} columns")
    except Exception as e:
        print(f"[ERROR] Failed to load dataset: {e}")
        return
    
    # Add new columns
    print(f"\n🔍 Adding affected_software and affected_versions columns...")
    df["affected_software"] = df["cve_id"].apply(
        lambda cve_id: cache.get(cve_id, {}).get("affected_software") if isinstance(cve_id, str) else None
    )
    df["affected_versions"] = df["cve_id"].apply(
        lambda cve_id: cache.get(cve_id, {}).get("affected_versions") if isinstance(cve_id, str) else None
    )
    
    # Count enriched entries
    software_filled = df["affected_software"].notna().sum()
    versions_filled = df["affected_versions"].notna().sum()
    print(f"✓ affected_software: {software_filled} entries filled")
    print(f"✓ affected_versions: {versions_filled} entries filled")
    
    # Save output using the same delimiter and quoting to protect commas inside fields
    print(f"\n💾 Saving enriched dataset to {OUTPUT_PATH}...")
    try:
        df.to_csv(OUTPUT_PATH, index=False, sep=delim, quoting=csv.QUOTE_MINIMAL)
        print(f"✓ Dataset saved successfully!")
        print(f"\n📊 Output file: {OUTPUT_PATH}")
        print(f"   - Total rows: {len(df)}")
        print(f"   - Total columns: {len(df.columns)}")
    except Exception as e:
        print(f"[ERROR] Failed to save dataset: {e}")
        return
    
    print("\n" + "="*70)
    print("✅ Enrichment Complete!")
    print("="*70 + "\n")


if __name__ == "__main__":
    try:
        enrich_csv()
    except Exception as e:
        print(f"\n[FATAL ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
