import argparse
import json
import time
from pathlib import Path
from typing import Dict, Optional

import pandas as pd
import requests

DATASET_PATH = Path("cve_cisa_epss_enriched_dataset.csv")
CACHE_PATH = Path("nvd_response_cache.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
RATE_LIMIT_SECONDS = 0.65
API_KEY = "f1a20307-00be-4fce-85a4-59651d5c99d2"

NVD_HEADERS = {
    "apiKey": API_KEY,
    "User-Agent": "CVE-cache-enricher",
    "Accept": "application/json",
}
MITRE_HEADERS = {
    "User-Agent": NVD_HEADERS["User-Agent"],
    "Accept": "application/json",
}

_session = requests.Session()
_last_call = 0.0


def _respect_rate_limit():
    global _last_call
    now = time.monotonic()
    delay = RATE_LIMIT_SECONDS - (now - _last_call)
    if delay > 0:
        time.sleep(delay)
        now = time.monotonic()
    _last_call = now


def load_cache() -> Dict[str, Dict[str, Optional[str]]]:
    """Load entire cache once at startup."""
    if not CACHE_PATH.exists():
        return {}
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def load_cached_cve_ids() -> set:
    """Load only CVE IDs from cache (much smaller than loading all data)."""
    if not CACHE_PATH.exists():
        return set()
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            return set(data.keys()) if isinstance(data, dict) else set()
    except (OSError, json.JSONDecodeError):
        return set()


def get_cached_entry(cve_id: str) -> Optional[Dict[str, Optional[str]]]:
    """Load and return a single CVE entry from cache."""
    if not CACHE_PATH.exists():
        return None
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data.get(cve_id) if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def find_last_cached_position(cached_ids: set) -> int:
    """Return last row index in CSV that is already cached (for resume mode)."""
    if not cached_ids:
        return -1
    last_pos = -1
    pos = 0
    try:
        for chunk in pd.read_csv(DATASET_PATH, chunksize=4000, usecols=["cve_id"], low_memory=False):
            for _, row in chunk.iterrows():
                cve_id = row.get("cve_id")
                if isinstance(cve_id, str) and cve_id in cached_ids:
                    last_pos = pos
                pos += 1
    except Exception:
        return last_pos
    return last_pos


def save_cache(cache: Dict[str, Dict[str, Optional[str]]]):
    """Save cache to disk, sorted by key."""
    try:
        with CACHE_PATH.open("w", encoding="utf-8") as handle:
            json.dump(dict(sorted(cache.items())), handle, ensure_ascii=False, indent=2)
    except OSError as e:
        print(f"[ERROR] Failed to save cache: {e}")


def fetch_nvd(cve_id: str) -> Optional[Dict[str, Optional[str]]]:
    _respect_rate_limit()
    params = {"cveId": cve_id}
    try:
        resp = _session.get(NVD_URL, headers=NVD_HEADERS, params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})

    software = set()
    versions = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                criteria = cpe.get("criteria") or cpe.get("cpe23Uri") or ""
                if not criteria.startswith("cpe:2.3:"):
                    continue
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    if vendor not in {"*", "-"} and product not in {"*", "-"}:
                        software.add(f"{vendor}:{product}")
                if len(parts) > 5 and parts[5] not in {"*", "-"}:
                    versions.add(parts[5])
                for bound_key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"):
                    if cpe.get(bound_key):
                        versions.add(str(cpe[bound_key]))

    if not software and not versions:
        return None
    return {
        "affected_software": ", ".join(sorted(software)) if software else None,
        "affected_versions": ", ".join(sorted(versions)) if versions else None,
    }


def fetch_mitre(cve_id: str) -> Optional[Dict[str, Optional[str]]]:
    _respect_rate_limit()
    try:
        resp = _session.get(MITRE_URL.format(cve_id=cve_id), headers=MITRE_HEADERS, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    containers = data.get("containers", {}) if isinstance(data, dict) else {}
    sections = []
    cna = containers.get("cna")
    if isinstance(cna, dict):
        sections.append(cna.get("affected", []))
    for adp in containers.get("adp", []) or []:
        if isinstance(adp, dict):
            sections.append(adp.get("affected", []))

    software = set()
    versions = set()
    for section in sections:
        if not section:
            continue
        for entry in section:
            if not isinstance(entry, dict):
                continue
            vendor = entry.get("vendor") or ""
            product = entry.get("product") or ""
            if vendor and vendor not in {"*", "-"} and product and product not in {"*", "-"}:
                software.add(f"{vendor}:{product}")
            for v in entry.get("versions", []) or []:
                if not isinstance(v, dict):
                    continue
                val = v.get("version")
                if val and val not in {"*", "-", "unspecified"}:
                    versions.add(val)
                for key in ("greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual"):
                    if v.get(key):
                        versions.add(f"{key}:{v[key]}")

    if not software and not versions:
        return None
    return {
        "affected_software": ", ".join(sorted(software)) if software else None,
        "affected_versions": ", ".join(sorted(versions)) if versions else None,
    }


def enrich(mode: str):
    print("\n" + "="*70)
    print("CVE Cache Enricher Started")
    print(f"Mode: {mode}")
    print("="*70)
    
    # Count existing cache entries without loading all data
    existing_count = 0
    cached_cve_ids = load_cached_cve_ids()
    existing_count = len(cached_cve_ids)
    last_cached_pos = -1
    if mode == "resume":
        print("Finding last cached position in CSV (one pass)...")
        last_cached_pos = find_last_cached_position(cached_cve_ids)
        print(f"Last cached CSV row index: {last_cached_pos}")
    
    print(f"📂 Existing cache: {existing_count} CVEs")
    print(f"📄 Dataset: {DATASET_PATH}")
    print(f"💾 Cache file: {CACHE_PATH}")
    print("="*70 + "\n")
    
    chunk_size = 2000
    total_processed = 0
    skipped_cached = 0
    fetched_nvd = 0
    fetched_mitre = 0
    failed = 0
    
    try:
        row_index = 0
        for chunk_num, chunk in enumerate(pd.read_csv(DATASET_PATH, chunksize=chunk_size, usecols=["cve_id"], low_memory=False), start=1):
            print(f"\n📦 Processing chunk {chunk_num} ({len(chunk)} CVEs)...")
            
            chunk_saved = 0
            
            # Track new entries for this chunk only
            new_entries = {}
            
            try:
                for _, row in chunk.iterrows():
                    cve_id = row.get("cve_id")
                    if not isinstance(cve_id, str):
                        row_index += 1
                        continue

                    # Skip rows already covered in resume mode based on CSV order
                    if mode == "resume" and row_index <= last_cached_pos:
                        skipped_cached += 1
                        row_index += 1
                        continue

                    total_processed += 1
                    row_index += 1
                    
                    try:
                        # In resume mode: skip when cache already has usable info or known noisy multi-software/no-version entries
                        if mode == "resume" and (cve_id in cached_cve_ids or cve_id in new_entries):
                            cached = new_entries.get(cve_id) or get_cached_entry(cve_id)
                            if cached:
                                # Skip if we have complete data
                                if cached.get("affected_software") is not None and cached.get("affected_versions") is not None:
                                    skipped_cached += 1
                                    if total_processed % 50 == 0:
                                        print(f"  ✓ {total_processed} processed | {skipped_cached} cached | {fetched_nvd} NVD | {fetched_mitre} MITRE | {failed} failed")
                                    continue
                                
                                # Skip if cached CVE has multiple software but no versions (don't call NVD)
                                cached_software = cached.get("affected_software", "")
                                cached_versions = cached.get("affected_versions", "")
                                if cached_software:
                                    software_list = cached_software.split(", ")
                                    software_count = len([s for s in software_list if s])
                                    if software_count > 1 and not cached_versions:
                                        skipped_cached += 1
                                        print(f"  ⚠ Cached: {cve_id} has {software_count} software but no versions - skipping")
                                        continue

                        print(f"🔍 {cve_id}")
                        info = fetch_nvd(cve_id)
                        
                        # Keep NVD data even if multiple software are listed (only cached items are skipped earlier)
                        if info is not None:
                            fetched_nvd += 1
                            print(f"  ✓ NVD: {info.get('affected_software') or 'N/A'}")
                        else:
                            info = fetch_mitre(cve_id)
                            if info is not None:
                                fetched_mitre += 1
                                print(f"  ✓ MITRE: {info.get('affected_software') or 'N/A'}")
                            else:
                                failed += 1
                                print(f"  ✗ No data from any API")

                        # Store in new entries (not full cache yet)
                        new_entries[cve_id] = {
                            "affected_software": info.get("affected_software") if info else None,
                            "affected_versions": info.get("affected_versions") if info else None,
                        }
                        chunk_saved += 1
                    except Exception as e:
                        print(f"  [ERROR] Failed to process {cve_id}: {type(e).__name__}: {e}")
                        import traceback
                        traceback.print_exc()
                        failed += 1
                        continue

                # Save new entries: load cache, merge new ones, save
                if new_entries:
                    print(f"  💾 Merging {len(new_entries)} new entries into cache...")
                    cache = load_cache()
                    cache.update(new_entries)
                    save_cache(cache)
                    del cache  # Free immediately
                
                print(f"  ✓ Chunk {chunk_num}: {chunk_saved} new entries added")
                
                # Explicitly delete chunk and new_entries to free memory
                del chunk
                del new_entries
            except Exception as e:
                print(f"[ERROR] Failed processing chunk {chunk_num}: {type(e).__name__}: {e}")
                import traceback
                traceback.print_exc()
                # Save what we have so far
                try:
                    if new_entries:
                        cache = load_cache()
                        cache.update(new_entries)
                        save_cache(cache)
                        del cache
                    del new_entries
                except:
                    pass
                # Clean up chunk before breaking
                try:
                    del chunk
                except:
                    pass
                break
    except KeyboardInterrupt:
        print("\n[INFO] Processing interrupted by user")
    except Exception as e:
        print(f"[CRITICAL ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

    # Count final cache size without loading into memory
    final_count = 0
    if CACHE_PATH.exists():
        try:
            with CACHE_PATH.open("r", encoding="utf-8") as handle:
                temp_cache = json.load(handle)
                final_count = len(temp_cache)
                del temp_cache
        except (OSError, json.JSONDecodeError):
            final_count = 0

    print("\n" + "="*70)
    print("✅ Enrichment Complete!")
    print("="*70)
    print(f"Total CVEs processed: {total_processed}")
    print(f"  - Already cached (skipped): {skipped_cached}")
    print(f"  - Fetched from NVD: {fetched_nvd}")
    print(f"  - Fetched from MITRE: {fetched_mitre}")
    print(f"  - Failed (no data): {failed}")
    print(f"\n💾 Cache saved to: {CACHE_PATH}")
    print(f"📊 Total cached CVEs: {final_count}")
    print("="*70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE Cache Enricher")
    parser.add_argument(
        "--mode",
        choices=["resume", "recheck"],
        default="resume",
        help="resume: skip cached CVEs when possible (default); recheck: reprocess all CVEs regardless of cache",
    )
    args = parser.parse_args()

    try:
        enrich(args.mode)
    except Exception as e:
        print(f"\n[FATAL ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
