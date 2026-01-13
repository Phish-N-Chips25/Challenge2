"""
Fetch CVEs from NVD (v2.0) and MITRE, extract affected software/versions, and append to dataset CSV.

Extracted fields (mapped to your dataset schema):
  - cve_id, base_severity, base_score, exploitability_score, impact_score
  - attack_vector, attack_complexity, privileges_required, user_interaction, scope
  - confidentiality_impact, integrity_impact, availability_impact, published_date
  - affected_software, affected_versions

Usage examples:
  # Append specific CVE IDs
  python update_dataset_with_nvd.py --cves CVE-2023-1234,CVE-2021-0001

  # Read CVEs from file (one per line)
  python update_dataset_with_nvd.py --cve-file new_cves.txt

  # Append recently modified CVEs from last 3 days
  python update_dataset_with_nvd.py --recent-days 3

Options:
- --dest defaults to cve_cisa_epss_enriched_dataset.csv
- Set NVD API key via --api-key or environment variable NVD_API_KEY (higher rate limits)
- --sleep: delay between requests when no API key (default 0.65s)

Notes:
- Extracts affected software/versions from both NVD and MITRE; NVD is tried first
- Schema alignment: only columns in destination CSV are written; extras are dropped
- Creates timestamped backup before writing
- After appending, re-run: python prepare_dataset_for_ml.py && python train_ml_models.py
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import pandas as pd

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    from urllib import request, parse, error


DEST_DEFAULT = "cve_cisa_epss_enriched_dataset.csv"
CVE_COL = "cve_id"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
RATE_LIMIT_SECONDS = 0.65


def fetch_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 30) -> Optional[Dict]:
    """Fetch JSON from URL using requests if available, else urllib."""
    if HAS_REQUESTS:
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            return None
    else:
        req = request.Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None


def extract_affected_from_nvd(cve: Dict) -> Optional[Dict[str, Optional[str]]]:
    """Extract affected_software and affected_versions from NVD CVE data."""
    software: Set[str] = set()
    versions: Set[str] = set()
    
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria") or cpe_match.get("cpe23Uri") or ""
                if not criteria.startswith("cpe:2.3:"):
                    continue
                parts = criteria.split(":")
                if len(parts) > 4:
                    vendor, product = parts[3], parts[4]
                    if vendor not in {"*", "-"} and product not in {"*", "-"}:
                        software.add(f"{vendor}:{product}")
                # Extract version info
                if len(parts) > 5 and parts[5] not in {"*", "-"}:
                    versions.add(parts[5])
                for bound_key in ("versionStartIncluding", "versionStartExcluding",
                                 "versionEndIncluding", "versionEndExcluding"):
                    if cpe_match.get(bound_key):
                        versions.add(str(cpe_match[bound_key]))
    
    if not software and not versions:
        return None
    return {
        "affected_software": ", ".join(sorted(software)) if software else None,
        "affected_versions": ", ".join(sorted(versions)) if versions else None,
    }


def extract_affected_from_mitre(data: Dict) -> Optional[Dict[str, Optional[str]]]:
    """Extract affected_software and affected_versions from MITRE CVE data."""
    software: Set[str] = set()
    versions: Set[str] = set()
    
    containers = data.get("containers", {}) if isinstance(data, dict) else {}
    sections = []
    
    # CNA section
    cna = containers.get("cna")
    if isinstance(cna, dict):
        sections.append(cna.get("affected", []))
    
    # ADP sections
    for adp in containers.get("adp", []) or []:
        if isinstance(adp, dict):
            sections.append(adp.get("affected", []))
    
    # Extract software and versions
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
            # Extract versions
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


def extract_cvss_metrics(cve: Dict) -> Dict[str, Optional[str]]:
    """Extract CVSS metrics from NVD CVE data."""
    row: Dict[str, Optional[str]] = {
        "base_score": None,
        "base_severity": None,
        "exploitability_score": None,
        "impact_score": None,
        "attack_vector": None,
        "attack_complexity": None,
        "privileges_required": None,
        "user_interaction": None,
        "scope": None,
        "confidentiality_impact": None,
        "integrity_impact": None,
        "availability_impact": None,
    }
    
    metrics = cve.get("metrics", {})
    
    # Prefer v3.1 > v3.0 > v2.0
    for metric_key in ("cvssMetricV31", "cvssMetricV30"):
        if metric_key in metrics and metrics[metric_key]:
            cvss_data = metrics[metric_key][0].get("cvssData", {})
            row["base_score"] = cvss_data.get("baseScore")
            row["base_severity"] = cvss_data.get("baseSeverity")
            row["attack_vector"] = cvss_data.get("attackVector")
            row["attack_complexity"] = cvss_data.get("attackComplexity")
            row["privileges_required"] = cvss_data.get("privilegesRequired")
            row["user_interaction"] = cvss_data.get("userInteraction")
            row["scope"] = cvss_data.get("scope")
            row["confidentiality_impact"] = cvss_data.get("confidentialityImpact")
            row["integrity_impact"] = cvss_data.get("integrityImpact")
            row["availability_impact"] = cvss_data.get("availabilityImpact")
            # v3 includes impact scores
            row["impact_score"] = metrics[metric_key][0].get("impactScore")
            row["exploitability_score"] = metrics[metric_key][0].get("exploitabilityScore")
            return row
    
    # Fallback to v2.0 if v3 not available
    if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
        row["base_score"] = cvss_data.get("baseScore")
        row["attack_vector"] = cvss_data.get("accessVector")  # v2: accessVector
        row["attack_complexity"] = cvss_data.get("accessComplexity")  # v2: accessComplexity
        row["privileges_required"] = cvss_data.get("authentication")  # v2: authentication
        row["confidentiality_impact"] = cvss_data.get("confidentialityImpact")
        row["integrity_impact"] = cvss_data.get("integrityImpact")
        row["availability_impact"] = cvss_data.get("availabilityImpact")
        # v2 impact/exploitability
        row["impact_score"] = metrics["cvssMetricV2"][0].get("impactScore")
        row["exploitability_score"] = metrics["cvssMetricV2"][0].get("exploitabilityScore")
    
    return row


def fetch_cve_data(cve_id: str, api_key: Optional[str]) -> Optional[Dict]:
    """Fetch CVE data from NVD and extract CVSS + affected software/versions."""
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    
    data = fetch_json(url, headers=headers)
    if not data or not data.get("vulnerabilities"):
        return None
    
    cve = data["vulnerabilities"][0].get("cve")
    if not cve:
        return None
    
    row = {CVE_COL: cve.get("id"), "published_date": cve.get("published")}
    
    # Extract CVSS metrics
    row.update(extract_cvss_metrics(cve))
    
    # Try NVD first for affected software/versions
    affected = extract_affected_from_nvd(cve)
    if affected:
        row.update(affected)
        return row
    
    # Fallback to MITRE if NVD doesn't have software info
    mitre_data = fetch_json(MITRE_API_URL.format(cve_id=cve_id), headers={"Accept": "application/json"})
    if mitre_data:
        affected = extract_affected_from_mitre(mitre_data)
        if affected:
            row.update(affected)
    
    return row


def fetch_recent_from_nvd(days: int, api_key: Optional[str]) -> List[Dict]:
    """Fetch recently modified CVEs from NVD."""
    end = datetime.utcnow()
    start = end - timedelta(days=days)
    start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_str = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    
    url = f"{NVD_API_URL}?lastModStartDate={start_str}&lastModEndDate={end_str}&resultsPerPage=2000&startIndex=0"
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    
    data = fetch_json(url, headers=headers)
    rows: List[Dict] = []
    
    if not data or not data.get("vulnerabilities"):
        print(f"[WARN] No CVEs modified in last {days} days")
        return rows
    
    for v in data["vulnerabilities"]:
        cve = v.get("cve")
        if not cve:
            continue
        row = {CVE_COL: cve.get("id"), "published_date": cve.get("published")}
        row.update(extract_cvss_metrics(cve))
        affected = extract_affected_from_nvd(cve)
        if affected:
            row.update(affected)
        rows.append(row)
    
    print(f"[OK] Fetched {len(rows)} recent CVEs from NVD")
    return rows

def make_backup(path: str) -> Optional[str]:
    """Create timestamped backup of CSV file."""
    if not os.path.exists(path):
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{os.path.splitext(path)[0]}.backup-{ts}.csv"
    try:
        os.replace(path, backup)
        print(f"[OK] Backup created: {backup}")
        return backup
    except Exception as exc:
        print(f"[WARN] Could not create backup: {exc}")
        return None


def append_rows(dest_path: str, rows: List[Dict]) -> int:
    """Append new CVE rows to destination CSV, preserving schema and deduplicating."""
    if not rows:
        return 0
    
    # Load or create destination
    if os.path.exists(dest_path):
        dst = pd.read_csv(dest_path)
        if CVE_COL not in dst.columns:
            print(f"[ERROR] Destination CSV must contain '{CVE_COL}'. Found: {list(dst.columns)}")
            return 0
    else:
        # Create new CSV with required columns from first row
        if rows:
            dst = pd.DataFrame(columns=[CVE_COL])
        else:
            return 0
    
    existing = set(str(v).upper() for v in dst[CVE_COL].astype(str))
    
    # Prepare DataFrame from fetched rows
    df = pd.DataFrame(rows)
    if df.empty:
        return 0
    
    # Normalize cve_id case
    df[CVE_COL] = df[CVE_COL].astype(str).str.upper()
    
    # Deduplicate: drop CVEs already in destination
    df = df[~df[CVE_COL].isin(existing)]
    if df.empty:
        print("[INFO] All CVEs already exist in destination.")
        return 0
    
    # Align to destination schema: fill missing columns, drop extras
    for col in dst.columns:
        if col not in df.columns:
            df[col] = None
    df = df[dst.columns]
    
    # Backup and write
    if os.path.exists(dest_path):
        backup = make_backup(dest_path)
        if backup is None:
            print("[WARN] Proceeding without backup.")
    
    new_dst = pd.concat([dst, df], ignore_index=True)
    new_dst.to_csv(dest_path, index=False)
    print(f"[OK] Appended {len(df)} rows to {dest_path}")
    return len(df)

def main():
    parser = argparse.ArgumentParser(description="Fetch CVEs from NVD and append to dataset CSV.")
    parser.add_argument("--dest", default=DEST_DEFAULT, help="Destination training CSV to append to")
    parser.add_argument("--cves", help="Comma-separated CVE IDs (e.g., CVE-2023-1234,CVE-2021-0001)")
    parser.add_argument("--cve-file", help="Path to a file with one CVE ID per line")
    parser.add_argument("--recent-days", type=int, help="Fetch CVEs modified within the given number of days")
    parser.add_argument("--api-key", help="NVD API key (defaults to env NVD_API_KEY)")
    parser.add_argument("--sleep", type=float, default=0.65, help="Delay between requests (seconds) when no API key")
    args = parser.parse_args()

    api_key = args.api_key or os.getenv("NVD_API_KEY")
    rows: List[Dict] = []

    # Load existing CVE IDs from destination
    existing_cves: Set[str] = set()
    if os.path.exists(args.dest):
        try:
            dst = pd.read_csv(args.dest)
            if CVE_COL in dst.columns:
                existing_cves = set(str(v).upper() for v in dst[CVE_COL].astype(str))
        except Exception as e:
            print(f"[WARN] Could not load existing CVEs from {args.dest}: {e}")

    # Collect CVEs to fetch
    cve_ids: List[str] = []
    if args.cves:
        cve_ids.extend([c.strip().upper() for c in args.cves.split(",") if c.strip()])
    if args.cve_file:
        with open(args.cve_file, "r", encoding="utf-8") as f:
            cve_ids.extend([line.strip().upper() for line in f if line.strip()])
    
    # Deduplicate input list
    cve_ids = sorted(set(cve_ids))

    if cve_ids:
        # Filter out CVEs already in dataset
        new_cves = [cve for cve in cve_ids if cve not in existing_cves]
        skipped = len(cve_ids) - len(new_cves)
        
        if skipped > 0:
            print(f"[INFO] {skipped} CVE(s) already in dataset (skipped)")
        
        if new_cves:
            print(f"[INFO] Fetching {len(new_cves)} new CVEs from NVD...")
            for idx, cve in enumerate(new_cves, 1):
                row = fetch_cve_data(cve, api_key)
                if row:
                    rows.append(row)
                    print(f"  ✓ {cve}")
                else:
                    print(f"  ✗ {cve} (no data)")
                # Rate-limit if no key
                if not api_key and idx < len(new_cves):
                    time.sleep(args.sleep)
        else:
            print("[INFO] All CVEs already in dataset.")
    elif args.recent_days:
        rows = fetch_recent_from_nvd(args.recent_days, api_key)
    else:
        print("[ERROR] Provide --cves, --cve-file, or --recent-days.")
        sys.exit(1)

    appended = append_rows(args.dest, rows)
    if appended > 0:
        print("\n" + "="*70)
        print("✅ Success! Next steps:")
        print("="*70)
        print("1. Refresh features:  python prepare_dataset_for_ml.py")
        print("2. Retrain models:    python train_ml_models.py")
        print("="*70 + "\n")
    else:
        print("\n[INFO] No changes made to destination CSV.")

if __name__ == "__main__":
    main()
