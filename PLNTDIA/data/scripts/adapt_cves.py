import pandas as pd
import random
import re

INPUT_CSV = "../../AAUTIA/cve_cisa_epss_enriched_dataset_with_nvd.csv"
OUTPUT_CSV = "cves_windows_ready_for_loader.csv"

CHUNK_SIZE = 100_000
YEARS_BACK = 6
TARGET_COUNT = 100

EXCLUDED_KEYWORDS = [
    "linux", "ubuntu", "debian", "redhat", "centos", "fedora", "suse", "alpine",
    "unix", "aix", "solaris", "freebsd", "openbsd", "netbsd",
    "android", "ios", "iphone", "ipad",
    "macos", "osx", "darwin", "huawei",
    "vxworks", "openwrt", "routeros",
    "linux_kernel", "cisco", "samsung", "nokia",
]

EPSS_BINS = [
    (0.0, 0.01),
    (0.01, 0.1),
    (0.1, 0.3),
    (0.3, 0.6),
    (0.6, 1.0),
]

TARGET_PER_BIN = TARGET_COUNT // len(EPSS_BINS)


def is_potentially_windows_applicable(software_field: str) -> bool:
    if pd.isna(software_field):
        return True
    software_field = software_field.lower()
    return not any(k in software_field for k in EXCLUDED_KEYWORDS)


def clean_first_value(value: str) -> str:
    if pd.isna(value):
        return ""
    value = str(value).strip().replace('"', '')
    return value.split(",")[0].strip()


def clean_version(version: str) -> str:
    if pd.isna(version):
        return ""

    v = str(version).strip()

    # remover aspas
    v = v.replace('"', '')

    # remover tudo a partir de '&'
    v = v.split("&")[0].strip()

    # ficar só com o primeiro se houver lista
    v = v.split(",")[0].strip()

    # remover operadores apenas no início
    v = re.sub(r'^(<=|>=|<|>)\s*', '', v)

    return v




def main():
    cutoff_date = pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=365 * YEARS_BACK)
    selected_by_bin = {b: [] for b in EPSS_BINS}

    for chunk in pd.read_csv(INPUT_CSV, chunksize=CHUNK_SIZE):
        chunk["published_date"] = pd.to_datetime(
            chunk["published_date"], errors="coerce", utc=True
        )

        chunk = chunk[
            (chunk["published_date"] >= cutoff_date) &
            (chunk["affected_software"].apply(is_potentially_windows_applicable)) &
            (chunk["epss_score"].notna())
        ]

        if chunk.empty:
            continue

        chunk = chunk.sample(frac=1)

        for _, row in chunk.iterrows():
            epss = row["epss_score"]
            for b in EPSS_BINS:
                if b[0] <= epss < b[1]:
                    if len(selected_by_bin[b]) < TARGET_PER_BIN:
                        selected_by_bin[b].append(row)
                    break

        if all(len(v) >= TARGET_PER_BIN for v in selected_by_bin.values()):
            break

    df = pd.DataFrame(
        [row for rows in selected_by_bin.values() for row in rows]
    ).sample(frac=1)

    if len(df) > TARGET_COUNT:
        df = df.sample(TARGET_COUNT)

    # Construir CSV final com limpeza
    df_final = pd.DataFrame({
        "id": df["cve_id"],
        "severity": df["base_severity"],
        "epss": df["epss_score"].astype(float),
        "software": df["affected_software"].apply(clean_first_value),
        "version": df["affected_versions"].apply(clean_version),
    })

    df_final["ops"] = random.choices(
        population=[1, 2, 3],
        weights=[0.45, 0.4, 0.15],
        k=len(df_final)
    )

    df_final.to_csv(OUTPUT_CSV, index=False)
    print(f"✅ Ficheiro criado: {OUTPUT_CSV} ({len(df_final)} CVEs)")


if __name__ == "__main__":
    main()
