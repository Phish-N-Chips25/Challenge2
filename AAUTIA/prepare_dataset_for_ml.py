"""
CVE EPSS Dataset Preparation for Machine Learning
Encodes categorical, numerical, and temporal features for ML model training
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

# Load the dataset
df = pd.read_csv('cve_cisa_epss_enriched_dataset_with_nvd.csv')

print("=" * 80)
print("CVE DATASET ANALYSIS & PREPROCESSING")
print("=" * 80)
print(f"\nDataset Shape: {df.shape}")
print(f"\nColumn Names and Types:")
print(df.dtypes)
print(f"\nFirst few rows:")
print(df.head())
print(f"\nMissing Values:")
print(df.isnull().sum())
print(f"\nBasic Statistics:")
print(df.describe())

# ============================================================================
# FEATURE ENGINEERING & ENCODING STRATEGY
# ============================================================================

# Create a copy for processing
df_processed = df.copy()

# 1. TEMPORAL FEATURE ENGINEERING
print("\n" + "=" * 80)
print("1. TEMPORAL FEATURE ENGINEERING")
print("=" * 80)

df_processed['published_date'] = pd.to_datetime(df_processed['published_date'], utc=True)
# Use timezone-aware timestamp for comparison
now = pd.Timestamp.now(tz='UTC')
df_processed['days_since_publication'] = (now - df_processed['published_date']).dt.days
df_processed['year_published'] = df_processed['published_date'].dt.year
df_processed['month_published'] = df_processed['published_date'].dt.month
df_processed['quarter_published'] = df_processed['published_date'].dt.quarter

print(f"✓ Created temporal features: days_since_publication, year_published, month_published, quarter_published")

# 2. CATEGORICAL ENCODING
print("\n" + "=" * 80)
print("2. CATEGORICAL FEATURE ENCODING")
print("=" * 80)

# Binary categorical features (Boolean-like) - Use Label Encoding
binary_features = ['cisa_kev']  # False/True
for col in binary_features:
    df_processed[col] = df_processed[col].astype(str).map({'False': 0, 'True': 1})
    print(f"✓ {col}: Label Encoded (False→0, True→1)")

# Ordinal categorical features - CVSS Severity levels have order
severity_mapping = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
df_processed['base_severity_encoded'] = df_processed['base_severity'].map(severity_mapping)
print(f"✓ base_severity: Ordinal Encoded (LOW→1, MEDIUM→2, HIGH→3, CRITICAL→4)")

# Nominal categorical features - One-Hot Encoding
# These have no inherent order
nominal_categorical = ['attack_vector', 'attack_complexity', 'privileges_required', 
                       'user_interaction', 'scope', 'confidentiality_impact', 
                       'integrity_impact', 'availability_impact']

for col in nominal_categorical:
    # Create one-hot encoded columns
    dummies = pd.get_dummies(df_processed[col], prefix=col, drop_first=False)
    df_processed = pd.concat([df_processed, dummies], axis=1)
    print(f"✓ {col}: One-Hot Encoded → {list(dummies.columns)}")

# 3. TEXT/COMPLEX FEATURE HANDLING
print("\n" + "=" * 80)
print("3. TEXT FEATURE HANDLING")
print("=" * 80)

# affected_software & affected_versions - Create feature counts
df_processed['num_affected_software'] = df_processed['affected_software'].fillna('').str.split(',').str.len()
df_processed['num_affected_versions'] = df_processed['affected_versions'].fillna('').str.split(',').str.len()
print(f"✓ affected_software: Created 'num_affected_software' feature (count of affected products)")
print(f"✓ affected_versions: Created 'num_affected_versions' feature (count of affected versions)")

# 4. HANDLE MISSING VALUES
print("\n" + "=" * 80)
print("4. MISSING VALUE HANDLING")
print("=" * 80)

# Numeric columns - fill with median
numeric_cols = ['base_score', 'exploitability_score', 'impact_score', 'epss_score', 'epss_perc',
                'days_since_publication', 'year_published', 'month_published', 'quarter_published',
                'num_affected_software', 'num_affected_versions']

for col in numeric_cols:
    if df_processed[col].isnull().sum() > 0:
        median_val = df_processed[col].median()
        df_processed[col].fillna(median_val, inplace=True)
        print(f"✓ {col}: Filled {df_processed[col].isnull().sum()} missing values with median ({median_val:.4f})")

# ============================================================================
# SELECT FINAL FEATURE SET
# ============================================================================
print("\n" + "=" * 80)
print("5. FEATURE SELECTION FOR ML MODELS")
print("=" * 80)

# Define target variable
target = 'epss_score'

# Define feature sets
# NOTE: 'epss_perc' REMOVED - it's derived from epss_score (data leakage!)
numerical_features = ['base_score', 'exploitability_score', 'impact_score',
                      'days_since_publication', 'year_published', 'month_published', 
                      'quarter_published', 'num_affected_software', 'num_affected_versions']

# Get all one-hot encoded columns (those with underscores from get_dummies)
encoded_categorical = (
    ['base_severity_encoded', 'cisa_kev'] +
    [col for col in df_processed.columns if (
        col.startswith('attack_vector_') or 
        col.startswith('attack_complexity_') or
        col.startswith('privileges_required_') or
        col.startswith('user_interaction_') or
        col.startswith('scope_') or
        col.startswith('confidentiality_impact_') or 
        col.startswith('integrity_impact_') or 
        col.startswith('availability_impact_')
    )]
)

X = df_processed[numerical_features + encoded_categorical].copy()
y = df_processed[target].copy()

print(f"\nTarget Variable: {target}")
print(f"Target Statistics:")
print(y.describe())

print(f"\nFeature Dimensions:")
print(f"  - Numerical features: {len(numerical_features)}")
print(f"  - Encoded categorical features: {len(encoded_categorical)}")
print(f"  - Total features (X): {X.shape[1]}")
print(f"  - Total samples: {X.shape[0]}")

# ============================================================================
# FEATURE SCALING (Important for distance-based models: KNN, SVM)
# ============================================================================
print("\n" + "=" * 80)
print("6. FEATURE SCALING")
print("=" * 80)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_scaled_df = pd.DataFrame(X_scaled, columns=X.columns)

print(f"✓ StandardScaler applied to all features")
print(f"  - Mean after scaling: {X_scaled_df.mean().mean():.6f}")
print(f"  - Std after scaling: {X_scaled_df.std().mean():.6f}")

# ============================================================================
# SAVE PROCESSED DATA
# ============================================================================
print("\n" + "=" * 80)
print("7. SAVING PROCESSED DATA")
print("=" * 80)

# Save unscaled data
X.to_csv('X_features_unscaled.csv', index=False)
y.to_csv('y_target.csv', index=False, header=True)
print("✓ Saved: X_features_unscaled.csv")
print("✓ Saved: y_target.csv")

# Save scaled data
X_scaled_df.to_csv('X_features_scaled.csv', index=False)
print("✓ Saved: X_features_scaled.csv (StandardScaler applied)")

# Save feature names mapping
feature_mapping = {
    'numerical_features': numerical_features,
    'categorical_features': encoded_categorical,
    'all_features': list(X.columns)
}
import json
with open('feature_mapping.json', 'w') as f:
    json.dump(feature_mapping, f, indent=2)
print("✓ Saved: feature_mapping.json")

# ============================================================================
# DATA SUMMARY REPORT
# ============================================================================
print("\n" + "=" * 80)
print("ENCODING SUMMARY")
print("=" * 80)

summary = f"""
ENCODING STRATEGY APPLIED:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. NUMERICAL FEATURES (10 features):
   - {', '.join(numerical_features)}
   - Scaling: StandardScaler (mean=0, std=1) - APPLIED
   - Best for: Tree-based models, Linear models

2. CATEGORICAL FEATURES (20+ features):
   
   a) Binary Encoding:
      - cisa_kev: False→0, True→1
   
   b) Ordinal Encoding:
      - base_severity: LOW(1) < MEDIUM(2) < HIGH(3) < CRITICAL(4)
   
   c) One-Hot Encoding:
      - attack_vector (2 categories)
      - attack_complexity (2 categories)
      - privileges_required (3 categories)
      - user_interaction (2 categories)
      - scope (2 categories)
      - confidentiality_impact (3 categories)
      - integrity_impact (3 categories)
      - availability_impact (3 categories)

3. TEMPORAL FEATURES (4 features):
   - days_since_publication: Days since CVE publication
   - year_published: Year of publication
   - month_published: Month of publication
   - quarter_published: Quarter of publication

4. DERIVED TEXT FEATURES (2 features):
   - num_affected_software: Count of affected products
   - num_affected_versions: Count of affected versions

TARGET VARIABLE:
   - epss_score: Continuous (0.0 to 1.0)
   - Type: Regression Task

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MODELS RECOMMENDED FOR THIS DATA:

✓ TREE-BASED MODELS (No scaling required):
  - Random Forest: Excellent for feature importance
  - LightGBM: Fast, handles missing values well
  - XGBoost: Powerful, good generalization
  → Use: X_features_unscaled.csv

✓ DISTANCE-BASED MODELS (Scaling required):
  - KNN: Requires scaled features for distance computation
  → Use: X_features_scaled.csv

✓ LINEAR MODELS (Scaling recommended):
  - Linear Regression, Ridge, Lasso
  → Use: X_features_scaled.csv

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OUTPUT FILES:
   ✓ X_features_unscaled.csv - Features without scaling (for tree models)
   ✓ X_features_scaled.csv - Features with StandardScaler (for KNN, linear models)
   ✓ y_target.csv - Target variable (EPSS scores)
   ✓ feature_mapping.json - Feature names and groupings
"""

print(summary)

print("✓ PREPROCESSING COMPLETE!")
print(f"\n  Total samples: {X.shape[0]}")
print(f"  Total features: {X.shape[1]}")
print(f"  Ready for model training!")
