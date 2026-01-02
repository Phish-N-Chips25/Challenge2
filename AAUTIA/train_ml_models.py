"""
ML Model Training with FLAML AutoML - EPSS Score Prediction
Uses FLAML for automated hyperparameter tuning across RF, LightGBM, XGBoost, and KNN
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestRegressor
from sklearn.neighbors import KNeighborsRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
import lightgbm as lgb
import xgboost as xgb
from flaml import AutoML
import warnings
warnings.filterwarnings('ignore')

# Suppress LightGBM boost warnings on Windows with GPU
os.environ['LIGHTGBM_EXEC_MODE'] = 'cpu_thread'  # Suppress OpenCL warnings

# ============================================================================
# GPU AVAILABILITY CHECK
# ============================================================================

def check_gpu_availability():
    """Check if CUDA GPU is available and ready for training"""
    print("=" * 80)
    print("GPU AVAILABILITY CHECK")
    print("=" * 80)
    
    gpu_available = False
    gpu_info = {}
    
    # Check XGBoost GPU support
    print("\n Checking XGBoost GPU support...")
    try:
        # Test if XGBoost can build with GPU
        import xgboost as xgb
        xgb_version = xgb.__version__
        print(f"   [OK] XGBoost version: {xgb_version}")
        
        # Try to create a small GPU-based model
        dtrain = xgb.DMatrix(np.random.rand(10, 5), label=np.random.rand(10))
        params = {'tree_method': 'gpu_hist', 'gpu_id': 0}
        xgb.train(params, dtrain, num_boost_round=1)
        print(f"   [OK] XGBoost GPU support: AVAILABLE")
        gpu_info['xgboost'] = True
        gpu_available = True
    except Exception as e:
        print(f"   [FAIL] XGBoost GPU support: NOT AVAILABLE")
        print(f"     Reason: {str(e)[:80]}")
        gpu_info['xgboost'] = False
    
    # Check LightGBM GPU support (skip test - just check if CUDA is available)
    print("\n Checking LightGBM GPU support...")
    try:
        import lightgbm as lgb
        lgb_version = lgb.__version__
        print(f"   [OK] LightGBM version: {lgb_version}")
        
        # LightGBM will automatically use GPU if CUDA is available
        # Skip the GPU test to avoid Windows boost::filesystem warnings
        if gpu_info.get('xgboost', False):
            print(f"   [OK] LightGBM GPU support: AVAILABLE (via CUDA)")
            gpu_info['lightgbm'] = True
            gpu_available = True
        else:
            print(f"   [OK] LightGBM GPU support: Will use CPU")
            gpu_info['lightgbm'] = False
    except Exception as e:
        print(f"   [FAIL] LightGBM GPU support: NOT AVAILABLE")
        print(f"     Reason: {str(e)[:80]}")
        gpu_info['lightgbm'] = False
    
    # Try to get GPU device information
    print("\n Detecting GPU hardware...")
    try:
        # Try using PyTorch to get GPU info (if installed)
        import torch
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1e9
            cuda_version = torch.version.cuda
            print(f"   [OK] GPU Detected: {gpu_name}")
            print(f"   [OK] GPU Memory: {gpu_memory:.1f} GB")
            print(f"   [OK] CUDA Version: {cuda_version}")
            gpu_info['device'] = gpu_name
            gpu_info['memory_gb'] = gpu_memory
        else:
            print(f"   [FAIL] PyTorch CUDA: Not available")
    except ImportError:
        # PyTorch not installed, try alternative method
        try:
            import subprocess
            result = subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total', '--format=csv,noheader'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                gpu_data = result.stdout.strip().split(',')
                if len(gpu_data) >= 2:
                    print(f"   [OK] GPU Detected: {gpu_data[0].strip()}")
                    print(f"   [OK] GPU Memory: {gpu_data[1].strip()}")
                    gpu_info['device'] = gpu_data[0].strip()
        except:
            print(f"   GPU hardware info not available (nvidia-smi not found)")
    
    # Final summary
    print("\n" + "=" * 80)
    if gpu_available:
        print(" GPU TRAINING ENABLED")
        if gpu_info.get('xgboost') and gpu_info.get('lightgbm'):
            print("   Both XGBoost and LightGBM will use GPU acceleration")
            print("   Expected speedup: 2-5x faster training")
        elif gpu_info.get('xgboost'):
            print("   XGBoost will use GPU acceleration")
            print("   LightGBM will use CPU")
        elif gpu_info.get('lightgbm'):
            print("   LightGBM will use GPU acceleration")
            print("   XGBoost will use CPU")
    else:
        print("  GPU TRAINING DISABLED")
        print("   All models will use CPU")
        print("   To enable GPU:")
        print("   1. Install CUDA Toolkit (https://developer.nvidia.com/cuda-downloads)")
        print("   2. Reinstall XGBoost: pip uninstall xgboost && pip install xgboost")
        print("   3. Reinstall LightGBM: pip uninstall lightgbm && pip install lightgbm --config-settings=cmake.define.USE_GPU=ON")
    print("=" * 80)
    
    return gpu_info

# Run GPU check
GPU_INFO = check_gpu_availability()

# ============================================================================
# LOAD PREPROCESSED DATA
# ============================================================================

# Load features and target
X_unscaled = pd.read_csv('X_features_unscaled.csv')
X_scaled = pd.read_csv('X_features_scaled.csv')
y = pd.read_csv('y_target.csv').values.ravel()

print("=" * 80)
print("ML MODEL TRAINING WITH FLAML AUTOML - EPSS SCORE PREDICTION")
print("=" * 80)
print(f"\nData loaded successfully!")
print(f"Features shape: {X_unscaled.shape}")
print(f"Target shape: {y.shape}")
print("\n FLAML AutoML Configuration:")
print("   • Early stopping enabled - stops when no improvement detected")
print("   • GPU acceleration enabled for LightGBM & XGBoost (if available)")
print("   • Max time budget: 30 min per model (usually finishes earlier)")
print("   • This approach finds better hyperparameters than fixed 10-min runs")

# Split data (stratify by EPSS percentile for better validation distribution)
X_train_unscaled, X_test_unscaled, y_train, y_test = train_test_split(
    X_unscaled, y, test_size=0.2, random_state=42
)
X_train_scaled, X_test_scaled, _, _ = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

print(f"\nTrain set: {X_train_unscaled.shape[0]} samples")
print(f"Test set: {X_test_unscaled.shape[0]} samples")

# ============================================================================
# 1. RANDOM FOREST WITH FLAML AUTOML
# ============================================================================
print("\n" + "=" * 80)
print("1. RANDOM FOREST REGRESSOR (FLAML AutoML Tuning)")
print("=" * 80)
print("Tuning hyperparameters with early stopping (stops when no improvement)...")
print("This may take 15-30 minutes depending on convergence")

automl_rf = AutoML(
    task='regression',
    estimator_list=['rf'],  # Only train Random Forest
    time_budget=1800,  # 30 minutes max (will stop early if no improvement)
    metric='r2',
    verbose=1,
    seed=42,
    n_jobs=-1,
    early_stop=True,  # Stop when no improvement
    log_training_metric=True  # Show training progress
)

automl_rf.fit(X_train_unscaled, y_train)

rf_pred = automl_rf.predict(X_test_unscaled)
rf_mse = mean_squared_error(y_test, rf_pred)
rf_rmse = np.sqrt(rf_mse)
rf_mae = mean_absolute_error(y_test, rf_pred)
rf_r2 = r2_score(y_test, rf_pred)
rf_model = automl_rf.model

print(f"\n[OK] Random Forest Results (FLAML Optimized):")
print(f"  - Best hyperparameters: {automl_rf.best_config}")
print(f"  - RMSE: {rf_rmse:.6f}")
print(f"  - MAE:  {rf_mae:.6f}")
print(f"  - R²:   {rf_r2:.4f}")

# Save model immediately
import joblib
joblib.dump(rf_model, 'rf_epss_model.pkl')
print(f"\n[OK] Model saved: rf_epss_model.pkl")

# Feature importance
if hasattr(rf_model, 'feature_importances_'):
    feature_importance = pd.DataFrame({
        'feature': X_train_unscaled.columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False).head(15)
    
    print(f"\n  Top 15 Most Important Features:")
    for idx, row in feature_importance.iterrows():
        print(f"    {row['feature']:40s}: {row['importance']:.4f}")

# Cross-validation (skip if estimator is not sklearn-compatible)
try:
    cv_scores = cross_val_score(rf_model, X_train_unscaled, y_train, cv=5, scoring='r2')
    print(f"\n  Cross-validation R² Scores: {cv_scores}")
    print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
except Exception as e:
    print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

# ============================================================================
# 2. LIGHTGBM REGRESSOR WITH FLAML AUTOML
# ============================================================================
print("\n" + "=" * 80)
print("2. LIGHTGBM REGRESSOR (FLAML AutoML Tuning)")
print("=" * 80)
print("Tuning hyperparameters with early stopping (stops when no improvement)...")
print("This may take 15-30 minutes depending on convergence")
print("GPU acceleration enabled if available")

automl_lgb = AutoML(
    task='regression',
    estimator_list=['lgbm'],  # Only train LightGBM
    time_budget=1800,  # 30 minutes max (will stop early if no improvement)
    metric='r2',
    verbose=1,
    seed=42,
    n_jobs=-1,
    early_stop=True,  # Stop when no improvement
    log_training_metric=True,  # Show training progress
    # GPU settings for LightGBM (will fallback to CPU if GPU unavailable)
    eval_method='auto'
)

# Use GPU if available (based on check)
if GPU_INFO.get('lightgbm', False):
    try:
        automl_lgb.fit(
            X_train_unscaled, y_train,
            **{'lgb': {'device': 'gpu', 'gpu_platform_id': 0, 'gpu_device_id': 0}}
        )
        print(f"   Using GPU acceleration ({GPU_INFO.get('device', 'CUDA GPU')})")
    except Exception as e:
        print(f"    GPU failed, falling back to CPU: {str(e)[:50]}")
        automl_lgb.fit(X_train_unscaled, y_train)
else:
    automl_lgb.fit(X_train_unscaled, y_train)
    print("   Using CPU (GPU not available)")

lgb_pred = automl_lgb.predict(X_test_unscaled)
lgb_mse = mean_squared_error(y_test, lgb_pred)
lgb_rmse = np.sqrt(lgb_mse)
lgb_mae = mean_absolute_error(y_test, lgb_pred)
lgb_r2 = r2_score(y_test, lgb_pred)
lgb_model = automl_lgb.model

print(f"\n[OK] LightGBM Results (FLAML Optimized):")
print(f"  - Best hyperparameters: {automl_lgb.best_config}")
print(f"  - RMSE: {lgb_rmse:.6f}")
print(f"  - MAE:  {lgb_mae:.6f}")
print(f"  - R²:   {lgb_r2:.4f}")

# Save model immediately
joblib.dump(lgb_model, 'lgb_epss_model.pkl')
print(f"\n[OK] Model saved: lgb_epss_model.pkl")

# Feature importance
if hasattr(lgb_model, 'feature_importances_'):
    lgb_importance = pd.DataFrame({
        'feature': X_train_unscaled.columns,
        'importance': lgb_model.feature_importances_
    }).sort_values('importance', ascending=False).head(15)
    
    print(f"\n  Top 15 Most Important Features:")
    for idx, row in lgb_importance.iterrows():
        print(f"    {row['feature']:40s}: {row['importance']:.4f}")

try:
    cv_scores = cross_val_score(lgb_model, X_train_unscaled, y_train, cv=5, scoring='r2')
    print(f"\n  Cross-validation R² Scores: {cv_scores}")
    print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
except Exception as e:
    print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

# ============================================================================
# 3. XGBOOST REGRESSOR WITH FLAML AUTOML
# ============================================================================
print("\n" + "=" * 80)
print("3. XGBOOST REGRESSOR (FLAML AutoML Tuning)")
print("=" * 80)
print("Tuning hyperparameters with early stopping (stops when no improvement)...")
print("This may take 15-30 minutes depending on convergence")
print("GPU acceleration enabled if available")

automl_xgb = AutoML(
    task='regression',
    estimator_list=['xgboost'],  # Only train XGBoost
    time_budget=1800,  # 30 minutes max (will stop early if no improvement)
    metric='r2',
    verbose=1,
    seed=42,
    n_jobs=-1,
    early_stop=True,  # Stop when no improvement
    log_training_metric=True  # Show training progress
)

# Use GPU if available (based on check)
if GPU_INFO.get('xgboost', False):
    try:
        automl_xgb.fit(
            X_train_unscaled, y_train,
            **{'xgboost': {'tree_method': 'gpu_hist', 'gpu_id': 0}}
        )
        print(f"   Using GPU acceleration ({GPU_INFO.get('device', 'CUDA GPU')})")
    except Exception as e:
        print(f"    GPU failed, falling back to CPU: {str(e)[:50]}")
        automl_xgb.fit(X_train_unscaled, y_train)
else:
    automl_xgb.fit(X_train_unscaled, y_train)
    print("   Using CPU (GPU not available)")

xgb_pred = automl_xgb.predict(X_test_unscaled)
xgb_mse = mean_squared_error(y_test, xgb_pred)
xgb_rmse = np.sqrt(xgb_mse)
xgb_mae = mean_absolute_error(y_test, xgb_pred)
xgb_r2 = r2_score(y_test, xgb_pred)
xgb_model = automl_xgb.model

print(f"\n[OK] XGBoost Results (FLAML Optimized):")
print(f"  - Best hyperparameters: {automl_xgb.best_config}")
print(f"  - RMSE: {xgb_rmse:.6f}")
print(f"  - MAE:  {xgb_mae:.6f}")
print(f"  - R²:   {xgb_r2:.4f}")

# Save model immediately
joblib.dump(xgb_model, 'xgb_epss_model.pkl')
print(f"\n[OK] Model saved: xgb_epss_model.pkl")

# Feature importance
if hasattr(xgb_model, 'feature_importances_'):
    xgb_importance = pd.DataFrame({
        'feature': X_train_unscaled.columns,
        'importance': xgb_model.feature_importances_
    }).sort_values('importance', ascending=False).head(15)
    
    print(f"\n  Top 15 Most Important Features:")
    for idx, row in xgb_importance.iterrows():
        print(f"    {row['feature']:40s}: {row['importance']:.4f}")

try:
    cv_scores = cross_val_score(xgb_model, X_train_unscaled, y_train, cv=5, scoring='r2')
    print(f"\n  Cross-validation R² Scores: {cv_scores}")
    print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
except Exception as e:
    print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

# ============================================================================
# 4. K-NEAREST NEIGHBORS WITH FLAML AUTOML (requires scaled features)
# ============================================================================
print("\n" + "=" * 80)
print("4. K-NEAREST NEIGHBORS REGRESSOR (FLAML AutoML Tuning)")
print("=" * 80)
print("Tuning hyperparameters with early stopping (stops when no improvement)...")
print("This may take 10-20 minutes depending on convergence")
print("Note: KNN does not support GPU acceleration")

automl_knn = AutoML(
    task='regression',
    estimator_list=['kneighbor'],  # Only train KNN
    time_budget=1200,  # 20 minutes max (will stop early if no improvement)
    metric='r2',
    verbose=1,
    seed=42,
    n_jobs=-1,
    early_stop=True,  # Stop when no improvement
    log_training_metric=True  # Show training progress
)

# KNN requires scaled features
automl_knn.fit(X_train_scaled, y_train)

knn_pred = automl_knn.predict(X_test_scaled)
knn_mse = mean_squared_error(y_test, knn_pred)
knn_rmse = np.sqrt(knn_mse)
knn_mae = mean_absolute_error(y_test, knn_pred)
knn_r2 = r2_score(y_test, knn_pred)
knn_model = automl_knn.model

print(f"\n[OK] KNN Results (FLAML Optimized):")
print(f"  - Best hyperparameters: {automl_knn.best_config}")
print(f"  - RMSE: {knn_rmse:.6f}")
print(f"  - MAE:  {knn_mae:.6f}")
print(f"  - R²:   {knn_r2:.4f}")

# Save model immediately
joblib.dump(knn_model, 'knn_epss_model.pkl')
print(f"\n[OK] Model saved: knn_epss_model.pkl")

try:
    cv_scores = cross_val_score(knn_model, X_train_scaled, y_train, cv=5, scoring='r2')
    print(f"\n  Cross-validation R² Scores: {cv_scores}")
    print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
except Exception as e:
    print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

# ============================================================================
# MODEL COMPARISON
# ============================================================================
print("\n" + "=" * 80)
print("MODEL PERFORMANCE COMPARISON (FLAML Optimized)")
print("=" * 80)

comparison_df = pd.DataFrame({
    'Model': ['Random Forest (FLAML)', 'LightGBM (FLAML)', 'XGBoost (FLAML)', 'KNN (FLAML)'],
    'RMSE': [rf_rmse, lgb_rmse, xgb_rmse, knn_rmse],
    'MAE': [rf_mae, lgb_mae, xgb_mae, knn_mae],
    'R² Score': [rf_r2, lgb_r2, xgb_r2, knn_r2]
})

print("\n" + comparison_df.to_string(index=False))

best_model_idx = comparison_df['R² Score'].idxmax()
best_model_name = comparison_df.loc[best_model_idx, 'Model']
best_r2 = comparison_df.loc[best_model_idx, 'R² Score']
best_rmse = comparison_df.loc[best_model_idx, 'RMSE']

print(f"\n BEST MODEL: {best_model_name}")
print(f"   R² Score: {best_r2:.4f}")
print(f"   RMSE: {best_rmse:.6f}")

print("\n" + "=" * 80)
print("FLAML AutoML SUMMARY")
print("=" * 80)
print(f"\nRandom Forest Best Config: {automl_rf.best_config}")
print(f"LightGBM Best Config:      {automl_lgb.best_config}")
print(f"XGBoost Best Config:       {automl_xgb.best_config}")
print(f"KNN Best Config:           {automl_knn.best_config}")

# ============================================================================
# PREDICTION EXAMPLE
# ============================================================================
print("\n" + "=" * 80)
print("PREDICTION EXAMPLE (Using Best FLAML-Optimized Model)")
print("=" * 80)

# Make predictions on a sample using best model
sample_indices = np.random.choice(len(X_test_unscaled), 5, replace=False)

# Determine which model to use for predictions
if best_model_idx == 0:
    use_predictions = rf_pred
    model_name = "Random Forest (FLAML)"
elif best_model_idx == 1:
    use_predictions = lgb_pred
    model_name = "LightGBM (FLAML)"
elif best_model_idx == 2:
    use_predictions = xgb_pred
    model_name = "XGBoost (FLAML)"
else:
    use_predictions = knn_pred
    model_name = "KNN (FLAML)"

print(f"\nSample Predictions (using {model_name}):\n")
print(f"{'Actual EPSS':<15} {'Prediction':<15} {'Error':<10}")
print("-" * 40)

for idx in sample_indices:
    actual = y_test[idx]
    pred = use_predictions[idx]
    error = abs(actual - pred)
    print(f"{actual:<15.6f} {pred:<15.6f} {error:<10.6f}")

print("\n[OK] FLAML AUTOML TRAINING COMPLETE!")
print("\nSaved Models (all optimized with FLAML):")
print("  - rf_epss_model.pkl")
print("  - lgb_epss_model.pkl")
print("  - xgb_epss_model.pkl")
print("  - knn_epss_model.pkl")
print(f"\n Best Model: {best_model_name}")
print(f"   Expected R² on new data: ~{best_r2:.4f}")
