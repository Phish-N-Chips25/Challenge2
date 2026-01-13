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
from sklearn.preprocessing import StandardScaler, PolynomialFeatures
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
from sklearn.linear_model import LinearRegression, Lasso, ElasticNet, SGDRegressor
import lightgbm as lgb
import xgboost as xgb
from flaml import AutoML
from sklearn.svm import SVR
import json
import optuna
from optuna.trial import TrialState
import warnings
warnings.filterwarnings('ignore')
import joblib


def save_json(data, path):
    """Persist dictionaries/lists to JSON with a small helper."""
    def _default(obj):
        if isinstance(obj, (np.integer, np.int64)):
            return int(obj)
        if isinstance(obj, (np.floating, np.float64)):
            return float(obj)
        if isinstance(obj, (set, tuple)):
            return list(obj)
        return str(obj)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=_default)
        print(f"[OK] Saved JSON: {path}")
    except Exception as exc:  # pragma: no cover - defensive logging
        print(f"[WARN] Failed to save JSON {path}: {exc}")

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
# CHECK FOR ALREADY TRAINED MODELS
# ============================================================================
print("\nChecking for already trained models...")
training_config = {
    'rf': {'file': 'rf_epss_model.pkl', 'skip': False},
    'lgb': {'file': 'lgb_epss_model.pkl', 'skip': False},
    'xgb': {'file': 'xgb_epss_model.pkl', 'skip': False},
    'knn': {'file': 'knn_epss_model.pkl', 'skip': False},
    'svm': {'file': 'svm_epss_models.pkl', 'skip': False},  # All SVM kernels in one file
    'linreg': {'file': 'linreg_epss_model.pkl', 'skip': False},
    'sgd': {'file': 'sgd_epss_model.pkl', 'skip': False},
    'poly': {'file': 'poly_epss_model.pkl', 'skip': False},
    'lasso': {'file': 'lasso_epss_model.pkl', 'skip': False},
    'elasticnet': {'file': 'elasticnet_epss_model.pkl', 'skip': False}
}

for model_name, config in training_config.items():
    if os.path.exists(config['file']):
        config['skip'] = True
        print(f"  [SKIP] {model_name.upper()} - already trained ({config['file']})")
    else:
        print(f"  [TRAIN] {model_name.upper()} - will be trained")

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
print("   • SVM trained with multiple kernel options (linear, rbf, poly, sigmoid)")
print("   • Additional models: Linear Regression, SGD, Polynomial, Lasso, ElasticNet")

# Split data (stratify by EPSS percentile for better validation distribution)
X_train_unscaled, X_test_unscaled, y_train, y_test = train_test_split(
    X_unscaled, y, test_size=0.2, random_state=42
)
X_train_scaled, X_test_scaled, _, _ = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

print(f"\nTrain set: {X_train_unscaled.shape[0]} samples")
print(f"Test set: {X_test_unscaled.shape[0]} samples")

# Storage for model results
model_results = {}

# ============================================================================
# 1. RANDOM FOREST WITH FLAML AUTOML
# ============================================================================
if training_config['rf']['skip']:
    print("\n" + "=" * 80)
    print("1. RANDOM FOREST REGRESSOR (SKIPPED - Already Trained)")
    print("=" * 80)
    rf_model = joblib.load(training_config['rf']['file'])
    rf_pred = rf_model.predict(X_test_unscaled)
    rf_mse = mean_squared_error(y_test, rf_pred)
    rf_rmse = np.sqrt(rf_mse)
    rf_mae = mean_absolute_error(y_test, rf_pred)
    rf_r2 = r2_score(y_test, rf_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {rf_rmse:.6f}")
    print(f"  - MAE:  {rf_mae:.6f}")
    print(f"  - R²:   {rf_r2:.4f}")
    save_json({'params': rf_model.get_params()}, 'rf_params.json')
    if hasattr(rf_model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': X_train_unscaled.columns,
            'importance': rf_model.feature_importances_
        }).sort_values('importance', ascending=False).head(15)
        save_json({
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in feature_importance.iterrows()
            ]
        }, 'rf_feature_importance.json')
        print(f"\n  Top 15 Most Important Features:")
        for idx, row in feature_importance.iterrows():
            print(f"    {row['feature']:40s}: {row['importance']:.4f}")
else:
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
    joblib.dump(rf_model, 'rf_epss_model.pkl')
    print(f"\n[OK] Model saved: rf_epss_model.pkl")
    save_json({
        'best_config': automl_rf.best_config,
        'model_params': rf_model.get_params()
    }, 'rf_params.json')

    # Feature importance
    if hasattr(rf_model, 'feature_importances_'):
        feature_importance = pd.DataFrame({
            'feature': X_train_unscaled.columns,
            'importance': rf_model.feature_importances_
        }).sort_values('importance', ascending=False).head(15)
        save_json({
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in feature_importance.iterrows()
            ]
        }, 'rf_feature_importance.json')
        
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

model_results['rf'] = {'rmse': rf_rmse, 'mae': rf_mae, 'r2': rf_r2}

# ============================================================================
# 2. LIGHTGBM REGRESSOR WITH FLAML AUTOML
# ============================================================================
if training_config['lgb']['skip']:
    print("\n" + "=" * 80)
    print("2. LIGHTGBM REGRESSOR (SKIPPED - Already Trained)")
    print("=" * 80)
    lgb_model = joblib.load(training_config['lgb']['file'])
    lgb_pred = lgb_model.predict(X_test_unscaled)
    lgb_mse = mean_squared_error(y_test, lgb_pred)
    lgb_rmse = np.sqrt(lgb_mse)
    lgb_mae = mean_absolute_error(y_test, lgb_pred)
    lgb_r2 = r2_score(y_test, lgb_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {lgb_rmse:.6f}")
    print(f"  - MAE:  {lgb_mae:.6f}")
    print(f"  - R²:   {lgb_r2:.4f}")
    save_json({'params': lgb_model.get_params()}, 'lgb_params.json')
    if hasattr(lgb_model, 'feature_importances_'):
        lgb_importance = pd.DataFrame({
            'feature': X_train_unscaled.columns,
            'importance': lgb_model.feature_importances_
        }).sort_values('importance', ascending=False).head(15)
        save_json({
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in lgb_importance.iterrows()
            ]
        }, 'lgb_feature_importance.json')
        print(f"\n  Top 15 Most Important Features:")
        for idx, row in lgb_importance.iterrows():
            print(f"    {row['feature']:40s}: {row['importance']:.4f}")
else:
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
    save_json({
        'best_config': automl_lgb.best_config,
        'model_params': lgb_model.get_params()
    }, 'lgb_params.json')

    # Feature importance
    if hasattr(lgb_model, 'feature_importances_'):
        lgb_importance = pd.DataFrame({
            'feature': X_train_unscaled.columns,
            'importance': lgb_model.feature_importances_
        }).sort_values('importance', ascending=False).head(15)
        save_json({
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in lgb_importance.iterrows()
            ]
        }, 'lgb_feature_importance.json')
        
        print(f"\n  Top 15 Most Important Features:")
        for idx, row in lgb_importance.iterrows():
            print(f"    {row['feature']:40s}: {row['importance']:.4f}")

    try:
        cv_scores = cross_val_score(lgb_model, X_train_unscaled, y_train, cv=5, scoring='r2')
        print(f"\n  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

model_results['lgb'] = {'rmse': lgb_rmse, 'mae': lgb_mae, 'r2': lgb_r2}

# ============================================================================
# 3. XGBOOST REGRESSOR WITH FLAML AUTOML
# ============================================================================
if training_config['xgb']['skip']:
    print("\n" + "=" * 80)
    print("3. XGBOOST REGRESSOR (SKIPPED - Already Trained)")
    print("=" * 80)
    xgb_model = joblib.load(training_config['xgb']['file'])
    xgb_pred = xgb_model.predict(X_test_unscaled)
    xgb_mse = mean_squared_error(y_test, xgb_pred)
    xgb_rmse = np.sqrt(xgb_mse)
    xgb_mae = mean_absolute_error(y_test, xgb_pred)
    xgb_r2 = r2_score(y_test, xgb_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {xgb_rmse:.6f}")
    print(f"  - MAE:  {xgb_mae:.6f}")
    print(f"  - R²:   {xgb_r2:.4f}")
    save_json({'params': xgb_model.get_params()}, 'xgb_params.json')
    if hasattr(xgb_model, 'feature_importances_'):
        xgb_importance = pd.DataFrame({
            'feature': X_train_unscaled.columns,
            'importance': xgb_model.feature_importances_
        }).sort_values('importance', ascending=False).head(15)
        save_json({
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in xgb_importance.iterrows()
            ]
        }, 'xgb_feature_importance.json')
        print(f"\n  Top 15 Most Important Features:")
        for idx, row in xgb_importance.iterrows():
            print(f"    {row['feature']:40s}: {row['importance']:.4f}")
else:
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
    save_json({
        'best_config': automl_xgb.best_config,
        'model_params': xgb_model.get_params()
    }, 'xgb_params.json')

    # Feature importance
    if hasattr(xgb_model, 'feature_importances_'):
        xgb_importance = pd.DataFrame({
            'feature': X_train_unscaled.columns,
            'importance': xgb_model.feature_importances_
        }).sort_values('importance', ascending=False).head(15)
        save_json({
            'top_features': [
                {'feature': row['feature'], 'importance': float(row['importance'])}
                for _, row in xgb_importance.iterrows()
            ]
        }, 'xgb_feature_importance.json')
        
        print(f"\n  Top 15 Most Important Features:")
        for idx, row in xgb_importance.iterrows():
            print(f"    {row['feature']:40s}: {row['importance']:.4f}")

    try:
        cv_scores = cross_val_score(xgb_model, X_train_unscaled, y_train, cv=5, scoring='r2')
        print(f"\n  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

model_results['xgb'] = {'rmse': xgb_rmse, 'mae': xgb_mae, 'r2': xgb_r2}

# ============================================================================
# 4. K-NEAREST NEIGHBORS WITH FLAML AUTOML (requires scaled features)
# ============================================================================
if training_config['knn']['skip']:
    print("\n" + "=" * 80)
    print("4. K-NEAREST NEIGHBORS REGRESSOR (SKIPPED - Already Trained)")
    print("=" * 80)
    knn_model = joblib.load(training_config['knn']['file'])
    knn_pred = knn_model.predict(X_test_scaled)
    knn_mse = mean_squared_error(y_test, knn_pred)
    knn_rmse = np.sqrt(knn_mse)
    knn_mae = mean_absolute_error(y_test, knn_pred)
    knn_r2 = r2_score(y_test, knn_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {knn_rmse:.6f}")
    print(f"  - MAE:  {knn_mae:.6f}")
    print(f"  - R²:   {knn_r2:.4f}")
    save_json({'params': knn_model.get_params()}, 'knn_params.json')
else:
    print("\n" + "=" * 80)
    print("4. K-NEAREST NEIGHBORS REGRESSOR (FLAML AutoML Tuning)")
    print("=" * 80)
    print("Tuning hyperparameters with early stopping (stops when no improvement)...")
    print("This may take 10-20 minutes depending on convergence")
    print("Note: KNN does not support GPU acceleration or feature importance extraction")

    automl_knn = AutoML(
        task='regression',
        estimator_list=['kneighbor'],  # Only train KNN
        time_budget=1800,  # 30 minutes max (will stop early if no improvement)
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
    save_json({
        'best_config': automl_knn.best_config,
        'model_params': knn_model.get_params()
    }, 'knn_params.json')

    try:
        cv_scores = cross_val_score(knn_model, X_train_scaled, y_train, cv=5, scoring='r2')
        print(f"\n  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"\n  Cross-validation skipped (estimator not sklearn-compatible): {str(e)[:80]}")

    print(f"\n  Note: Feature importance not available for KNN (distance-based, not tree-based)")

model_results['knn'] = {'rmse': knn_rmse, 'mae': knn_mae, 'r2': knn_r2}

# ============================================================================
# 5. SUPPORT VECTOR MACHINE WITH MULTIPLE KERNELS (Optuna Tuning)
# ============================================================================
if training_config['svm']['skip']:
    print("\n" + "=" * 80)
    print("5. SUPPORT VECTOR MACHINE WITH KERNELS (SKIPPED - Already Trained)")
    print("=" * 80)
    svm_models = joblib.load(training_config['svm']['file'])
    svm_results = {}
    svm_params = {}
    for kernel, model in svm_models.items():
        pred = model.predict(X_test_scaled)
        mse = mean_squared_error(y_test, pred)
        rmse = np.sqrt(mse)
        mae = mean_absolute_error(y_test, pred)
        r2 = r2_score(y_test, pred)
        svm_results[kernel] = {'rmse': rmse, 'mae': mae, 'r2': r2, 'pred': pred}
        svm_params[kernel] = model.get_params()
        print(f"  [{kernel.upper():10s}] RMSE: {rmse:.6f}, MAE: {mae:.6f}, R²: {r2:.4f}")
    # Use best SVM for comparison
    if svm_results:
        best_svm_kernel = max(svm_results.keys(), key=lambda k: svm_results[k]['r2'])
        svm_pred = svm_results[best_svm_kernel]['pred']
        svm_rmse = svm_results[best_svm_kernel]['rmse']
        svm_mae = svm_results[best_svm_kernel]['mae']
        svm_r2 = svm_results[best_svm_kernel]['r2']
        print(f"\n  Best SVM Kernel: {best_svm_kernel.upper()} (R² = {svm_r2:.4f})")
        save_json({
            'best_kernel': best_svm_kernel,
            'model_params': svm_params
        }, 'svm_params.json')
    else:
        print("\n[WARN] No SVM models found in loaded file; SVM will be excluded from comparison.")
        best_svm_kernel = 'none'
        svm_pred = np.zeros_like(y_test)
        svm_rmse = np.inf
        svm_mae = np.inf
        svm_r2 = -np.inf
else:
    print("\n" + "=" * 80)
    print("5. SUPPORT VECTOR MACHINE WITH KERNELS (Optuna Tuning)")
    print("=" * 80)
    print("Training SVM with different kernel options using Optuna...")
    print("Tuning hyperparameters (C, gamma, degree) per kernel with TPE sampler")
    print("Note: epsilon fixed at 0.1 in order to save time)")
    print("SVM uses scaled features for optimal performance")
    print("Note: Using 20 trials and 2-fold CV for faster convergence")
    print("Warning: Training may take 30-60 minutes with all 4 kernels")
    
    # Use pre-scaled features provided in X_train_scaled/X_test_scaled
    
    svm_models = {}
    svm_results = {}
    svm_configs = {}
    checkpoint_dir = os.path.join(os.getcwd(), "svm_checkpoints")
    os.makedirs(checkpoint_dir, exist_ok=True)
    # Test all 4 kernel types - linear may be slow
    kernels = ['rbf', 'poly', 'sigmoid', 'linear']
    
    print(f"\nTraining SVMs with Optuna for kernels: {', '.join(kernels)}...\n")
    
    for kernel in kernels:
        print(f"  Training SVM with {kernel} kernel (Optuna - 20 trials, 2-fold CV)...")
        try:
            def objective(trial):
                params = {
                    'kernel': kernel,
                    'C': 10 ** trial.suggest_float('C_log', -2, 2),
                    #'epsilon': 10 ** trial.suggest_float('epsilon_log', -4, 1)
                    'epsilon': 0.1  # Fixed epsilon
                }
                if kernel in ['rbf', 'poly', 'sigmoid']:
                    params['gamma'] = 10 ** trial.suggest_float('gamma_log', -4, 0)
                if kernel == 'poly':
                    params['degree'] = trial.suggest_int('degree', 2, 4)

                model = SVR(**params)
                scores = cross_val_score(model, X_train_scaled, y_train, cv=2, scoring='r2', n_jobs=-1)
                return scores.mean()

            storage_url = f"sqlite:///{os.path.join(checkpoint_dir, f'svm_optuna_{kernel}.db')}"
            study_name = f"svm_{kernel}"
            study = optuna.create_study(
                direction='maximize',
                sampler=optuna.samplers.TPESampler(seed=42),
                storage=storage_url,
                study_name=study_name,
                load_if_exists=True
            )

            completed = sum(1 for t in study.trials if t.state == TrialState.COMPLETE)
            remaining = max(0, 20 - completed)
            if remaining > 0:
                print(f"    Resuming {kernel} study: {completed} completed, {remaining} remaining trials...")
                study.optimize(objective, n_trials=remaining, show_progress_bar=True)
            else:
                print(f"    {kernel} study already has {completed} completed trials; skipping new trials.")

            best_params = study.best_params

            # Rebuild params in SVR signature
            final_params = {
                'kernel': kernel,
                'C': 10 ** best_params['C_log'] if 'C_log' in best_params else best_params.get('C', 1.0),
                #'epsilon': 10 ** best_params['epsilon_log'] if 'epsilon_log' in best_params else best_params.get('epsilon', 0.1)
                'epsilon': 0.1
            }
            if kernel in ['rbf', 'poly', 'sigmoid']:
                final_params['gamma'] = 10 ** best_params['gamma_log'] if 'gamma_log' in best_params else best_params.get('gamma', 'scale')
            if kernel == 'poly':
                final_params['degree'] = best_params.get('degree', 3)

            svm_model = SVR(**final_params)
            svm_model.fit(X_train_scaled, y_train)
            
            # Make predictions
            pred = svm_model.predict(X_test_scaled)
            mse = mean_squared_error(y_test, pred)
            rmse = np.sqrt(mse)
            mae = mean_absolute_error(y_test, pred)
            r2 = r2_score(y_test, pred)
            
            svm_models[kernel] = svm_model
            svm_results[kernel] = {'rmse': rmse, 'mae': mae, 'r2': r2, 'pred': pred}
            svm_configs[kernel] = final_params

            # Save checkpoint per kernel
            checkpoint_path = os.path.join(checkpoint_dir, f"svm_{kernel}.pkl")
            joblib.dump({
                'kernel': kernel,
                'model': svm_model,
                'params': final_params,
                'metrics': {'rmse': rmse, 'mae': mae, 'r2': r2},
                'best_value': study.best_value
            }, checkpoint_path)
            print(f"    [OK] Checkpoint saved: {checkpoint_path}")
            
            print(f"    [OK] RMSE: {rmse:.6f}, MAE: {mae:.6f}, R²: {r2:.4f}")
            print(f"    Best hyperparameters: {final_params}")
            
            # Cross-validation
            try:
                cv_scores = cross_val_score(svm_model, X_train_scaled, y_train, cv=5, scoring='r2')
                print(f"    CV R² (mean±std): {cv_scores.mean():.4f}±{cv_scores.std():.4f}")
            except:
                pass
        except Exception as e:
            print(f"    [FAIL] Error training {kernel} SVM: {str(e)[:80]}")
    
    # Save all SVM models
    joblib.dump(svm_models, 'svm_epss_models.pkl')
    print(f"\n[OK] All SVM models saved: svm_epss_models.pkl")
    
    if svm_results:
        # Select best SVM
        best_svm_kernel = max(svm_results.keys(), key=lambda k: svm_results[k]['r2'])
        svm_pred = svm_results[best_svm_kernel]['pred']
        svm_rmse = svm_results[best_svm_kernel]['rmse']
        svm_mae = svm_results[best_svm_kernel]['mae']
        svm_r2 = svm_results[best_svm_kernel]['r2']
        save_json({
            'best_kernel': best_svm_kernel,
            'kernel_configs': svm_configs,
            'model_params': {k: m.get_params() for k, m in svm_models.items()}
        }, 'svm_params.json')
    else:
        print("\n[WARN] No SVM models trained successfully; SVM will be excluded from comparison.")
        best_svm_kernel = 'none'
        svm_pred = np.zeros_like(y_test)
        svm_rmse = np.inf
        svm_mae = np.inf
        svm_r2 = -np.inf
    
    print(f"\n[OK] SVM Results Summary (FLAML Optimized):")
    for kernel in kernels:
        if kernel in svm_results:
            print(f"  - {kernel.upper():10s}: RMSE={svm_results[kernel]['rmse']:.6f}, MAE={svm_results[kernel]['mae']:.6f}, R²={svm_results[kernel]['r2']:.4f}")
    print(f"\n  Best SVM Kernel: {best_svm_kernel.upper()} (R² = {svm_r2:.4f})")

model_results['svm'] = {'rmse': svm_rmse, 'mae': svm_mae, 'r2': svm_r2}

# ============================================================================
# 6. LINEAR REGRESSION
# ============================================================================
if training_config['linreg']['skip']:
    print("\n" + "=" * 80)
    print("6. LINEAR REGRESSION (SKIPPED - Already Trained)")
    print("=" * 80)
    linreg_model = joblib.load(training_config['linreg']['file'])
    linreg_pred = linreg_model.predict(X_test_scaled)
    linreg_mse = mean_squared_error(y_test, linreg_pred)
    linreg_rmse = np.sqrt(linreg_mse)
    linreg_mae = mean_absolute_error(y_test, linreg_pred)
    linreg_r2 = r2_score(y_test, linreg_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {linreg_rmse:.6f}")
    print(f"  - MAE:  {linreg_mae:.6f}")
    print(f"  - R²:   {linreg_r2:.4f}")
else:
    print("\n" + "=" * 80)
    print("6. LINEAR REGRESSION (with Optuna Tuning)")
    print("=" * 80)
    print("Tuning hyperparameter (fit_intercept) with 3-fold cross-validation...")
    
    # Optuna-based hyperparameter tuning for Linear Regression
    def linreg_objective(trial):
        fit_intercept = trial.suggest_categorical('fit_intercept', [True, False])
        model = LinearRegression(fit_intercept=fit_intercept)
        scores = cross_val_score(model, X_train_scaled, y_train, cv=3, scoring='r2', n_jobs=-1)
        return scores.mean()
    
    study = optuna.create_study(direction='maximize', sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(linreg_objective, n_trials=5, show_progress_bar=True)
    
    best_fit_intercept = study.best_params['fit_intercept']
    
    linreg_model = LinearRegression(fit_intercept=best_fit_intercept)
    linreg_model.fit(X_train_scaled, y_train)
    
    linreg_pred = linreg_model.predict(X_test_scaled)
    linreg_mse = mean_squared_error(y_test, linreg_pred)
    linreg_rmse = np.sqrt(linreg_mse)
    linreg_mae = mean_absolute_error(y_test, linreg_pred)
    linreg_r2 = r2_score(y_test, linreg_pred)
    
    print(f"[OK] Linear Regression Results (Optuna Optimized):")
    print(f"  - Best fit_intercept: {best_fit_intercept}")
    print(f"  - RMSE: {linreg_rmse:.6f}")
    print(f"  - MAE:  {linreg_mae:.6f}")
    print(f"  - R²:   {linreg_r2:.4f}")
    
    joblib.dump(linreg_model, 'linreg_epss_model.pkl')
    print(f"[OK] Model saved: linreg_epss_model.pkl")
    save_json({'best_fit_intercept': best_fit_intercept, 'params': linreg_model.get_params()}, 'linreg_params.json')
    
    try:
        cv_scores = cross_val_score(linreg_model, X_train_scaled, y_train, cv=5, scoring='r2')
        print(f"  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"  Cross-validation skipped: {str(e)[:80]}")

model_results['linreg'] = {'rmse': linreg_rmse, 'mae': linreg_mae, 'r2': linreg_r2}

# ============================================================================
# 7. STOCHASTIC GRADIENT DESCENT (SGD) REGRESSOR
# ============================================================================
if training_config['sgd']['skip']:
    print("\n" + "=" * 80)
    print("7. STOCHASTIC GRADIENT DESCENT (SKIPPED - Already Trained)")
    print("=" * 80)
    sgd_model = joblib.load(training_config['sgd']['file'])
    sgd_pred = sgd_model.predict(X_test_scaled)
    sgd_mse = mean_squared_error(y_test, sgd_pred)
    sgd_rmse = np.sqrt(sgd_mse)
    sgd_mae = mean_absolute_error(y_test, sgd_pred)
    sgd_r2 = r2_score(y_test, sgd_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {sgd_rmse:.6f}")
    print(f"  - MAE:  {sgd_mae:.6f}")
    print(f"  - R²:   {sgd_r2:.4f}")
else:
    print("\n" + "=" * 80)
    print("7. STOCHASTIC GRADIENT DESCENT REGRESSOR")
    print("=" * 80)
    print("Tuning hyperparameters (learning_rate, alpha, eta0, loss) with cross-validation...")
    
    # Optuna-based hyperparameter tuning for SGD
    def sgd_objective(trial):
        params = {
            'alpha': 10 ** trial.suggest_float('alpha_log', -5, 0),
            'eta0': trial.suggest_float('eta0', 0.001, 0.1),
            'loss': trial.suggest_categorical('loss', ['squared_error', 'huber']),
            'epsilon': trial.suggest_float('epsilon', 0.1, 0.5),
            'random_state': 42
        }
        model = SGDRegressor(**params)
        scores = cross_val_score(model, X_train_scaled, y_train, cv=3, scoring='r2', n_jobs=-1)
        return scores.mean()
    
    study = optuna.create_study(direction='maximize', sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(sgd_objective, n_trials=20, show_progress_bar=True)
    
    best_params = study.best_params
    final_params = {
        'alpha': 10 ** best_params['alpha_log'],
        'eta0': best_params['eta0'],
        'loss': best_params['loss'],
        'epsilon': best_params['epsilon'],
        'random_state': 42
    }
    
    sgd_model = SGDRegressor(**final_params)
    sgd_model.fit(X_train_scaled, y_train)
    
    sgd_pred = sgd_model.predict(X_test_scaled)
    sgd_mse = mean_squared_error(y_test, sgd_pred)
    sgd_rmse = np.sqrt(sgd_mse)
    sgd_mae = mean_absolute_error(y_test, sgd_pred)
    sgd_r2 = r2_score(y_test, sgd_pred)
    
    print(f"[OK] SGD Results (Optuna Optimized):")
    print(f"  - Best hyperparameters: {final_params}")
    print(f"  - RMSE: {sgd_rmse:.6f}")
    print(f"  - MAE:  {sgd_mae:.6f}")
    print(f"  - R²:   {sgd_r2:.4f}")
    
    joblib.dump(sgd_model, 'sgd_epss_model.pkl')
    print(f"[OK] Model saved: sgd_epss_model.pkl")
    save_json({'best_params': final_params, 'model_params': sgd_model.get_params()}, 'sgd_params.json')
    
    try:
        cv_scores = cross_val_score(sgd_model, X_train_scaled, y_train, cv=5, scoring='r2')
        print(f"  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"  Cross-validation skipped: {str(e)[:80]}")

model_results['sgd'] = {'rmse': sgd_rmse, 'mae': sgd_mae, 'r2': sgd_r2}

# ============================================================================
# 8. POLYNOMIAL REGRESSION
# ============================================================================
if training_config['poly']['skip']:
    print("\n" + "=" * 80)
    print("8. POLYNOMIAL REGRESSION (SKIPPED - Already Trained)")
    print("=" * 80)
    poly_model = joblib.load(training_config['poly']['file'])
    poly_pred = poly_model.predict(X_test_scaled)
    poly_mse = mean_squared_error(y_test, poly_pred)
    poly_rmse = np.sqrt(poly_mse)
    poly_mae = mean_absolute_error(y_test, poly_pred)
    poly_r2 = r2_score(y_test, poly_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {poly_rmse:.6f}")
    print(f"  - MAE:  {poly_mae:.6f}")
    print(f"  - R²:   {poly_r2:.4f}")
else:
    print("\n" + "=" * 80)
    print("8. POLYNOMIAL REGRESSION (with Optuna Tuning)")
    print("=" * 80)
    print("Tuning hyperparameters (degree, alpha regularization) with 3-fold cross-validation...")
    
    # Optuna-based hyperparameter tuning for Polynomial Regression
    def poly_objective(trial):
        degree = trial.suggest_int('degree', 1, 3)
        alpha = 10 ** trial.suggest_float('alpha_log', -5, 0) if trial.suggest_categorical('use_ridge', [True, False]) else 0
        
        # Create pipeline with polynomial features and ridge regression
        from sklearn.linear_model import Ridge
        poly_transformer = PolynomialFeatures(degree=degree, include_bias=False)
        X_train_poly_temp = poly_transformer.fit_transform(X_train_scaled)
        
        if alpha > 0:
            model = Ridge(alpha=alpha, random_state=42)
        else:
            model = LinearRegression()
        
        from sklearn.pipeline import Pipeline
        pipeline = Pipeline([('poly', PolynomialFeatures(degree=degree, include_bias=False)), 
                           ('ridge', Ridge(alpha=alpha, random_state=42) if alpha > 0 else LinearRegression())])
        scores = cross_val_score(pipeline, X_train_scaled, y_train, cv=3, scoring='r2', n_jobs=-1)
        return scores.mean()
    
    study = optuna.create_study(direction='maximize', sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(poly_objective, n_trials=15, show_progress_bar=True)
    
    best_degree = study.best_params['degree']
    best_use_ridge = study.best_params['use_ridge']
    best_alpha_poly = 10 ** study.best_params['alpha_log'] if best_use_ridge else 0
    
    # Create best model
    poly_transformer = PolynomialFeatures(degree=best_degree, include_bias=False)
    X_train_poly = poly_transformer.fit_transform(X_train_scaled)
    X_test_poly = poly_transformer.transform(X_test_scaled)
    
    if best_alpha_poly > 0:
        from sklearn.linear_model import Ridge
        poly_model = Ridge(alpha=best_alpha_poly, random_state=42)
    else:
        poly_model = LinearRegression()
    
    poly_model.fit(X_train_poly, y_train)
    
    poly_pred = poly_model.predict(X_test_poly)
    poly_mse = mean_squared_error(y_test, poly_pred)
    poly_rmse = np.sqrt(poly_mse)
    poly_mae = mean_absolute_error(y_test, poly_pred)
    poly_r2 = r2_score(y_test, poly_pred)
    
    print(f"[OK] Polynomial Regression Results (Optuna Optimized):")
    print(f"  - Best degree: {best_degree}")
    print(f"  - Use Ridge regularization: {best_use_ridge}")
    if best_use_ridge:
        print(f"  - Best alpha: {best_alpha_poly:.6f}")
    print(f"  - Features after transformation: {X_train_poly.shape[1]} (from {X_train_scaled.shape[1]})")
    print(f"  - RMSE: {poly_rmse:.6f}")
    print(f"  - MAE:  {poly_mae:.6f}")
    print(f"  - R²:   {poly_r2:.4f}")
    
    # Save both transformer and model
    joblib.dump((poly_transformer, poly_model), 'poly_epss_model.pkl')
    print(f"[OK] Model saved: poly_epss_model.pkl")
    save_json({
        'best_degree': best_degree,
        'use_ridge': best_use_ridge,
        'best_alpha': best_alpha_poly if best_use_ridge else None,
        'n_features_original': X_train_scaled.shape[1],
        'n_features_transformed': X_train_poly.shape[1]
    }, 'poly_params.json')
    
    try:
        from sklearn.pipeline import Pipeline
        from sklearn.linear_model import Ridge
        if best_use_ridge:
            pipeline = Pipeline([('poly', PolynomialFeatures(degree=best_degree, include_bias=False)), 
                               ('ridge', Ridge(alpha=best_alpha_poly, random_state=42))])
        else:
            pipeline = Pipeline([('poly', PolynomialFeatures(degree=best_degree, include_bias=False)), 
                               ('linreg', LinearRegression())])
        cv_scores = cross_val_score(pipeline, X_train_scaled, y_train, cv=5, scoring='r2')
        print(f"  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"  Cross-validation skipped: {str(e)[:80]}")

model_results['poly'] = {'rmse': poly_rmse, 'mae': poly_mae, 'r2': poly_r2}

# ============================================================================
# 9. LASSO REGRESSION
# ============================================================================
if training_config['lasso']['skip']:
    print("\n" + "=" * 80)
    print("9. LASSO REGRESSION (SKIPPED - Already Trained)")
    print("=" * 80)
    lasso_model = joblib.load(training_config['lasso']['file'])
    lasso_pred = lasso_model.predict(X_test_scaled)
    lasso_mse = mean_squared_error(y_test, lasso_pred)
    lasso_rmse = np.sqrt(lasso_mse)
    lasso_mae = mean_absolute_error(y_test, lasso_pred)
    lasso_r2 = r2_score(y_test, lasso_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {lasso_rmse:.6f}")
    print(f"  - MAE:  {lasso_mae:.6f}")
    print(f"  - R²:   {lasso_r2:.4f}")
else:
    print("\n" + "=" * 80)
    print("9. LASSO REGRESSION")
    print("=" * 80)
    print("Tuning hyperparameter (alpha) with cross-validation...")
    
    # Optuna-based hyperparameter tuning for Lasso
    def lasso_objective(trial):
        alpha = 10 ** trial.suggest_float('alpha_log', -5, 1)
        model = Lasso(alpha=alpha, random_state=42, max_iter=10000)
        scores = cross_val_score(model, X_train_scaled, y_train, cv=3, scoring='r2', n_jobs=-1)
        return scores.mean()
    
    study = optuna.create_study(direction='maximize', sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(lasso_objective, n_trials=20, show_progress_bar=True)
    
    best_alpha = 10 ** study.best_params['alpha_log']
    
    lasso_model = Lasso(alpha=best_alpha, random_state=42, max_iter=10000)
    lasso_model.fit(X_train_scaled, y_train)
    
    lasso_pred = lasso_model.predict(X_test_scaled)
    lasso_mse = mean_squared_error(y_test, lasso_pred)
    lasso_rmse = np.sqrt(lasso_mse)
    lasso_mae = mean_absolute_error(y_test, lasso_pred)
    lasso_r2 = r2_score(y_test, lasso_pred)
    
    print(f"[OK] Lasso Regression Results (Optuna Optimized):")
    print(f"  - Best alpha: {best_alpha:.6f}")
    print(f"  - Non-zero coefficients: {np.sum(lasso_model.coef_ != 0)} / {len(lasso_model.coef_)}")
    print(f"  - RMSE: {lasso_rmse:.6f}")
    print(f"  - MAE:  {lasso_mae:.6f}")
    print(f"  - R²:   {lasso_r2:.4f}")
    
    joblib.dump(lasso_model, 'lasso_epss_model.pkl')
    print(f"[OK] Model saved: lasso_epss_model.pkl")
    save_json({'best_alpha': best_alpha, 'non_zero_coeffs': int(np.sum(lasso_model.coef_ != 0))}, 'lasso_params.json')
    
    try:
        cv_scores = cross_val_score(lasso_model, X_train_scaled, y_train, cv=5, scoring='r2')
        print(f"  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"  Cross-validation skipped: {str(e)[:80]}")

model_results['lasso'] = {'rmse': lasso_rmse, 'mae': lasso_mae, 'r2': lasso_r2}

# ============================================================================
# 10. ELASTICNET REGRESSION
# ============================================================================
if training_config['elasticnet']['skip']:
    print("\n" + "=" * 80)
    print("10. ELASTICNET REGRESSION (SKIPPED - Already Trained)")
    print("=" * 80)
    elasticnet_model = joblib.load(training_config['elasticnet']['file'])
    elasticnet_pred = elasticnet_model.predict(X_test_scaled)
    elasticnet_mse = mean_squared_error(y_test, elasticnet_pred)
    elasticnet_rmse = np.sqrt(elasticnet_mse)
    elasticnet_mae = mean_absolute_error(y_test, elasticnet_pred)
    elasticnet_r2 = r2_score(y_test, elasticnet_pred)
    print(f"Model loaded successfully!")
    print(f"  - RMSE: {elasticnet_rmse:.6f}")
    print(f"  - MAE:  {elasticnet_mae:.6f}")
    print(f"  - R²:   {elasticnet_r2:.4f}")
else:
    print("\n" + "=" * 80)
    print("10. ELASTICNET REGRESSION")
    print("=" * 80)
    print("Tuning hyperparameters (alpha, l1_ratio) with cross-validation...")
    
    # Optuna-based hyperparameter tuning for ElasticNet
    def elasticnet_objective(trial):
        alpha = 10 ** trial.suggest_float('alpha_log', -5, 1)
        l1_ratio = trial.suggest_float('l1_ratio', 0.0, 1.0)
        model = ElasticNet(alpha=alpha, l1_ratio=l1_ratio, random_state=42, max_iter=10000)
        scores = cross_val_score(model, X_train_scaled, y_train, cv=3, scoring='r2', n_jobs=-1)
        return scores.mean()
    
    study = optuna.create_study(direction='maximize', sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(elasticnet_objective, n_trials=20, show_progress_bar=True)
    
    best_alpha = 10 ** study.best_params['alpha_log']
    best_l1_ratio = study.best_params['l1_ratio']
    
    elasticnet_model = ElasticNet(alpha=best_alpha, l1_ratio=best_l1_ratio, random_state=42, max_iter=10000)
    elasticnet_model.fit(X_train_scaled, y_train)
    
    elasticnet_pred = elasticnet_model.predict(X_test_scaled)
    elasticnet_mse = mean_squared_error(y_test, elasticnet_pred)
    elasticnet_rmse = np.sqrt(elasticnet_mse)
    elasticnet_mae = mean_absolute_error(y_test, elasticnet_pred)
    elasticnet_r2 = r2_score(y_test, elasticnet_pred)
    
    print(f"[OK] ElasticNet Regression Results (Optuna Optimized):")
    print(f"  - Best alpha: {best_alpha:.6f}")
    print(f"  - Best l1_ratio: {best_l1_ratio:.4f}")
    print(f"  - Non-zero coefficients: {np.sum(elasticnet_model.coef_ != 0)} / {len(elasticnet_model.coef_)}")
    print(f"  - RMSE: {elasticnet_rmse:.6f}")
    print(f"  - MAE:  {elasticnet_mae:.6f}")
    print(f"  - R²:   {elasticnet_r2:.4f}")
    
    joblib.dump(elasticnet_model, 'elasticnet_epss_model.pkl')
    print(f"[OK] Model saved: elasticnet_epss_model.pkl")
    save_json({'best_alpha': best_alpha, 'best_l1_ratio': best_l1_ratio, 'non_zero_coeffs': int(np.sum(elasticnet_model.coef_ != 0))}, 'elasticnet_params.json')
    
    try:
        cv_scores = cross_val_score(elasticnet_model, X_train_scaled, y_train, cv=5, scoring='r2')
        print(f"  Cross-validation R² Scores: {cv_scores}")
        print(f"  Mean CV R²: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    except Exception as e:
        print(f"  Cross-validation skipped: {str(e)[:80]}")

model_results['elasticnet'] = {'rmse': elasticnet_rmse, 'mae': elasticnet_mae, 'r2': elasticnet_r2}

# ============================================================================
# MODEL COMPARISON
# ============================================================================
print("\n" + "=" * 80)
print("MODEL PERFORMANCE COMPARISON (All Models)")
print("=" * 80)

comparison_df = pd.DataFrame({
    'Model': [
        'Random Forest (FLAML)', 'LightGBM (FLAML)', 'XGBoost (FLAML)', 'KNN (FLAML)', 
        f'SVM ({best_svm_kernel})', 'Linear Regression', 'SGD', 'Polynomial (Degree 2)',
        'Lasso', 'ElasticNet'
    ],
    'RMSE': [
        model_results['rf']['rmse'], model_results['lgb']['rmse'], model_results['xgb']['rmse'], 
        model_results['knn']['rmse'], svm_rmse, model_results['linreg']['rmse'],
        model_results['sgd']['rmse'], model_results['poly']['rmse'], 
        model_results['lasso']['rmse'], model_results['elasticnet']['rmse']
    ],
    'MAE': [
        model_results['rf']['mae'], model_results['lgb']['mae'], model_results['xgb']['mae'],
        model_results['knn']['mae'], svm_mae, model_results['linreg']['mae'],
        model_results['sgd']['mae'], model_results['poly']['mae'],
        model_results['lasso']['mae'], model_results['elasticnet']['mae']
    ],
    'R² Score': [
        model_results['rf']['r2'], model_results['lgb']['r2'], model_results['xgb']['r2'],
        model_results['knn']['r2'], svm_r2, model_results['linreg']['r2'],
        model_results['sgd']['r2'], model_results['poly']['r2'],
        model_results['lasso']['r2'], model_results['elasticnet']['r2']
    ]
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
print("TRAINING SUMMARY")
print("=" * 80)

if not training_config['rf']['skip']:
    print(f"\nRandom Forest Best Config: {automl_rf.best_config}")
if not training_config['lgb']['skip']:
    print(f"LightGBM Best Config:      {automl_lgb.best_config}")
if not training_config['xgb']['skip']:
    print(f"XGBoost Best Config:       {automl_xgb.best_config}")
if not training_config['knn']['skip']:
    print(f"KNN Best Config:           {automl_knn.best_config}")

if not training_config['svm']['skip']:
    print(f"\nSVM Best Kernel:           {best_svm_kernel}")
    print(f"SVM (FLAML) Tuning Notes:")
    print(f"  - Hyperparameters automatically optimized by FLAML")
    print(f"  - C (regularization), gamma, epsilon tuned per kernel")

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
elif best_model_idx == 3:
    use_predictions = knn_pred
    model_name = "KNN (FLAML)"
else:
    use_predictions = svm_pred
    model_name = f"SVM ({best_svm_kernel})"

print(f"\nSample Predictions (using {model_name}):\n")
print(f"{'Actual EPSS':<15} {'Prediction':<15} {'Error':<10}")
print("-" * 40)

for idx in sample_indices:
    actual = y_test[idx]
    pred = use_predictions[idx]
    error = abs(actual - pred)
    print(f"{actual:<15.6f} {pred:<15.6f} {error:<10.6f}")

print("\n[OK] ML MODEL TRAINING COMPLETE!")
print("\nSaved Models:")
if not training_config['rf']['skip']:
    print("  - rf_epss_model.pkl")
if not training_config['lgb']['skip']:
    print("  - lgb_epss_model.pkl")
if not training_config['xgb']['skip']:
    print("  - xgb_epss_model.pkl")
if not training_config['knn']['skip']:
    print("  - knn_epss_model.pkl")
if not training_config['svm']['skip']:
    print("  - svm_epss_models.pkl (all kernel variants)")
if not training_config['linreg']['skip']:
    print("  - linreg_epss_model.pkl")
if not training_config['sgd']['skip']:
    print("  - sgd_epss_model.pkl")
if not training_config['poly']['skip']:
    print("  - poly_epss_model.pkl")
if not training_config['lasso']['skip']:
    print("  - lasso_epss_model.pkl")
if not training_config['elasticnet']['skip']:
    print("  - elasticnet_epss_model.pkl")
print(f"\n Best Model: {best_model_name}")
print(f"   Expected R² on new data: ~{best_r2:.4f}")
print(f"   RMSE: {best_rmse:.6f}")
