"""
Test Trained Models on Current Dataset
Evaluate model performance by comparing predictions against actual EPSS scores
"""

import os
import glob
import pandas as pd
import numpy as np
import joblib
import json
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns

def extract_model_parameters(model, model_name):
    """
    Extract and format model hyperparameters.
    
    Args:
        model: Trained model object (may be FLAML wrapper or raw model)
        model_name: Name of the model
    
    Returns:
        dict: Key hyperparameters with actual values
    """
    # FLAML wraps models - extract the underlying model if wrapped
    if hasattr(model, 'model'):
        # FLAML wrapper - get underlying model
        actual_model = model.model
    elif hasattr(model, 'estimator'):
        # Some wrappers use .estimator
        actual_model = model.estimator
    else:
        # Already unwrapped
        actual_model = model
    
    # Get all parameters
    params = actual_model.get_params()
    
    # Define important parameters for each model type and extract with defaults
    if 'Random Forest' in model_name:
        important_params = {
            'n_estimators': params.get('n_estimators', 100),
            'max_depth': params.get('max_depth', 'unlimited') if params.get('max_depth') is not None else 'unlimited',
            'min_samples_split': params.get('min_samples_split', 2),
            'min_samples_leaf': params.get('min_samples_leaf', 1),
            'max_features': params.get('max_features', 1.0),
            'random_state': params.get('random_state', None)
        }
    elif 'XGBoost' in model_name:
        important_params = {
            'n_estimators': params.get('n_estimators', 100),
            'max_depth': params.get('max_depth', 6),
            'learning_rate': params.get('learning_rate', 0.3),
            'subsample': params.get('subsample', 1.0),
            'colsample_bytree': params.get('colsample_bytree', 1.0),
            'reg_alpha': params.get('reg_alpha', 0.0),
            'reg_lambda': params.get('reg_lambda', 1.0)
        }
    elif 'LightGBM' in model_name:
        important_params = {
            'n_estimators': params.get('n_estimators', 100),
            'max_depth': params.get('max_depth', -1),
            'learning_rate': params.get('learning_rate', 0.1),
            'num_leaves': params.get('num_leaves', 31),
            'subsample': params.get('subsample', 1.0),
            'colsample_bytree': params.get('colsample_bytree', 1.0),
            'reg_alpha': params.get('reg_alpha', 0.0),
            'reg_lambda': params.get('reg_lambda', 0.0)
        }
    elif 'K-Nearest' in model_name:
        important_params = {
            'n_neighbors': params.get('n_neighbors', 5),
            'weights': params.get('weights', 'uniform'),
            'algorithm': params.get('algorithm', 'auto'),
            'leaf_size': params.get('leaf_size', 30),
            'p': params.get('p', 2)
        }
    else:
        # Return all params if model type unknown
        important_params = params
    
    return important_params


def discover_models():
    """
    Find available model pickle files in the repo.
    Looks in current directory and ./models for *.pkl files.
    Returns list of tuples: (model_path, display_name, uses_scaled_features)
    """
    candidates = []
    search_paths = ['.', './models']
    seen = set()

    def display_name_from_filename(fname: str) -> str:
        base = os.path.basename(fname).lower()
        if 'random' in base or 'rf_' in base:
            return 'Random Forest'
        if 'xgb' in base or 'xgboost' in base:
            return 'XGBoost'
        if 'lgb' in base or 'lightgbm' in base:
            return 'LightGBM'
        if 'knn' in base or 'kneighbor' in base:
            return 'K-Nearest Neighbors'
        if 'svm' in base and 'linear' in base:
            return 'SVM (Linear)'
        if 'svm' in base and 'rbf' in base:
            return 'SVM (RBF)'
        if 'svm' in base and 'poly' in base:
            return 'SVM (Poly)'
        if 'svm' in base and 'sigmoid' in base:
            return 'SVM (Sigmoid)'
        if 'linreg' in base or 'linear_regression' in base:
            return 'Linear Regression'
        if 'elasticnet' in base:
            return 'ElasticNet'
        if 'lasso' in base:
            return 'Lasso'
        if 'sgd' in base:
            return 'SGD Regressor'
        # Check for polynomial regression (but not SVM poly)
        if 'poly' in base and 'svm' not in base:
            return 'Polynomial Regression'
        # Fallback to filename
        return os.path.splitext(os.path.basename(fname))[0]

    def needs_scaled(name: str) -> bool:
        name_lower = name.lower()
        # Distance/linear methods generally need scaling
        return any(key in name_lower for key in [
            'knn', 'svm', 'linear regression', 'elasticnet', 'lasso', 'sgd', 'polynomial'
        ])

    for path in search_paths:
        for f in glob.glob(os.path.join(path.replace('\\', '/'), '*.pkl')):
            norm = os.path.normpath(f)
            if norm in seen:
                continue
            name = display_name_from_filename(norm)
            scaled = needs_scaled(name)
            candidates.append((norm, name, scaled))
            seen.add(norm)

    # Prefer unique display names; if duplicates, keep first occurrence
    unique = []
    seen_names = set()
    for m in candidates:
        if m[1] in seen_names:
            continue
        seen_names.add(m[1])
        unique.append(m)

    return unique


def load_params_json_fallback(model_display_name: str) -> dict | None:
    """
    Attempt to load hyperparameters from models/*.json when get_params is not informative.
    Returns dict or None if not found.
    """
    mapping = {
        'Random Forest': 'rf_params.json',
        'XGBoost': 'xgb_params.json',
        'LightGBM': 'lgb_params.json',
        'K-Nearest Neighbors': 'knn_params.json',
        'Linear Regression': 'linreg_params.json',
        'ElasticNet': 'elasticnet_params.json',
        'Lasso': 'lasso_params.json',
        'SGD Regressor': 'sgd_params.json',
        'Polynomial Regression': 'poly_params.json',
        'SVM (RBF)': 'svm_params.json',
        'SVM (Poly)': 'svm_params.json',
        'SVM (Sigmoid)': 'svm_params.json',
        'SVM (Linear)': 'svm_params.json',
    }
    fname = mapping.get(model_display_name)
    if not fname:
        return None
    path = os.path.join('models', fname)
    if not os.path.exists(path):
        # Also check root
        path = fname
        if not os.path.exists(path):
            return None
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        # Some files store under 'model_params' or 'params'
        if isinstance(data, dict):
            for key in ['model_params', 'params']:
                if key in data and isinstance(data[key], dict):
                    return data[key]
        return data
    except Exception:
        return None


def evaluate_model(model_path, X_test, actual_scores, model_name, use_scaled=False):
    """
    Evaluate a single model on test data.
    
    Args:
        model_path: Path to the saved model
        X_test: DataFrame with preprocessed features
        actual_scores: Array of actual EPSS scores
        model_name: Name of the model for display
        use_scaled: Whether this model uses scaled features
    
    Returns:
        dict: Evaluation metrics
    """
    print(f"\n{'='*80}")
    print(f"Testing: {model_name}")
    print(f"{'='*80}")
    
    # Load model directly and make predictions
    model = joblib.load(model_path)
    
    # Handle special case: Polynomial Regression saved as tuple (poly_features, ridge_model)
    if isinstance(model, tuple) and len(model) == 2:
        from sklearn.pipeline import Pipeline
        poly_features, ridge_model = model
        model = Pipeline([
            ('poly', poly_features),
            ('ridge', ridge_model)
        ])
    
    predictions = model.predict(X_test)
    
    # Extract hyperparameters (fallback to JSON if needed)
    try:
        hyperparameters = extract_model_parameters(model, model_name)
    except Exception:
        hyperparameters = None
    if not hyperparameters or (isinstance(hyperparameters, dict) and not hyperparameters):
        hp_json = load_params_json_fallback(model_name)
        if hp_json:
            hyperparameters = hp_json
        else:
            hyperparameters = {}
    
    # Calculate metrics
    mae = mean_absolute_error(actual_scores, predictions)
    rmse = np.sqrt(mean_squared_error(actual_scores, predictions))
    r2 = r2_score(actual_scores, predictions)
    
    # Calculate percentage within tolerance
    tolerance = 0.1  # 10% tolerance
    within_tolerance = np.mean(np.abs(actual_scores - predictions) <= tolerance)
    
    metrics = {
        'model': model_name,
        'mae': mae,
        'rmse': rmse,
        'r2': r2,
        'within_10%': within_tolerance * 100,
        'predictions': predictions,
        'hyperparameters': hyperparameters
    }
    
    print(f"\n📊 Performance Metrics:")
    print(f"  Mean Absolute Error (MAE):  {mae:.6f}")
    print(f"  Root Mean Squared Error:    {rmse:.6f}")
    print(f"  R² Score:                   {r2:.6f}")
    print(f"  Within 10% Tolerance:       {within_tolerance*100:.2f}%")
    
    print(f"\n  FLAML-Optimized Hyperparameters:")
    for param, value in hyperparameters.items():
        print(f"  {param:20s}: {value}")
    
    return metrics


def plot_predictions_vs_actual(results, actual_scores, sample_size=1000):
    """
    Create visualization comparing predictions vs actual scores.
    
    Args:
        results: List of metric dictionaries from all models
        actual_scores: Array of actual EPSS scores
        sample_size: Number of samples to plot (for performance)
    """
    n_models = len(results)
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    axes = axes.flatten()
    
    # Sample data for plotting
    indices = np.random.choice(len(actual_scores), size=min(sample_size, len(actual_scores)), replace=False)
    actual_sample = actual_scores[indices]
    
    for idx, result in enumerate(results):
        ax = axes[idx]
        pred_sample = result['predictions'][indices]
        
        # Scatter plot
        ax.scatter(actual_sample, pred_sample, alpha=0.5, s=10)
        
        # Perfect prediction line
        min_val = min(actual_sample.min(), pred_sample.min())
        max_val = max(actual_sample.max(), pred_sample.max())
        ax.plot([min_val, max_val], [min_val, max_val], 'r--', label='Perfect Prediction')
        
        # Labels and title
        ax.set_xlabel('Actual EPSS Score')
        ax.set_ylabel('Predicted EPSS Score')
        ax.set_title(f"{result['model']}\nR² = {result['r2']:.4f}, MAE = {result['mae']:.6f}")
        ax.legend()
        ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('model_predictions_comparison.png', dpi=300, bbox_inches='tight')
    print(f"\n Visualization saved to: model_predictions_comparison.png")
    plt.close()


def create_comparison_report(results):
    """
    Create a comparison report of all models.
    
    Args:
        results: List of metric dictionaries from all models
    """
    print(f"\n{'='*80}")
    print("MODEL COMPARISON SUMMARY")
    print(f"{'='*80}")
    
    # Create comparison DataFrame
    comparison_df = pd.DataFrame([
        {
            'Model': r['model'],
            'MAE': r['mae'],
            'RMSE': r['rmse'],
            'R² Score': r['r2'],
            'Within 10%': f"{r['within_10%']:.2f}%"
        }
        for r in results
    ])
    
    # Sort by R² score (descending)
    comparison_df = comparison_df.sort_values('R² Score', ascending=False)
    
    print("\n" + comparison_df.to_string(index=False))
    
    # Save to CSV
    comparison_df.to_csv('model_comparison_results.csv', index=False)
    print(f"\n Comparison saved to: model_comparison_results.csv")
        # Save to JSON
    results_json = []
    for r in results:
        results_json.append({
            'model': r['model'],
            'mae': r['mae'],
            'rmse': r['rmse'],
            'r2': r['r2'],
            'within_10_percent': r['within_10%']
        })
    
    with open('model_comparison_results.json', 'w') as f:
        json.dump(results_json, f, indent=2)
    print(f"📁 Comparison saved to: model_comparison_results.json")
        # Identify best model
    best_model = comparison_df.iloc[0]['Model']
    best_r2 = comparison_df.iloc[0]['R² Score']
    print(f"\n Best Model: {best_model} (R² = {best_r2:.6f})")
    
    return comparison_df


def main():
    """
    Main function to test all models on the dataset.
    """
    print("="*80)
    print("TESTING TRAINED MODELS ON VALIDATION DATASET")
    print("="*80)
    
    # Load preprocessed features and targets
    print("\n Loading preprocessed data...")
    X_unscaled = pd.read_csv('X_features_unscaled.csv')
    X_scaled = pd.read_csv('X_features_scaled.csv')
    y = pd.read_csv('y_target.csv').values.ravel()
    
    print(f"  Features shape: {X_unscaled.shape}")
    print(f"  Target shape: {y.shape}")
    
    # Use the SAME split as training (test_size=0.2, random_state=42)
    print("\n Splitting data using same parameters as training...")
    print("  - Train/Test split: 80/20")
    print("  - Random state: 42")
    print("  - This matches the validation set used during training")
    
    # Split both unscaled and scaled features
    _, X_test_unscaled, _, y_test = train_test_split(
        X_unscaled, y, test_size=0.2, random_state=42
    )
    _, X_test_scaled, _, _ = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42
    )
    
    print(f"\n Validation set: {len(X_test_unscaled):,} CVEs")
    print(f"  (Exact same validation set from training)")
    
    # Discover models dynamically
    discovered = discover_models()
    if not discovered:
        print("\n No model .pkl files found in current folder or ./models")
    else:
        print("\n🔎 Discovered models:")
        for p, n, s in discovered:
            print(f"  - {n} ({'scaled' if s else 'unscaled'}) @ {p}")

    # Prepare test inputs per model
    models = []
    for model_path, name, use_scaled in discovered:
        X_test = X_test_scaled if use_scaled else X_test_unscaled
        models.append((model_path, name, X_test))
    
    # Test each model
    results = []
    for model_path, model_name, X_test in models:
        try:
            use_scaled = 'scaled' in str(X_test.columns) or model_name == 'K-Nearest Neighbors'
            metrics = evaluate_model(model_path, X_test, y_test, model_name, use_scaled)
            results.append(metrics)
        except FileNotFoundError:
            print(f"\n  Model not found: {model_path}")
        except Exception as e:
            print(f"\n Error testing {model_name}: {str(e)}")
    
    if not results:
        print("\n❌ No models could be tested!")
        return
    # Save hyperparameters to file
    print(f"\n{'='*80}")
    print("SAVING HYPERPARAMETERS")
    print(f"{'='*80}")
    
    hyperparams_data = {}
    for result in results:
        hyperparams_data[result['model']] = result['hyperparameters']
    
    with open('model_hyperparameters.json', 'w') as f:
        json.dump(hyperparams_data, f, indent=2, default=str)
    print(f"\n Hyperparameters saved to: model_hyperparameters.json")
    
    # Create comparison report
    comparison_df = create_comparison_report(results)
    
    # Create visualization
    print(f" MODEL TESTING COMPLETE!")
    print(f"{'='*80}")
    print("\nGenerated files:")
    print("  - model_comparison_results.csv")    
    print("  - model_comparison_results.json")    
    print("  - model_hyperparameters.json")
    print("  - model_predictions_comparison.png")
    # Error distribution analysis
    print(f"\n{'='*80}")
    print("ERROR DISTRIBUTION ANALYSIS")
    print(f"{'='*80}")
    
    for result in results:
        errors = y_test - result['predictions']
        print(f"\n{result['model']}:")
        print(f"  Mean Error:      {np.mean(errors):+.6f}")
        print(f"  Median Error:    {np.median(errors):+.6f}")
        print(f"  Std Dev:         {np.std(errors):.6f}")
        print(f"  Max Overpredict: {errors.min():.6f}")
        print(f"  Max Underpredict: {errors.max():.6f}")
    
    print(f"\n{'='*80}")
    print(" MODEL TESTING COMPLETE!")
    print(f"{'='*80}")
    print("\nGenerated files:")
    print("  - model_comparison_results.csv")    
    print("  - model_comparison_results.json")
    print("  - model_hyperparameters.json")    
    print("  - model_predictions_comparison.png")


if __name__ == "__main__":
    main()
