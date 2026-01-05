"""
EPSS Score Prediction using Trained Models
Load a trained model and predict EPSS scores for new CVEs
"""

import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime

class EPSSPredictorPipeline:
    """
    Pipeline for encoding new CVE data and predicting EPSS scores
    using pre-trained ML models.
    """
    
    def __init__(self, model_path='rf_epss_model.pkl', feature_mapping_path='feature_mapping.json'):
        """
        Initialize the predictor with a trained model.
        
        Args:
            model_path: Path to saved model (e.g., 'rf_epss_model.pkl')
            feature_mapping_path: Path to feature mapping JSON
        """
        self.model = joblib.load(model_path)
        
        with open(feature_mapping_path, 'r') as f:
            self.feature_mapping = json.load(f)
        
        self.feature_columns = self.feature_mapping['all_features']
        print(f" Loaded model from {model_path}")
        print(f" Expected features: {len(self.feature_columns)}")
    
    def encode_new_cve_data(self, cve_data):
        """
        Encode raw CVE data to match training feature format.
        
        Args:
            cve_data: Dict with CVE information
                {
                    'base_score': 7.5,
                    'exploitability_score': 3.9,
                    'impact_score': 3.6,
                    'epss_perc': 0.85,
                    'base_severity': 'HIGH',
                    'cisa_kev': False,
                    'attack_vector': 'NETWORK',
                    'attack_complexity': 'LOW',
                    'privileges_required': 'NONE',
                    'user_interaction': 'NONE',
                    'scope': 'UNCHANGED',
                    'confidentiality_impact': 'NONE',
                    'integrity_impact': 'NONE',
                    'availability_impact': 'HIGH',
                    'published_date': '2023-01-15',
                    'affected_software': 'apache:httpd, linux:kernel',
                    'affected_versions': '1.0, 2.0, 2.1'
                }
        
        Returns:
            pd.DataFrame: Encoded features ready for prediction
        """
        
        # Initialize feature dict
        features = {}
        
        # 1. Add numeric features (direct copy)
        numeric_cols = ['base_score', 'exploitability_score', 'impact_score', 'epss_perc']
        for col in numeric_cols:
            features[col] = cve_data.get(col, 0)
        
        # 2. Encode temporal features
        if 'published_date' in cve_data:
            pub_date = pd.to_datetime(cve_data['published_date'])
            # Remove timezone info to avoid tz-naive vs tz-aware errors
            if pub_date.tzinfo is not None:
                pub_date = pub_date.tz_localize(None)
            now = pd.Timestamp.now()
            features['days_since_publication'] = (now - pub_date).days
            features['year_published'] = pub_date.year
            features['month_published'] = pub_date.month
            features['quarter_published'] = pub_date.quarter
        else:
            features['days_since_publication'] = 0
            features['year_published'] = datetime.now().year
            features['month_published'] = datetime.now().month
            features['quarter_published'] = (datetime.now().month - 1) // 3 + 1
        
        # 3. Encode ordinal categorical (base_severity)
        severity_mapping = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        features['base_severity_encoded'] = severity_mapping.get(
            cve_data.get('base_severity', 'MEDIUM'), 2
        )
        
        # 4. Encode binary categorical (cisa_kev)
        features['cisa_kev'] = 1 if cve_data.get('cisa_kev', False) else 0
        
        # 5. One-hot encode nominal categorical features
        categorical_cols = {
            'attack_vector': ['NETWORK', 'LOCAL', 'ADJACENT_NETWORK', 'PHYSICAL'],
            'attack_complexity': ['LOW', 'HIGH'],
            'privileges_required': ['NONE', 'LOW', 'HIGH'],
            'user_interaction': ['NONE', 'REQUIRED'],
            'scope': ['UNCHANGED', 'CHANGED'],
            'confidentiality_impact': ['NONE', 'LOW', 'HIGH'],
            'integrity_impact': ['NONE', 'LOW', 'HIGH'],
            'availability_impact': ['NONE', 'LOW', 'HIGH']
        }
        
        for col, categories in categorical_cols.items():
            value = cve_data.get(col, categories[0])
            for cat in categories:
                col_name = f"{col}_{cat}"
                features[col_name] = 1 if value == cat else 0
        
        # 6. Extract features from text
        if 'affected_software' in cve_data:
            software = str(cve_data['affected_software']).split(',')
            features['num_affected_software'] = len([s for s in software if s.strip()])
        else:
            features['num_affected_software'] = 0
        
        if 'affected_versions' in cve_data:
            versions = str(cve_data['affected_versions']).split(',')
            features['num_affected_versions'] = len([v for v in versions if v.strip()])
        else:
            features['num_affected_versions'] = 0
        
        # 7. Create DataFrame with correct column order
        df = pd.DataFrame([features])
        
        # Ensure all expected columns exist
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Select only columns in correct order
        df = df[self.feature_columns]
        
        return df
    
    def predict(self, cve_data):
        """
        Predict EPSS score for a CVE.
        
        Args:
            cve_data: Dict with CVE information
        
        Returns:
            float: Predicted EPSS score (0.0 - 1.0)
        """
        encoded_features = self.encode_new_cve_data(cve_data)
        prediction = self.model.predict(encoded_features)[0]
        return float(prediction)
    
    def predict_batch(self, cve_data_list):
        """
        Predict EPSS scores for multiple CVEs.
        
        Args:
            cve_data_list: List of dicts with CVE information
        
        Returns:
            np.ndarray: Array of predictions
        """
        encoded_list = []
        for cve_data in cve_data_list:
            encoded_list.append(self.encode_new_cve_data(cve_data).values[0])
        
        encoded_array = np.array(encoded_list)
        predictions = self.model.predict(encoded_array)
        return predictions


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    
    print("=" * 80)
    print("EPSS SCORE PREDICTION PIPELINE")
    print("=" * 80)
    
    # Initialize predictor with Random Forest model
    # (You can change to 'lgb_epss_model.pkl', 'xgb_epss_model.pkl', or 'knn_epss_model.pkl')
    predictor = EPSSPredictorPipeline(
        model_path='rf_epss_model.pkl',
        feature_mapping_path='feature_mapping.json'
    )
    
    # ========================================================================
    # EXAMPLE 1: Single CVE Prediction
    # ========================================================================
    print("\n" + "=" * 80)
    print("EXAMPLE 1: SINGLE CVE PREDICTION")
    print("=" * 80)
    
    cve_example = {
        'base_score': 9.8,
        'exploitability_score': 3.9,
        'impact_score': 5.9,
        'epss_perc': 0.90,
        'base_severity': 'CRITICAL',
        'cisa_kev': False,
        'attack_vector': 'NETWORK',
        'attack_complexity': 'LOW',
        'privileges_required': 'NONE',
        'user_interaction': 'NONE',
        'scope': 'UNCHANGED',
        'confidentiality_impact': 'HIGH',
        'integrity_impact': 'HIGH',
        'availability_impact': 'HIGH',
        'published_date': '2023-06-15',
        'affected_software': 'apache:httpd, linux:kernel',
        'affected_versions': '2.4.55, 5.10'
    }
    
    print("\nCVE Details:")
    for key, value in cve_example.items():
        print(f"  {key:30s}: {value}")
    
    epss_pred = predictor.predict(cve_example)
    print(f"\n Predicted EPSS Score: {epss_pred:.6f}")
    print(f"  Risk Level: {'CRITICAL' if epss_pred > 0.8 else 'HIGH' if epss_pred > 0.5 else 'MEDIUM'}")
    
    # ========================================================================
    # EXAMPLE 2: Multiple CVE Predictions (Batch)
    # ========================================================================
    print("\n" + "=" * 80)
    print("EXAMPLE 2: BATCH PREDICTION (Multiple CVEs)")
    print("=" * 80)
    
    cve_batch = [
        {
            'base_score': 7.5,
            'exploitability_score': 3.9,
            'impact_score': 3.6,
            'epss_perc': 0.85,
            'base_severity': 'HIGH',
            'cisa_kev': False,
            'attack_vector': 'NETWORK',
            'attack_complexity': 'LOW',
            'privileges_required': 'NONE',
            'user_interaction': 'NONE',
            'scope': 'UNCHANGED',
            'confidentiality_impact': 'NONE',
            'integrity_impact': 'NONE',
            'availability_impact': 'HIGH',
            'published_date': '2024-01-10',
            'affected_software': 'nginx:nginx',
            'affected_versions': '1.24.0'
        },
        {
            'base_score': 5.5,
            'exploitability_score': 1.8,
            'impact_score': 3.6,
            'epss_perc': 0.45,
            'base_severity': 'MEDIUM',
            'cisa_kev': True,
            'attack_vector': 'LOCAL',
            'attack_complexity': 'LOW',
            'privileges_required': 'LOW',
            'user_interaction': 'NONE',
            'scope': 'UNCHANGED',
            'confidentiality_impact': 'NONE',
            'integrity_impact': 'NONE',
            'availability_impact': 'HIGH',
            'published_date': '2024-02-20',
            'affected_software': 'linux:linux_kernel',
            'affected_versions': '6.1'
        },
        {
            'base_score': 9.0,
            'exploitability_score': 3.1,
            'impact_score': 5.9,
            'epss_perc': 0.92,
            'base_severity': 'CRITICAL',
            'cisa_kev': False,
            'attack_vector': 'NETWORK',
            'attack_complexity': 'LOW',
            'privileges_required': 'NONE',
            'user_interaction': 'REQUIRED',
            'scope': 'CHANGED',
            'confidentiality_impact': 'HIGH',
            'integrity_impact': 'HIGH',
            'availability_impact': 'NONE',
            'published_date': '2024-03-05',
            'affected_software': 'python:cpython, django:django',
            'affected_versions': '3.10, 4.2'
        }
    ]
    
    predictions = predictor.predict_batch(cve_batch)
    
    print(f"\n{'CVE':<5} {'Base Score':<12} {'Severity':<12} {'Predicted EPSS':<15} {'Risk':<10}")
    print("-" * 60)
    for i, pred in enumerate(predictions):
        base_score = cve_batch[i]['base_score']
        severity = cve_batch[i]['base_severity']
        risk = 'CRITICAL' if pred > 0.8 else 'HIGH' if pred > 0.5 else 'MEDIUM'
        print(f"CVE-{i+1:<2} {base_score:<12.1f} {severity:<12s} {pred:<15.6f} {risk:<10s}")
    
    # ========================================================================
    # EXAMPLE 3: Predicting from CSV
    # ========================================================================
    print("\n" + "=" * 80)
    print("EXAMPLE 3: BATCH PREDICTION FROM CSV")
    print("=" * 80)
    
    print("\nTo predict EPSS scores for CVEs in a CSV file:")
    print("""
    # Load CVEs from CSV
    cves_df = pd.read_csv('your_cves.csv')
    
    # Convert to list of dicts
    cves_list = cves_df.to_dict('records')
    
    # Predict
    predictor = EPSSPredictorPipeline('rf_epss_model.pkl')
    predictions = predictor.predict_batch(cves_list)
    
    # Add predictions to dataframe
    cves_df['predicted_epss'] = predictions
    cves_df.to_csv('cves_with_predictions.csv', index=False)
    """)
    
    print("\n PREDICTION PIPELINE READY!")
    print("\nUse EPSSPredictorPipeline class for custom predictions:")
    print("  - predictor.predict(cve_dict) for single CVE")
    print("  - predictor.predict_batch(cve_list) for multiple CVEs")
