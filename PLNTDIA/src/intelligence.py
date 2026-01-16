import json
import os
import joblib
import pandas as pd
import requests
from datetime import datetime
from .cve_dataset import cve_dataset

# --- CONFIGURAÇÃO ---
# Caminhos relativos à raiz do projeto (onde corre o app.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # PLNTDIA root
MAPPING_PATH = os.path.join(BASE_DIR, "ml_models", "feature_mapping.json")

# AAUTIA models directory (all trained models)
CHALLENGE2_DIR = os.path.dirname(BASE_DIR)  # Challenge2 root
AAUTIA_MODELS_DIR = os.path.join(CHALLENGE2_DIR, "AAUTIA", "models")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEIntelligence:
    def __init__(self):
        self.models = {}  # Dictionary to store all models
        self.feature_mapping = None
        self.feature_columns = []

        print(f"🔍 [Intelligence] Carregando modelos AAUTIA...")
        
        # Load feature mapping (same for all models)
        try:
            if os.path.exists(MAPPING_PATH):
                with open(MAPPING_PATH, 'r') as f:
                    self.feature_mapping = json.load(f)
                self.feature_columns = self.feature_mapping.get('all_features', [])
                print(f"   ✓ Feature mapping: {len(self.feature_columns)} features")
            else:
                print(f"   [ERROR] Feature mapping não encontrado em {MAPPING_PATH}")
        except Exception as e:
            print(f"   [ERROR] Erro ao carregar feature mapping: {e}")
        
        # Load all available models from AAUTIA directory
        self._load_all_models()
    
    def _load_all_models(self):
        """Load all trained models from AAUTIA directory"""
        model_files = {
            'random_forest': os.path.join(AAUTIA_MODELS_DIR, 'rf_epss_model.pkl'),
            'lightgbm': os.path.join(AAUTIA_MODELS_DIR, 'lgb_epss_model.pkl'),
            'xgboost': os.path.join(AAUTIA_MODELS_DIR, 'xgb_epss_model.pkl'),
            'knn': os.path.join(AAUTIA_MODELS_DIR, 'knn_epss_model.pkl'),
            'lasso': os.path.join(AAUTIA_MODELS_DIR, 'lasso_epss_model.pkl'),
            'elasticnet': os.path.join(AAUTIA_MODELS_DIR, 'elasticnet_epss_model.pkl'),
            'linear_regression': os.path.join(AAUTIA_MODELS_DIR, 'linreg_epss_model.pkl'),
            'polynomial': os.path.join(AAUTIA_MODELS_DIR, 'poly_epss_model.pkl'),
            'sgd': os.path.join(AAUTIA_MODELS_DIR, 'sgd_epss_model.pkl'),
        }
        
        # Try to load each model
        for model_name, model_path in model_files.items():
            try:
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
                    print(f"   ✓ {model_name.replace('_', ' ').title()}")
            except Exception as e:
                print(f"   ✗ {model_name}: {str(e)[:50]}")
        
        if self.models:
            print(f"✅ [Intelligence] {len(self.models)} modelos carregados")
        else:
            print(f"❌ [Intelligence] Nenhum modelo carregado!")

    def fetch_nvd_data(self, cve_id):
        """Vai à API da NVD buscar os dados brutos."""
        print(f"🔍 [Intelligence] A consultar NVD para {cve_id}...")
        
        headers = {"Accept": "application/json"}
        # Se tiveres uma API Key no ambiente, usa-a (opcional)
        api_key = os.getenv("NVD_API_KEY")
        if api_key: headers["apiKey"] = api_key
        
        url = f"{NVD_API_URL}?cveId={cve_id}"
        
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                print(f"❌ Erro NVD HTTP {resp.status_code}")
                return None
                
            data = resp.json()
            
            if not data.get("vulnerabilities"):
                return None
            
            cve_item = data["vulnerabilities"][0]["cve"]
            return self._parse_nvd_json(cve_item)
        except Exception as e:
            print(f"❌ Erro de conexão NVD: {e}")
            return None

    def _parse_nvd_json(self, cve):
        """Extrai e normaliza os campos que o modelo precisa."""
        row = {
            "cve_id": cve.get("id"),
            "published_date": cve.get("published"),
            "description": cve["descriptions"][0]["value"] if cve.get("descriptions") else ""
        }
        
        # Extrair Métricas CVSS (Lógica de prioridade V3.1 > V3.0 > V2)
        metrics = cve.get("metrics", {})
        cvss_data = {}
        row["exploitability_score"] = 0.0
        row["impact_score"] = 0.0
        
        # Tentar V3.1
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss_data = m["cvssData"]
            row["exploitability_score"] = m.get("exploitabilityScore", 0)
            row["impact_score"] = m.get("impactScore", 0)
        # Tentar V3.0
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            cvss_data = m["cvssData"]
            row["exploitability_score"] = m.get("exploitabilityScore", 0)
            row["impact_score"] = m.get("impactScore", 0)
        # Fallback V2
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            cvss_data = m["cvssData"]
            row["exploitability_score"] = m.get("exploitabilityScore", 0)
            row["impact_score"] = m.get("impactScore", 0)
            
        # Mapeamento seguro de campos
        row["base_score"] = cvss_data.get("baseScore", 5.0)
        row["base_severity"] = cvss_data.get("baseSeverity", "MEDIUM")
        row["attack_vector"] = cvss_data.get("attackVector", "NETWORK")
        row["attack_complexity"] = cvss_data.get("attackComplexity", "LOW")
        row["privileges_required"] = cvss_data.get("privilegesRequired", "NONE")
        row["user_interaction"] = cvss_data.get("userInteraction", "NONE")
        row["scope"] = cvss_data.get("scope", "UNCHANGED")
        row["confidentiality_impact"] = cvss_data.get("confidentialityImpact", "NONE")
        row["integrity_impact"] = cvss_data.get("integrityImpact", "NONE")
        row["availability_impact"] = cvss_data.get("availabilityImpact", "NONE")
        
        # Extração de Software (Tentativa de adivinhar o produto)
        affected_software = set()
        if "configurations" in cve:
            for config in cve["configurations"]:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        if "cpe:2.3:" in criteria:
                            parts = criteria.split(":")
                            if len(parts) > 4:
                                # parts[3]=vendor, parts[4]=product
                                affected_software.add(f"{parts[4]}") 
        
        row["affected_software"] = ", ".join(list(affected_software))
        return row

    def predict_epss(self, cve_data):
        """
        Ensemble prediction using all available models.
        Returns dictionary with individual predictions and ensemble result.
        """
        if not self.models: 
            print("[ERROR] Nenhum modelo carregado, retornando valor default.")
            return {'ensemble': 0.5, 'predictions': {}, 'method': 'default'}

        # Preparar features (Dicionário -> DataFrame)
        features = {}
        
        # 1. Copiar numéricos
        features['base_score'] = float(cve_data.get('base_score', 0))
        features['exploitability_score'] = float(cve_data.get('exploitability_score', 0))
        features['impact_score'] = float(cve_data.get('impact_score', 0))
        
        # 2. Temporais
        if cve_data.get('published_date'):
            try:
                # Remove timezone se existir para evitar erros do pandas
                pub_date = pd.to_datetime(cve_data['published_date']).replace(tzinfo=None)
                now = pd.Timestamp.now()
                features['days_since_publication'] = (now - pub_date).days
                features['year_published'] = pub_date.year
                features['month_published'] = pub_date.month
                features['quarter_published'] = pub_date.quarter
            except:
                features['days_since_publication'] = 0
                features['year_published'] = datetime.now().year
                features['month_published'] = datetime.now().month
                features['quarter_published'] = 1
        else:
            features['days_since_publication'] = 0
            features['year_published'] = datetime.now().year
            features['month_published'] = datetime.now().month
            features['quarter_published'] = 1

        # 3. Categóricos (Encoding igual ao teu treino em AAUTIA)
        severity_mapping = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        sev_val = str(cve_data.get('base_severity', 'MEDIUM')).upper()
        features['base_severity_encoded'] = severity_mapping.get(sev_val, 2)
        features['cisa_kev'] = 0 
        
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
            value = str(cve_data.get(col, categories[0])).upper()
            for cat in categories:
                features[f"{col}_{cat}"] = 1 if value == cat else 0
        
        # 4. Texto
        soft_list = str(cve_data.get('affected_software', '')).split(',')
        features['num_affected_software'] = len([s for s in soft_list if s.strip()])
        features['num_affected_versions'] = 0

        # Criar DataFrame e ordenar colunas
        df = pd.DataFrame([features])
        
        # Garantir que todas as colunas que o modelo espera existem (preenche com 0)
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Reordenar exatamente como no treino
        df = df[self.feature_columns]
        
        # Previsão com todos os modelos
        predictions = {}
        try:
            for model_name, model in self.models.items():
                try:
                    pred = model.predict(df)[0]
                    # Clip predictions to [0, 1] range (EPSS scores are probabilities)
                    pred = max(0.0, min(1.0, pred))
                    predictions[model_name] = float(pred)
                except Exception as e:
                    print(f"   [ERROR] Erro em {model_name}: {str(e)[:50]}")
            
            if not predictions:
                return {'ensemble': 0.5, 'predictions': {}, 'method': 'default'}
            
            # Ensemble: Média ponderada (dar mais peso aos melhores modelos)
            # Baseado nos resultados do AAUTIA: LightGBM > RF > XGBoost
            weights = {
                'lightgbm': 0.25,
                'random_forest': 0.22,
                'xgboost': 0.20,
                'polynomial': 0.10,
                'elasticnet': 0.08,
                'lasso': 0.05,
                'linear_regression': 0.05,
                'knn': 0.03,
                'sgd': 0.02
            }
            
            # Calcular média ponderada
            weighted_sum = 0
            total_weight = 0
            for model_name, pred_value in predictions.items():
                weight = weights.get(model_name, 0.10)  # Default weight se não especificado
                weighted_sum += pred_value * weight
                total_weight += weight
            
            ensemble_prediction = weighted_sum / total_weight if total_weight > 0 else sum(predictions.values()) / len(predictions)
            
            return {
                'ensemble': float(ensemble_prediction),
                'predictions': predictions,
                'method': 'weighted_average',
                'models_used': len(predictions)
            }
            
        except Exception as e:
            print(f"❌ Erro na previsão ML: {e}")
            return {'ensemble': 0.5, 'predictions': {}, 'method': 'error'}

    def analyze_zero_day(self, cve_id: str) -> dict:
        """
        Complete zero-day analysis workflow:
        1. Check if CVE exists in AAUTIA dataset
        2. If not, fetch from NVD
        3. Predict EPSS using ML model
        4. Add to AAUTIA dataset (main source of truth)
        5. Sync to PLNTDIA dataset for scheduling
        
        Returns dictionary with analysis results
        """
        print(f"\n🚨 [Zero-Day Analysis] Iniciando análise de {cve_id}...")
        
        # Step 1: Check if CVE already exists
        if cve_dataset.cve_exists(cve_id):
            print(f"   📋 CVE encontrado no dataset AAUTIA")
            existing_cve = cve_dataset.get_cve(cve_id)
            return {
                'success': True,
                'status': 'exists',
                'cve_id': cve_id,
                'epss_score': float(existing_cve.get('epss_score', 0)),
                'epss_perc': float(existing_cve.get('epss_perc', 0)),
                'severity': existing_cve.get('base_severity', 'MEDIUM'),
                'description': existing_cve.get('description', '')[:150],
                'source': 'aautia-dataset',
                'message': f'EPSS Score: {float(existing_cve.get("epss_score", 0)):.4f}'
            }
        
        # Step 2: Fetch from NVD
        print(f"   🔍 CVE não encontrado. Consultando NVD...")
        cve_data = self.fetch_nvd_data(cve_id)
        
        if not cve_data:
            print(f"   [FAILED] CVE não encontrado na NVD")
            return {
                'success': False,
                'error': f'CVE {cve_id} não encontrado na NVD ou erro de conexão'
            }
        
        # Step 3: Predict EPSS
        print(f"   🤖 Executando modelos ML (AAUTIA Ensemble) para previsão EPSS...")
        prediction_result = self.predict_epss(cve_data)
        predicted_epss = prediction_result['ensemble']
        
        print(f"   ✅ EPSS Ensemble: {predicted_epss:.4f}")
        if prediction_result.get('models_used'):
            print(f"   📊 Modelos usados: {prediction_result['models_used']}")
            # Show individual predictions
            for model_name, pred in prediction_result.get('predictions', {}).items():
                print(f"      • {model_name.replace('_', ' ').title()}: {pred:.4f}")
        
        # Step 4: Add to AAUTIA dataset (main source of truth)
        print(f"   💾 Adicionando CVE ao dataset AAUTIA...")
        success = cve_dataset.add_cve(cve_data, predicted_epss)
        
        if not success:
            return {
                'success': False,
                'error': f'Erro ao adicionar {cve_id} ao dataset AAUTIA'
            }
        
        # Step 5: Sync to PLNTDIA dataset for scheduling
        print(f"   🔄 Sincronizando com dataset PLNTDIA...")
        cve_dataset.sync_to_plntdia_dataset(cve_id)
        
        return {
            'success': True,
            'status': 'new',
            'cve_id': cve_id,
            'epss_score': float(predicted_epss),
            'epss_perc': round(predicted_epss * 100, 2),
            'severity': cve_data.get('base_severity', 'MEDIUM'),
            'description': cve_data.get('description', '')[:150],
            'source': 'ml-prediction',
            'ensemble_method': prediction_result.get('method', 'unknown'),
            'models_used': prediction_result.get('models_used', 0),
            'individual_predictions': prediction_result.get('predictions', {}),
            'message': f'✅ Zero-Day criado com EPSS ensemble: {predicted_epss:.4f} ({prediction_result.get("models_used", 0)} modelos)'
        }

# Singleton para usar na app
intelligence_engine = CVEIntelligence()