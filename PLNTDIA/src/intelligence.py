import json
import os
import joblib
import pandas as pd
import requests
from datetime import datetime

# --- CONFIGURAÇÃO ---
# Caminhos relativos à raiz do projeto (onde corre o app.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml_models", "rf_epss_model.pkl")
MAPPING_PATH = os.path.join(BASE_DIR, "ml_models", "feature_mapping.json")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEIntelligence:
    def __init__(self):
        self.model = None
        self.feature_mapping = None
        self.feature_columns = []

        # --- ADICIONA ESTAS LINHAS PARA DEBUG ---
        print(f"DEBUG: Estou à procura do modelo em: {MODEL_PATH}")
        print(f"DEBUG: O ficheiro existe? {os.path.exists(MODEL_PATH)}")
        # ----------------------------------------
        
        # Carregar Modelo ML e Mappings ao iniciar
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(MAPPING_PATH):
                self.model = joblib.load(MODEL_PATH)
                with open(MAPPING_PATH, 'r') as f:
                    self.feature_mapping = json.load(f)
                self.feature_columns = self.feature_mapping.get('all_features', [])
                print(f"✅ [Intelligence] Modelo carregado: {MODEL_PATH}")
            else:
                print(f"❌ [Intelligence] Ficheiros de modelo não encontrados em {MODEL_PATH}")
        except Exception as e:
            print(f"⚠️ [Intelligence] Erro ao carregar modelo: {e}")

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
        """Usa o modelo carregado para prever o EPSS."""
        if not self.model: 
            print("⚠️ Modelo não carregado, retornando valor default.")
            return 0.5 

        # Preparar features (Dicionário -> DataFrame)
        features = {}
        
        # 1. Copiar numéricos
        features['base_score'] = float(cve_data.get('base_score', 0))
        features['exploitability_score'] = float(cve_data.get('exploitability_score', 0))
        features['impact_score'] = float(cve_data.get('impact_score', 0))
        features['epss_perc'] = 0 # Dummy (o modelo espera esta coluna, mesmo que vazia na previsão)
        
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
        
        # Previsão
        try:
            prediction = self.model.predict(df)[0]
            return float(prediction)
        except Exception as e:
            print(f"❌ Erro na previsão ML: {e}")
            return 0.5

# Singleton para usar na app
intelligence_engine = CVEIntelligence()