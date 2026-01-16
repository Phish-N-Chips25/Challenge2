# src/cve_dataset.py
"""
Dataset Management for CVE Integration
Handles checking, adding, and updating CVEs in the enriched AAUTIA dataset
"""

import os
import pandas as pd
from datetime import datetime
from pathlib import Path

# Use the enriched AAUTIA dataset (main source of truth for ML)
DATASET_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),  # Go up to Challenge2
    "AAUTIA",
    "cve_cisa_epss_enriched_dataset_with_nvd.csv"
)

# Backup reference (original PLNTDIA dataset for comparison)
PLNTDIA_DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cves.csv")

class CVEDataset:
    def __init__(self):
        self.df = None
        self.load_dataset()
    
    def load_dataset(self):
        """Load CVE dataset from CSV"""
        try:
            if os.path.exists(DATASET_PATH):
                self.df = pd.read_csv(DATASET_PATH)
                print(f"✅ [CVEDataset] Carregado: {len(self.df)} CVEs")
            else:
                print(f"⚠️ [CVEDataset] Dataset não encontrado em {DATASET_PATH}")
                self.df = pd.DataFrame()
        except Exception as e:
            print(f"❌ [CVEDataset] Erro ao carregar dataset: {e}")
            self.df = pd.DataFrame()
    
    def cve_exists(self, cve_id: str) -> bool:
        """Check if CVE already exists in dataset"""
        if self.df is None or len(self.df) == 0:
            return False
        
        return cve_id in self.df['cve_id'].values if 'cve_id' in self.df.columns else False
    
    def get_cve(self, cve_id: str) -> dict:
        """Retrieve CVE data from dataset"""
        if not self.cve_exists(cve_id):
            return None
        
        row = self.df[self.df['cve_id'] == cve_id].iloc[0]
        return row.to_dict()
    
    def add_cve(self, cve_data: dict, predicted_epss: float) -> bool:
        """
        Add new CVE to AAUTIA enriched dataset with predicted EPSS score
        
        Args:
            cve_data: Dictionary with CVE information from NVD
            predicted_epss: Predicted EPSS score from ML model (0.0-1.0)
        
        Returns:
            True if added successfully, False otherwise
        """
        try:
            # Create new row with all AAUTIA dataset columns
            # Match the structure of cve_cisa_epss_enriched_dataset_with_nvd.csv
            new_row = {
                'cve_id': cve_data.get('cve_id', ''),
                'published_date': cve_data.get('published_date', ''),
                'base_score': float(cve_data.get('base_score', 0)),
                'exploitability_score': float(cve_data.get('exploitability_score', 0)),
                'impact_score': float(cve_data.get('impact_score', 0)),
                'epss_score': float(predicted_epss),  # ML-predicted score (0.0-1.0)
                'epss_perc': round(predicted_epss * 100, 2),  # Convert to percentage
                'base_severity': cve_data.get('base_severity', 'MEDIUM'),
                'cisa_kev': bool(cve_data.get('cisa_kev', False)),
                'attack_vector': cve_data.get('attack_vector', 'NETWORK'),
                'attack_complexity': cve_data.get('attack_complexity', 'LOW'),
                'privileges_required': cve_data.get('privileges_required', 'NONE'),
                'user_interaction': cve_data.get('user_interaction', 'NONE'),
                'scope': cve_data.get('scope', 'UNCHANGED'),
                'confidentiality_impact': cve_data.get('confidentiality_impact', 'NONE'),
                'integrity_impact': cve_data.get('integrity_impact', 'NONE'),
                'availability_impact': cve_data.get('availability_impact', 'NONE'),
                'affected_software': cve_data.get('affected_software', ''),
                'affected_versions': cve_data.get('affected_versions', ''),
                'description': cve_data.get('description', ''),
                'source': 'zero-day-injection'  # Mark as user-injected zero-day
            }
            
            # Append to dataframe
            self.df = pd.concat([self.df, pd.DataFrame([new_row])], ignore_index=True)
            
            # Save to AAUTIA dataset (main source of truth)
            self.df.to_csv(DATASET_PATH, index=False)
            print(f"✅ [CVEDataset] CVE {cve_data.get('cve_id')} adicionado ao dataset AAUTIA")
            print(f"   EPSS Predito (ML): {predicted_epss:.4f}")
            print(f"   Ficheiro: {DATASET_PATH}")
            
            return True
            
        except Exception as e:
            print(f"❌ [CVEDataset] Erro ao adicionar CVE: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_all_cve_ids(self) -> list:
        """Get list of all CVE IDs in dataset"""
        if self.df is None or len(self.df) == 0:
            return []
        
        return self.df['cve_id'].tolist() if 'cve_id' in self.df.columns else []
    
    def sync_to_plntdia_dataset(self, cve_id: str) -> bool:
        """
        Sync newly added CVE to PLNTDIA's local cves.csv for scheduling
        
        Args:
            cve_id: CVE ID to sync
        
        Returns:
            True if synced successfully
        """
        try:
            if not self.cve_exists(cve_id):
                print(f"⚠️ CVE {cve_id} não encontrado no dataset AAUTIA")
                return False
            
            # Load PLNTDIA dataset
            if not os.path.exists(PLNTDIA_DATASET_PATH):
                print(f"⚠️ Dataset PLNTDIA não encontrado em {PLNTDIA_DATASET_PATH}")
                return False
            
            plntdia_df = pd.read_csv(PLNTDIA_DATASET_PATH)
            
            # Check if CVE already in PLNTDIA dataset
            if cve_id in plntdia_df['cve_id'].values:
                print(f"ℹ️ CVE {cve_id} já existe em PLNTDIA dataset")
                return True
            
            # Get CVE from AAUTIA dataset
            cve_row = self.get_cve(cve_id)
            if not cve_row:
                return False
            
            # Add to PLNTDIA dataset
            plntdia_df = pd.concat([plntdia_df, pd.DataFrame([cve_row])], ignore_index=True)
            plntdia_df.to_csv(PLNTDIA_DATASET_PATH, index=False)
            
            print(f"✅ CVE {cve_id} sincronizado para PLNTDIA dataset")
            return True
            
        except Exception as e:
            print(f"❌ Erro ao sincronizar para PLNTDIA: {e}")
            return False


# Singleton instance
cve_dataset = CVEDataset()
