"""
Módulo de Base de Dados SQLite para CVEs e Sistema de Planeamento

Fornece armazenamento persistente para:
- CVEs completos do dataset
- Histórico de patches aplicados
- Relatórios de execução do algoritmo genético
"""

import sqlite3
import os
import json
import logging
from datetime import datetime, date
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import csv
import sys

# Aumentar limite de campo CSV para ficheiros grandes
csv.field_size_limit(sys.maxsize)

logger = logging.getLogger(__name__)

# Caminho default para a base de dados
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'plntdia.db')


@dataclass
class CVERecord:
    """Registo completo de um CVE na base de dados."""
    cve_id: str
    published_date: Optional[str] = None
    updated_date: Optional[str] = None
    cvss_version: Optional[str] = None
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    cisa_kev: bool = False
    cisa_kev_date: Optional[str] = None
    ssvc_exploitation: Optional[str] = None
    ssvc_automatable: Optional[str] = None
    ssvc_technical_impact: Optional[str] = None
    ssvc_decision: Optional[str] = None
    impacted_vendor: Optional[str] = None
    impacted_products: Optional[str] = None
    vulnerable_versions: Optional[str] = None
    cwe_number: Optional[str] = None
    cwe_description: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    
    def to_dict(self) -> Dict:
        """Converte para dicionário."""
        return asdict(self)


@dataclass  
class GAExecutionReport:
    """Relatório de execução do algoritmo genético."""
    id: Optional[int] = None
    execution_date: str = ""
    start_date: str = ""
    planning_days: int = 14
    population_size: int = 50
    generations: int = 100
    total_tasks: int = 0
    scheduled_tasks: int = 0
    success_rate: float = 0.0
    best_fitness: float = 0.0
    fitness_history: str = ""  # JSON array
    avg_fitness_history: str = ""  # JSON array
    tasks_by_severity: str = ""  # JSON object
    tasks_by_environment: str = ""  # JSON object
    tasks_by_worker: str = ""  # JSON object
    execution_time_ms: int = 0
    config_json: str = ""
    schedule_json: str = ""
    
    def to_dict(self) -> Dict:
        """Converte para dicionário com parsing de JSON."""
        result = asdict(self)
        # Parse JSON fields
        for field in ['fitness_history', 'avg_fitness_history', 'tasks_by_severity', 
                      'tasks_by_environment', 'tasks_by_worker', 'config_json', 'schedule_json']:
            if result[field]:
                try:
                    result[field] = json.loads(result[field])
                except:
                    pass
        return result


class Database:
    """Gestor de base de dados SQLite."""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        # Garantir que o diretório existe
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Obtém conexão com a base de dados."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """Inicializa as tabelas da base de dados."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Tabela de CVEs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                published_date TEXT,
                updated_date TEXT,
                cvss_version TEXT,
                base_score REAL,
                base_severity TEXT,
                attack_vector TEXT,
                attack_complexity TEXT,
                privileges_required TEXT,
                user_interaction TEXT,
                scope TEXT,
                confidentiality_impact TEXT,
                integrity_impact TEXT,
                availability_impact TEXT,
                cisa_kev INTEGER DEFAULT 0,
                cisa_kev_date TEXT,
                ssvc_exploitation TEXT,
                ssvc_automatable TEXT,
                ssvc_technical_impact TEXT,
                ssvc_decision TEXT,
                impacted_vendor TEXT,
                impacted_products TEXT,
                vulnerable_versions TEXT,
                cwe_number TEXT,
                cwe_description TEXT,
                epss_score REAL,
                epss_percentile REAL,
                exploitability_score REAL,
                impact_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Índices para pesquisa rápida
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(base_severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_score ON cves(base_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cves_vendor ON cves(impacted_vendor)')
        
        # Tabela de relatórios de execução do GA
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ga_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                execution_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                start_date TEXT,
                planning_days INTEGER,
                population_size INTEGER,
                generations INTEGER,
                total_tasks INTEGER,
                scheduled_tasks INTEGER,
                success_rate REAL,
                best_fitness REAL,
                fitness_history TEXT,
                avg_fitness_history TEXT,
                tasks_by_severity TEXT,
                tasks_by_environment TEXT,
                tasks_by_worker TEXT,
                execution_time_ms INTEGER,
                config_json TEXT,
                schedule_json TEXT
            )
        ''')
        
        # Tabela de patches aplicados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS applied_patches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                software_id TEXT,
                applied_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                applied_by TEXT,
                duration_hours REAL,
                notes TEXT,
                ga_report_id INTEGER,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id),
                FOREIGN KEY (ga_report_id) REFERENCES ga_reports(id)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_cve ON applied_patches(cve_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_patches_server ON applied_patches(server_id)')
        
        conn.commit()
        conn.close()
        logger.info(f"Base de dados inicializada: {self.db_path}")
    
    # ==================== OPERAÇÕES DE CVEs ====================
    
    def import_cves_from_csv(self, csv_path: str, clear_existing: bool = False) -> int:
        """
        Importa CVEs de um ficheiro CSV.
        
        Args:
            csv_path: Caminho para o ficheiro CSV
            clear_existing: Se True, apaga CVEs existentes antes de importar
            
        Returns:
            Número de CVEs importados
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if clear_existing:
            cursor.execute('DELETE FROM cves')
            logger.info("CVEs existentes removidos")
        
        count = 0
        
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    # Mapear campos do CSV para a tabela
                    cve_data = {
                        'cve_id': row.get('cve_id', '').strip(),
                        'published_date': row.get('published_date_file1') or row.get('published_date_file2'),
                        'updated_date': row.get('updated_date'),
                        'cvss_version': row.get('cvss_version'),
                        'base_score': self._parse_float(row.get('base_score_file1') or row.get('base_score_file2')),
                        'base_severity': row.get('base_severity_file1') or row.get('base_severity_file2'),
                        'attack_vector': row.get('attack_vector_file1') or row.get('attack_vector_file2'),
                        'attack_complexity': row.get('attack_complexity_file1') or row.get('attack_complexity_file2'),
                        'privileges_required': row.get('privileges_required_file1') or row.get('privileges_required_file2'),
                        'user_interaction': row.get('user_interaction_file1') or row.get('user_interaction_file2'),
                        'scope': row.get('scope_file1') or row.get('scope_file2'),
                        'confidentiality_impact': row.get('confidentiality_impact_file1') or row.get('confidentiality_impact_file2'),
                        'integrity_impact': row.get('integrity_impact_file1') or row.get('integrity_impact_file2'),
                        'availability_impact': row.get('availability_impact_file1') or row.get('availability_impact_file2'),
                        'cisa_kev': row.get('cisa_kev_file1', '').lower() == 'true' or row.get('cisa_kev_file2', '').lower() == 'true',
                        'cisa_kev_date': row.get('cisa_kev_date'),
                        'ssvc_exploitation': row.get('ssvc_exploitation'),
                        'ssvc_automatable': row.get('ssvc_automatable'),
                        'ssvc_technical_impact': row.get('ssvc_technical_impact'),
                        'ssvc_decision': row.get('ssvc_decision'),
                        'impacted_vendor': row.get('impacted_vendor'),
                        'impacted_products': row.get('impacted_products'),
                        'vulnerable_versions': row.get('vulnerable_versions'),
                        'cwe_number': row.get('cwe_number'),
                        'cwe_description': row.get('cwe_description'),
                        'epss_score': self._parse_float(row.get('epss_score')),
                        'epss_percentile': self._parse_float(row.get('epss_perc')),
                        'exploitability_score': self._parse_float(row.get('exploitability_score')),
                        'impact_score': self._parse_float(row.get('impact_score'))
                    }
                    
                    if not cve_data['cve_id']:
                        continue
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO cves (
                            cve_id, published_date, updated_date, cvss_version, base_score,
                            base_severity, attack_vector, attack_complexity, privileges_required,
                            user_interaction, scope, confidentiality_impact, integrity_impact,
                            availability_impact, cisa_kev, cisa_kev_date, ssvc_exploitation,
                            ssvc_automatable, ssvc_technical_impact, ssvc_decision, impacted_vendor,
                            impacted_products, vulnerable_versions, cwe_number, cwe_description,
                            epss_score, epss_percentile, exploitability_score, impact_score,
                            updated_at
                        ) VALUES (
                            :cve_id, :published_date, :updated_date, :cvss_version, :base_score,
                            :base_severity, :attack_vector, :attack_complexity, :privileges_required,
                            :user_interaction, :scope, :confidentiality_impact, :integrity_impact,
                            :availability_impact, :cisa_kev, :cisa_kev_date, :ssvc_exploitation,
                            :ssvc_automatable, :ssvc_technical_impact, :ssvc_decision, :impacted_vendor,
                            :impacted_products, :vulnerable_versions, :cwe_number, :cwe_description,
                            :epss_score, :epss_percentile, :exploitability_score, :impact_score,
                            CURRENT_TIMESTAMP
                        )
                    ''', cve_data)
                    count += 1
                    
                except Exception as e:
                    logger.warning(f"Erro ao importar CVE {row.get('cve_id', 'unknown')}: {e}")
                    continue
        
        conn.commit()
        conn.close()
        logger.info(f"Importados {count} CVEs de {csv_path}")
        return count
    
    def _parse_float(self, value: Any) -> Optional[float]:
        """Parse seguro de float."""
        if value is None or value == '':
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None
    
    def get_all_cves(
        self,
        page: int = 1,
        per_page: int = 50,
        severity: str = None,
        min_score: float = None,
        max_score: float = None,
        vendor: str = None,
        search: str = None,
        sort_by: str = 'base_score',
        sort_order: str = 'DESC',
        cisa_kev_only: bool = False
    ) -> Tuple[List[Dict], int]:
        """
        Obtém CVEs com filtros e paginação.
        
        Returns:
            Tupla com lista de CVEs e total de registos
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Construir query base
        query = 'SELECT * FROM cves WHERE 1=1'
        count_query = 'SELECT COUNT(*) FROM cves WHERE 1=1'
        params = []
        
        # Aplicar filtros
        if severity:
            query += ' AND UPPER(base_severity) = ?'
            count_query += ' AND UPPER(base_severity) = ?'
            params.append(severity.upper())
        
        if min_score is not None:
            query += ' AND base_score >= ?'
            count_query += ' AND base_score >= ?'
            params.append(min_score)
        
        if max_score is not None:
            query += ' AND base_score <= ?'
            count_query += ' AND base_score <= ?'
            params.append(max_score)
        
        if vendor:
            query += ' AND LOWER(impacted_vendor) LIKE ?'
            count_query += ' AND LOWER(impacted_vendor) LIKE ?'
            params.append(f'%{vendor.lower()}%')
        
        if search:
            query += ' AND (cve_id LIKE ? OR impacted_products LIKE ? OR cwe_description LIKE ?)'
            count_query += ' AND (cve_id LIKE ? OR impacted_products LIKE ? OR cwe_description LIKE ?)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param])
        
        if cisa_kev_only:
            query += ' AND cisa_kev = 1'
            count_query += ' AND cisa_kev = 1'
        
        # Obter total
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ordenação
        valid_sort_fields = ['base_score', 'epss_score', 'published_date', 'cve_id', 'base_severity']
        if sort_by not in valid_sort_fields:
            sort_by = 'base_score'
        
        sort_order = 'DESC' if sort_order.upper() == 'DESC' else 'ASC'
        query += f' ORDER BY {sort_by} {sort_order} NULLS LAST'
        
        # Paginação
        offset = (page - 1) * per_page
        query += ' LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        cves = [dict(row) for row in rows]
        conn.close()
        
        return cves, total
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict]:
        """Obtém um CVE por ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def get_cve_stats(self) -> Dict:
        """Obtém estatísticas dos CVEs na base de dados."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Total
        cursor.execute('SELECT COUNT(*) FROM cves')
        stats['total'] = cursor.fetchone()[0]
        
        # Por severidade
        cursor.execute('''
            SELECT base_severity, COUNT(*) as count 
            FROM cves 
            WHERE base_severity IS NOT NULL 
            GROUP BY base_severity
        ''')
        stats['by_severity'] = {row['base_severity']: row['count'] for row in cursor.fetchall()}
        
        # CISA KEV
        cursor.execute('SELECT COUNT(*) FROM cves WHERE cisa_kev = 1')
        stats['cisa_kev_count'] = cursor.fetchone()[0]
        
        # Média CVSS
        cursor.execute('SELECT AVG(base_score) FROM cves WHERE base_score IS NOT NULL')
        avg = cursor.fetchone()[0]
        stats['avg_cvss_score'] = round(avg, 2) if avg else 0
        
        # Média EPSS
        cursor.execute('SELECT AVG(epss_score) FROM cves WHERE epss_score IS NOT NULL')
        avg = cursor.fetchone()[0]
        stats['avg_epss_score'] = round(avg, 4) if avg else 0
        
        # Top vendors
        cursor.execute('''
            SELECT impacted_vendor, COUNT(*) as count 
            FROM cves 
            WHERE impacted_vendor IS NOT NULL AND impacted_vendor != ''
            GROUP BY impacted_vendor 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        stats['top_vendors'] = [{'vendor': row['impacted_vendor'], 'count': row['count']} for row in cursor.fetchall()]
        
        # Distribuição SSVC Decision
        cursor.execute('''
            SELECT ssvc_decision, COUNT(*) as count 
            FROM cves 
            WHERE ssvc_decision IS NOT NULL 
            GROUP BY ssvc_decision
        ''')
        stats['by_ssvc_decision'] = {row['ssvc_decision']: row['count'] for row in cursor.fetchall()}
        
        conn.close()
        return stats
    
    # ==================== OPERAÇÕES DE RELATÓRIOS GA ====================
    
    def save_ga_report(self, report: GAExecutionReport) -> int:
        """
        Guarda um relatório de execução do GA.
        
        Returns:
            ID do relatório inserido
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ga_reports (
                execution_date, start_date, planning_days, population_size, generations,
                total_tasks, scheduled_tasks, success_rate, best_fitness,
                fitness_history, avg_fitness_history, tasks_by_severity,
                tasks_by_environment, tasks_by_worker, execution_time_ms,
                config_json, schedule_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            report.execution_date or datetime.now().isoformat(),
            report.start_date,
            report.planning_days,
            report.population_size,
            report.generations,
            report.total_tasks,
            report.scheduled_tasks,
            report.success_rate,
            report.best_fitness,
            report.fitness_history,
            report.avg_fitness_history,
            report.tasks_by_severity,
            report.tasks_by_environment,
            report.tasks_by_worker,
            report.execution_time_ms,
            report.config_json,
            report.schedule_json
        ))
        
        report_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Relatório GA guardado com ID {report_id}")
        return report_id
    
    def get_ga_report(self, report_id: int) -> Optional[Dict]:
        """Obtém um relatório GA por ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM ga_reports WHERE id = ?', (report_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        report = dict(row)
        # Parse JSON fields
        for field in ['fitness_history', 'avg_fitness_history', 'tasks_by_severity',
                      'tasks_by_environment', 'tasks_by_worker', 'config_json', 'schedule_json']:
            if report.get(field):
                try:
                    report[field] = json.loads(report[field])
                except:
                    pass
        
        return report
    
    def get_recent_ga_reports(self, limit: int = 10) -> List[Dict]:
        """Obtém os relatórios GA mais recentes."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, execution_date, start_date, planning_days, total_tasks,
                   scheduled_tasks, success_rate, best_fitness, execution_time_ms
            FROM ga_reports 
            ORDER BY execution_date DESC 
            LIMIT ?
        ''', (limit,))
        
        reports = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return reports
    
    # ==================== OPERAÇÕES DE PATCHES APLICADOS ====================
    
    def record_applied_patch(
        self,
        cve_id: str,
        server_id: str,
        software_id: str = None,
        applied_by: str = None,
        duration_hours: float = None,
        notes: str = None,
        ga_report_id: int = None
    ) -> int:
        """Regista um patch aplicado."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO applied_patches (
                cve_id, server_id, software_id, applied_by, duration_hours, notes, ga_report_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, server_id, software_id, applied_by, duration_hours, notes, ga_report_id))
        
        patch_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return patch_id
    
    def get_applied_patches(
        self,
        server_id: str = None,
        cve_id: str = None,
        from_date: str = None,
        to_date: str = None
    ) -> List[Dict]:
        """Obtém patches aplicados com filtros."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        query = 'SELECT * FROM applied_patches WHERE 1=1'
        params = []
        
        if server_id:
            query += ' AND server_id = ?'
            params.append(server_id)
        
        if cve_id:
            query += ' AND cve_id = ?'
            params.append(cve_id)
        
        if from_date:
            query += ' AND applied_date >= ?'
            params.append(from_date)
        
        if to_date:
            query += ' AND applied_date <= ?'
            params.append(to_date)
        
        query += ' ORDER BY applied_date DESC'
        
        cursor.execute(query, params)
        patches = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return patches
    
    def is_patch_applied(self, cve_id: str, server_id: str) -> bool:
        """Verifica se um patch já foi aplicado."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM applied_patches 
            WHERE cve_id = ? AND server_id = ?
        ''', (cve_id, server_id))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0


# Instância global (singleton)
_db_instance: Optional[Database] = None


def get_database() -> Database:
    """Obtém instância singleton da base de dados."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance


def init_database(db_path: str = None) -> Database:
    """Inicializa a base de dados com caminho customizado."""
    global _db_instance
    _db_instance = Database(db_path)
    return _db_instance
