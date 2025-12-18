"""
Testes para o módulo de base de dados SQLite.
"""

import os
import sys
import pytest
import tempfile
import shutil

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.database import (
    Database, 
    CVERecord, 
    GAExecutionReport,
    init_database
)


class TestDatabase:
    """Testes para a classe Database."""
    
    @pytest.fixture
    def temp_db(self):
        """Cria uma base de dados temporária para testes."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, 'test.db')
        db = Database(db_path)
        yield db
        # Não há método close, então só limpar o diretório
        shutil.rmtree(temp_dir)
    
    def test_create_tables(self, temp_db):
        """Verifica que as tabelas são criadas."""
        # Verificar que a base de dados existe
        assert os.path.exists(temp_db.db_path)
        
        # Verificar que as tabelas existem
        conn = temp_db._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        assert 'cves' in tables
        assert 'ga_reports' in tables
        conn.close()
    
    def test_get_all_cves_empty(self, temp_db):
        """Testa que a base de dados vazia retorna lista vazia."""
        cves, total = temp_db.get_all_cves(page=1, per_page=10)
        
        assert isinstance(cves, list)
        assert len(cves) == 0
        assert total == 0
    
    def test_get_cve_by_id_not_found(self, temp_db):
        """Testa que CVE não existente retorna None."""
        result = temp_db.get_cve_by_id('CVE-NONEXISTENT')
        assert result is None
    
    def test_get_cve_stats_empty(self, temp_db):
        """Testa estatísticas com base de dados vazia."""
        stats = temp_db.get_cve_stats()
        
        assert 'total' in stats
        assert stats['total'] == 0


class TestGAExecutionReport:
    """Testes para relatórios de execução do GA."""
    
    @pytest.fixture
    def temp_db(self):
        """Cria uma base de dados temporária para testes."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, 'test.db')
        db = Database(db_path)
        yield db
        shutil.rmtree(temp_dir)
    
    def test_save_ga_report(self, temp_db):
        """Testa guardar relatório GA."""
        report = GAExecutionReport(
            execution_date='2024-01-15T10:30:00',
            start_date='2024-01-16',
            planning_days=14,
            population_size=50,
            generations=100,
            total_tasks=100,
            scheduled_tasks=85,
            success_rate=85.0,
            best_fitness=150.5,
            fitness_history='[100, 120, 140, 150]'
        )
        
        report_id = temp_db.save_ga_report(report)
        
        assert report_id is not None
        assert report_id > 0
    
    def test_get_ga_report(self, temp_db):
        """Testa obter relatório GA por ID."""
        report = GAExecutionReport(
            execution_date='2024-01-15T10:30:00',
            start_date='2024-01-16',
            planning_days=14,
            total_tasks=100,
            scheduled_tasks=85,
            success_rate=85.0,
            best_fitness=150.5
        )
        
        report_id = temp_db.save_ga_report(report)
        saved_report = temp_db.get_ga_report(report_id)
        
        assert saved_report is not None
        assert saved_report['best_fitness'] == 150.5
    
    def test_get_recent_ga_reports(self, temp_db):
        """Testa obter relatórios GA recentes."""
        # Guardar alguns relatórios
        for i in range(5):
            report = GAExecutionReport(
                execution_date=f'2024-01-{15+i}T10:30:00',
                start_date='2024-01-20',
                total_tasks=100 + i*10,
                scheduled_tasks=80 + i*5,
                success_rate=80.0 + i*2,
                best_fitness=100.0 + i*10
            )
            temp_db.save_ga_report(report)
        
        reports = temp_db.get_recent_ga_reports(limit=3)
        
        assert len(reports) == 3


class TestModuleFunctions:
    """Testes para funções do módulo."""
    
    @pytest.fixture
    def temp_db_path(self):
        """Cria um caminho temporário para a base de dados."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, 'test.db')
        yield db_path
        shutil.rmtree(temp_dir)
    
    def test_init_database(self, temp_db_path):
        """Testa inicialização da base de dados."""
        db = init_database(temp_db_path)
        
        assert os.path.exists(temp_db_path)
        assert db is not None
        assert db.db_path == temp_db_path


class TestCVERecord:
    """Testes para o dataclass CVERecord."""
    
    def test_create_minimal(self):
        """Testa criação com parâmetros mínimos."""
        cve = CVERecord(cve_id='CVE-2024-0001')
        
        assert cve.cve_id == 'CVE-2024-0001'
        assert cve.base_score is None
        assert cve.base_severity is None
    
    def test_create_full(self):
        """Testa criação com todos os parâmetros."""
        cve = CVERecord(
            cve_id='CVE-2024-0001',
            published_date='2024-01-15',
            base_score=9.8,
            base_severity='CRITICAL',
            attack_vector='NETWORK',
            attack_complexity='LOW',
            privileges_required='NONE',
            cisa_kev=True,
            epss_score=0.95
        )
        
        assert cve.cve_id == 'CVE-2024-0001'
        assert cve.base_score == 9.8
        assert cve.cisa_kev is True
        assert cve.epss_score == 0.95
    
    def test_to_dict(self):
        """Testa conversão para dicionário."""
        cve = CVERecord(
            cve_id='CVE-2024-0001',
            base_score=7.5
        )
        
        d = cve.to_dict()
        
        assert isinstance(d, dict)
        assert d['cve_id'] == 'CVE-2024-0001'
        assert d['base_score'] == 7.5


class TestGAExecutionReportDataclass:
    """Testes para o dataclass GAExecutionReport."""
    
    def test_create_minimal(self):
        """Testa criação com parâmetros mínimos."""
        report = GAExecutionReport()
        
        assert report.id is None
        assert report.execution_date == ""
        assert report.total_tasks == 0
    
    def test_create_full(self):
        """Testa criação com parâmetros completos."""
        report = GAExecutionReport(
            id=1,
            execution_date='2024-01-15T10:30:00',
            start_date='2024-01-16',
            planning_days=14,
            population_size=50,
            generations=100,
            total_tasks=100,
            scheduled_tasks=85,
            success_rate=85.0,
            best_fitness=150.5,
            fitness_history='[100, 120, 140, 150]'
        )
        
        assert report.id == 1
        assert report.total_tasks == 100
        assert report.success_rate == 85.0
    
    def test_to_dict(self):
        """Testa conversão para dicionário."""
        report = GAExecutionReport(
            execution_date='2024-01-15T10:30:00',
            total_tasks=50
        )
        
        d = report.to_dict()
        
        assert isinstance(d, dict)
        assert d['execution_date'] == '2024-01-15T10:30:00'
        assert d['total_tasks'] == 50
