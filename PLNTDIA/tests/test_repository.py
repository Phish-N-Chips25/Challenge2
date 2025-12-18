"""
Testes unitários para o módulo repository.py
"""

import pytest
import tempfile
import os
from src.repository import (
    get_mock_data,
    generate_stress_test_data,
    save_scenario_to_json,
    load_scenario_from_json,
    load_data_from_csv,
    load_servers_from_csv,
    load_workers_from_csv,
    generate_cves_for_infrastructure
)
from src.domain import Server, CVE, Worker


class TestLoadDataFromCSV:
    """Testes para carregamento de dados CSV."""
    
    def test_load_servers_returns_correct_count(self):
        """Testa que carrega 60 servidores do CSV (20 DEV, 20 TEST, 20 PROD)."""
        servers = load_servers_from_csv()
        assert len(servers) == 60
    
    def test_load_servers_have_correct_types(self):
        """Testa que servidores têm tipos corretos (DEV, TEST, PROD)."""
        servers = load_servers_from_csv()
        
        prod = [s for s in servers if "PROD" in s.id]
        test = [s for s in servers if "TEST" in s.id]
        dev = [s for s in servers if "DEV" in s.id]
        
        assert len(prod) == 20
        assert len(test) == 20
        assert len(dev) == 20
    
    def test_servers_have_downtime_windows(self):
        """Testa que servidores têm janelas de manutenção."""
        servers = load_servers_from_csv()
        
        for srv in servers:
            assert len(srv.downtime_windows) > 0
    
    def test_servers_have_software(self):
        """Testa que servidores têm software instalado."""
        servers = load_servers_from_csv()
        
        # A maioria dos servidores deve ter software
        servers_with_software = [s for s in servers if len(s.installed_software) > 0]
        assert len(servers_with_software) >= 50
    
    def test_load_workers_returns_correct_count(self):
        """Testa que carrega 10 técnicos do CSV."""
        servers = load_servers_from_csv()
        workers = load_workers_from_csv(servers=servers)
        assert len(workers) == 10
    
    def test_workers_have_levels(self):
        """Testa que trabalhadores têm níveis definidos."""
        servers = load_servers_from_csv()
        workers = load_workers_from_csv(servers=servers)
        
        levels = set(w.level for w in workers)
        assert "Senior" in levels
        assert "Mid" in levels
        assert "Junior" in levels
    
    def test_workers_have_skills(self):
        """Testa que trabalhadores têm skills."""
        servers = load_servers_from_csv()
        workers = load_workers_from_csv(servers=servers)
        
        for w in workers:
            assert len(w.skills) > 0
    
    def test_workers_have_shifts(self):
        """Testa que trabalhadores têm turnos."""
        servers = load_servers_from_csv()
        workers = load_workers_from_csv(servers=servers)
        
        for w in workers:
            assert len(w.weekly_shifts) > 0
    
    def test_seniors_authorized_for_prod(self):
        """Testa que seniors têm autorização para produção."""
        servers = load_servers_from_csv()
        workers = load_workers_from_csv(servers=servers)
        
        seniors = [w for w in workers if w.level == "Senior"]
        prod_servers = [s.id for s in servers if "PROD" in s.id]
        
        for senior in seniors:
            # Seniors devem ter autorização para pelo menos um servidor PROD
            auth_prod = [a for a in senior.authorized_server_ids if a in prod_servers]
            assert len(auth_prod) > 0
    
    def test_juniors_not_authorized_for_prod(self):
        """Testa que juniors NÃO têm autorização para produção."""
        servers = load_servers_from_csv()
        workers = load_workers_from_csv(servers=servers)
        
        juniors = [w for w in workers if w.level == "Junior"]
        prod_servers = [s.id for s in servers if "PROD" in s.id]
        
        for junior in juniors:
            auth_prod = [a for a in junior.authorized_server_ids if a in prod_servers]
            assert len(auth_prod) == 0
    
    def test_load_data_from_csv_returns_all(self):
        """Testa que load_data_from_csv retorna servidores e workers."""
        servers, workers = load_data_from_csv()
        
        assert len(servers) == 60
        assert len(workers) == 10


class TestGenerateCVEsForInfrastructure:
    """Testes para geração de CVEs."""
    
    def test_generates_correct_count(self):
        """Testa que gera o número correto de CVEs."""
        servers = load_servers_from_csv()
        cves = generate_cves_for_infrastructure(servers, n_cves=30, seed=42)
        assert len(cves) == 30
    
    def test_cves_target_installed_software(self):
        """Testa que CVEs afetam software que existe na infraestrutura."""
        servers = load_servers_from_csv()
        cves = generate_cves_for_infrastructure(servers, n_cves=50, seed=42)
        
        # Recolher todos os software IDs instalados
        installed_software = set()
        for srv in servers:
            for sw in srv.installed_software:
                installed_software.add(sw.id)
        
        # Todas as CVEs devem afetar software instalado
        for cve in cves:
            assert cve.affected_software_id in installed_software
    
    def test_reproducibility_with_seed(self):
        """Testa que seed garante reprodutibilidade."""
        servers = load_servers_from_csv()
        cves1 = generate_cves_for_infrastructure(servers, n_cves=10, seed=42)
        cves2 = generate_cves_for_infrastructure(servers, n_cves=10, seed=42)
        
        assert [c.id for c in cves1] == [c.id for c in cves2]
        assert [c.epss_score for c in cves1] == [c.epss_score for c in cves2]


class TestGetMockData:
    """Testes para get_mock_data (agora usa CSV)."""
    
    def test_returns_correct_types(self):
        """Testa que retorna os tipos corretos."""
        servers, cves, workers = get_mock_data()
        
        assert isinstance(servers, list)
        assert isinstance(cves, list)
        assert isinstance(workers, list)
        
        assert all(isinstance(s, Server) for s in servers)
        assert all(isinstance(c, CVE) for c in cves)
        assert all(isinstance(w, Worker) for w in workers)
    
    def test_returns_csv_data(self):
        """Testa que retorna dados do CSV."""
        servers, cves, workers = get_mock_data()
        
        assert len(servers) == 60
        assert len(cves) > 0
        assert len(workers) == 10


class TestGenerateStressTestData:
    """Testes para generate_stress_test_data (agora usa CSV)."""
    
    def test_loads_csv_data(self):
        """Testa que carrega dados do CSV."""
        servers, cves, workers = generate_stress_test_data(n_cves=20, seed=42)
        
        # Servidores e workers vêm do CSV
        assert len(servers) == 60
        assert len(workers) == 10
        # CVEs são gerados
        assert len(cves) == 20
    
    def test_reproducibility_with_seed(self):
        """Testa que seed garante reprodutibilidade."""
        result1 = generate_stress_test_data(n_cves=10, seed=42)
        result2 = generate_stress_test_data(n_cves=10, seed=42)
        
        # Mesmo seed deve produzir mesmos CVEs
        assert [c.id for c in result1[1]] == [c.id for c in result2[1]]
        assert [c.epss_score for c in result1[1]] == [c.epss_score for c in result2[1]]
    
    def test_different_seeds_produce_different_results(self):
        """Testa que seeds diferentes produzem CVEs diferentes."""
        result1 = generate_stress_test_data(n_cves=10, seed=42)
        result2 = generate_stress_test_data(n_cves=10, seed=123)
        
        epss1 = [c.epss_score for c in result1[1]]
        epss2 = [c.epss_score for c in result2[1]]
        assert epss1 != epss2
    
    def test_cve_severity_distribution(self):
        """Testa que CVEs têm severidades variadas."""
        _, cves, _ = generate_stress_test_data(n_cves=100, seed=42)
        
        severities = set(c.severity for c in cves)
        assert len(severities) >= 2  # Pelo menos 2 severidades diferentes
    
    def test_none_seed_is_random(self):
        """Testa que seed=None produz resultados aleatórios."""
        result1 = generate_stress_test_data(n_servers=5, n_cves=10, n_workers=2, seed=None)
        result2 = generate_stress_test_data(n_servers=5, n_cves=10, n_workers=2, seed=None)
        
        # Alta probabilidade de serem diferentes (não é garantido, mas quase certo)
        epss1 = [c.epss_score for c in result1[1]]
        epss2 = [c.epss_score for c in result2[1]]
        # Pelo menos um valor deve ser diferente (com probabilidade ~100%)
        # Nota: Este teste pode falhar muito raramente por coincidência
        assert epss1 != epss2 or len(epss1) == 0


class TestSaveLoadScenario:
    """Testes para save_scenario_to_json e load_scenario_from_json."""
    
    def test_save_and_load_roundtrip(self):
        """Testa que salvar e carregar preserva os dados."""
        # Gerar dados
        servers, cves, workers = generate_stress_test_data(n_cves=5, seed=42)
        
        # Usar apenas alguns para teste mais rápido
        servers = servers[:3]
        workers = workers[:2]
        
        # Salvar em ficheiro temporário
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filename = f.name
        
        try:
            save_scenario_to_json(servers, cves, workers, filename)
            
            # Carregar de volta
            loaded_servers, loaded_cves, loaded_workers = load_scenario_from_json(filename)
            
            # Verificar contagens
            assert len(loaded_servers) == len(servers)
            assert len(loaded_cves) == len(cves)
            assert len(loaded_workers) == len(workers)
            
            # Verificar IDs
            assert [s.id for s in loaded_servers] == [s.id for s in servers]
            assert [c.id for c in loaded_cves] == [c.id for c in cves]
            assert [w.id for w in loaded_workers] == [w.id for w in workers]
            
            # Verificar alguns valores
            assert loaded_servers[0].rto_hours == servers[0].rto_hours
            assert loaded_cves[0].epss_score == cves[0].epss_score
            assert loaded_workers[0].authorized_server_ids == workers[0].authorized_server_ids
            
        finally:
            # Limpar ficheiro temporário
            os.unlink(filename)
    
    def test_load_preserves_software(self):
        """Testa que software instalado é preservado."""
        servers, cves, workers = generate_stress_test_data(n_cves=5, seed=42)
        
        # Usar apenas servidores com software
        servers = [s for s in servers if len(s.installed_software) > 0][:3]
        workers = workers[:2]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filename = f.name
        
        try:
            save_scenario_to_json(servers, cves, workers, filename)
            loaded_servers, _, _ = load_scenario_from_json(filename)
            
            for orig, loaded in zip(servers, loaded_servers):
                assert len(orig.installed_software) == len(loaded.installed_software)
                for orig_sw, loaded_sw in zip(orig.installed_software, loaded.installed_software):
                    assert orig_sw.id == loaded_sw.id
                    assert orig_sw.version == loaded_sw.version
                    assert orig_sw.criticality == loaded_sw.criticality
                    
        finally:
            os.unlink(filename)
    
    def test_load_preserves_downtime_windows(self):
        """Testa que janelas de downtime são preservadas."""
        servers, cves, workers = generate_stress_test_data(n_cves=5, seed=42)
        
        servers = servers[:3]
        workers = workers[:2]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filename = f.name
        
        try:
            save_scenario_to_json(servers, cves, workers, filename)
            loaded_servers, _, _ = load_scenario_from_json(filename)
            
            for orig, loaded in zip(servers, loaded_servers):
                # Converter para comparar (listas vs tuplas)
                orig_windows = [tuple(w) for w in orig.downtime_windows]
                loaded_windows = [tuple(w) for w in loaded.downtime_windows]
                assert orig_windows == loaded_windows
                    
        finally:
            os.unlink(filename)
    
    def test_load_preserves_worker_details(self):
        """Testa que detalhes dos workers são preservados."""
        servers, cves, workers = generate_stress_test_data(n_cves=5, seed=42)
        
        servers = servers[:3]
        workers = workers[:3]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            filename = f.name
        
        try:
            save_scenario_to_json(servers, cves, workers, filename)
            _, _, loaded_workers = load_scenario_from_json(filename)
            
            for orig, loaded in zip(workers, loaded_workers):
                assert orig.id == loaded.id
                assert orig.name == loaded.name
                assert orig.level == loaded.level
                assert orig.skills == loaded.skills
                assert orig.on_call == loaded.on_call
                    
        finally:
            os.unlink(filename)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
