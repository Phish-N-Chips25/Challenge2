"""
Testes unitários para o módulo logic.py
"""

import pytest
from src.domain import Software, Server, CVE, Worker
from src.logic import (
    find_affected_servers,
    calculate_priority,
    is_worker_available,
    is_server_available,
    WEIGHT_EPSS,
    WEIGHT_CRITICALITY,
    WEIGHT_SEVERITY
)


class TestFindAffectedServers:
    """Testes para find_affected_servers."""
    
    @pytest.fixture
    def setup_servers(self):
        """Configura servidores para testes."""
        sw_apache = Software("Apache", "2.4", 8.0)
        sw_nginx = Software("Nginx", "1.18", 6.0)
        
        srv1 = Server("Srv_01", "Linux", "22", 4, [(0, 0, 24)], [sw_apache])
        srv2 = Server("Srv_02", "Linux", "22", 4, [(0, 0, 24)], [sw_nginx])
        srv3 = Server("Srv_03", "Linux", "22", 4, [(0, 0, 24)], [sw_apache, sw_nginx])
        
        return [srv1, srv2, srv3], sw_apache, sw_nginx
    
    def test_find_single_match(self, setup_servers):
        """Testa encontrar um único servidor afetado."""
        servers, sw_apache, _ = setup_servers
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        
        targets = find_affected_servers(cve, servers)
        
        # Deve encontrar Srv_01 e Srv_03
        assert len(targets) == 2
        server_ids = [t[0].id for t in targets]
        assert "Srv_01" in server_ids
        assert "Srv_03" in server_ids
    
    def test_find_no_match(self, setup_servers):
        """Testa quando não há servidores afetados."""
        servers, _, _ = setup_servers
        cve = CVE("CVE-1", "High", 0.8, "PostgreSQL", "13", 2, 1)
        
        targets = find_affected_servers(cve, servers)
        assert len(targets) == 0
    
    def test_version_mismatch(self, setup_servers):
        """Testa que versão diferente não faz match."""
        servers, _, _ = setup_servers
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.5", 2, 1)  # versão 2.5, não 2.4
        
        targets = find_affected_servers(cve, servers)
        assert len(targets) == 0


class TestCalculatePriority:
    """Testes para calculate_priority."""
    
    def test_priority_formula(self):
        """Testa que a fórmula está correta."""
        sw = Software("Apache", "2.4", criticality=10.0)
        cve = CVE("CVE-1", "Critical", epss_score=1.0, 
                  affected_software_id="Apache", affected_software_version="2.4",
                  estimated_fix_time=2, operators_required=1)
        
        # EPSS=1.0 -> scaled=10.0, Crit=10.0, Sev(Critical)=10.0
        # Formula: (10*0.5) + (10*0.3) + (10*0.2) = 5 + 3 + 2 = 10.0
        priority = calculate_priority(cve, sw)
        assert priority == 10.0
    
    def test_priority_low_risk(self):
        """Testa prioridade para CVE de baixo risco."""
        sw = Software("Test", "1.0", criticality=1.0)
        cve = CVE("CVE-1", "Low", epss_score=0.1, 
                  affected_software_id="Test", affected_software_version="1.0",
                  estimated_fix_time=1, operators_required=1)
        
        # EPSS=0.1 -> scaled=1.0, Crit=1.0, Sev(Low)=2.0
        # Formula: (1*0.5) + (1*0.3) + (2*0.2) = 0.5 + 0.3 + 0.4 = 1.2
        priority = calculate_priority(cve, sw)
        assert abs(priority - 1.2) < 0.01
    
    def test_priority_ordering(self):
        """Testa que prioridades ordenam corretamente."""
        sw_high = Software("Critical", "1.0", criticality=10.0)
        sw_low = Software("Optional", "1.0", criticality=2.0)
        
        cve_critical = CVE("CVE-1", "Critical", 0.9, "Critical", "1.0", 2, 1)
        cve_low = CVE("CVE-2", "Low", 0.1, "Optional", "1.0", 1, 1)
        
        p_critical = calculate_priority(cve_critical, sw_high)
        p_low = calculate_priority(cve_low, sw_low)
        
        assert p_critical > p_low


class TestIsWorkerAvailable:
    """Testes para is_worker_available."""
    
    @pytest.fixture
    def day_worker(self):
        """Worker que trabalha das 9h às 17h, Seg-Sex."""
        return Worker("Day_Worker", 
                     weekly_shifts=[(d, 9, 17) for d in range(5)],
                     authorized_server_ids=["Srv_01"])
    
    def test_available_in_shift(self, day_worker):
        """Testa disponibilidade dentro do turno."""
        # Segunda, 10h-12h (2h de trabalho)
        assert is_worker_available(day_worker, day=0, start_h=10, duration=2) == True
    
    def test_unavailable_before_shift(self, day_worker):
        """Testa indisponibilidade antes do turno."""
        # Segunda, 7h-9h
        assert is_worker_available(day_worker, day=0, start_h=7, duration=2) == False
    
    def test_unavailable_after_shift(self, day_worker):
        """Testa indisponibilidade após o turno."""
        # Segunda, 16h-18h (passa das 17h)
        assert is_worker_available(day_worker, day=0, start_h=16, duration=2) == False
    
    def test_unavailable_weekend(self, day_worker):
        """Testa indisponibilidade no fim de semana."""
        # Sábado, 10h-12h
        assert is_worker_available(day_worker, day=5, start_h=10, duration=2) == False
    
    def test_with_occupied_tracking(self, day_worker):
        """Testa com tracking de ocupação."""
        # Segunda (dia 0), 10h = hora absoluta 10 (0*24 + 10)
        # Ocupado das 10h às 12h = (10, 12)
        occupied = {"Day_Worker": [(10, 12)]}
        
        # Mesmo horário - deve estar indisponível
        assert is_worker_available(
            day_worker, day=0, start_h=10, duration=2,
            worker_occupied=occupied
        ) == False
        
        # Horário diferente - deve estar disponível
        assert is_worker_available(
            day_worker, day=0, start_h=14, duration=2,
            worker_occupied=occupied
        ) == True
    
    def test_with_daily_hours_limit(self, day_worker):
        """Testa limite de horas diárias."""
        daily_hours = {"Day_Worker": {0: 7}}  # Já trabalhou 7h na Segunda
        
        # 2h a mais excederia 8h
        assert is_worker_available(
            day_worker, day=0, start_h=14, duration=2,
            worker_daily_hours=daily_hours, max_daily_hours=8
        ) == False
        
        # 1h ainda cabe
        assert is_worker_available(
            day_worker, day=0, start_h=14, duration=1,
            worker_daily_hours=daily_hours, max_daily_hours=8
        ) == True


class TestIsServerAvailable:
    """Testes para is_server_available."""
    
    @pytest.fixture
    def prod_server(self):
        """Servidor de produção com janela curta."""
        return Server("Srv_Prod", "Linux", "22", rto_hours=4,
                     downtime_windows=[(0, 2, 6), (2, 2, 6)])  # Seg e Qua, 02h-06h
    
    @pytest.fixture
    def dev_server(self):
        """Servidor de dev disponível sempre."""
        return Server("Srv_Dev", "Linux", "22", rto_hours=24,
                     downtime_windows=[(d, 0, 24) for d in range(7)])
    
    def test_available_in_window(self, prod_server):
        """Testa disponibilidade dentro da janela."""
        # Segunda, 03h-05h (2h)
        assert is_server_available(prod_server, day=0, start_h=3, duration=2) == True
    
    def test_unavailable_outside_window(self, prod_server):
        """Testa indisponibilidade fora da janela."""
        # Segunda, 10h-12h
        assert is_server_available(prod_server, day=0, start_h=10, duration=2) == False
    
    def test_unavailable_wrong_day(self, prod_server):
        """Testa indisponibilidade em dia sem janela."""
        # Terça (dia sem janela)
        assert is_server_available(prod_server, day=1, start_h=3, duration=2) == False
    
    def test_task_too_long_for_window(self, prod_server):
        """Testa tarefa que não cabe na janela."""
        # Segunda, 03h com 5h de duração (terminaria às 08h, mas janela fecha às 06h)
        assert is_server_available(prod_server, day=0, start_h=3, duration=5) == False
    
    def test_dev_always_available(self, dev_server):
        """Testa servidor de dev sempre disponível."""
        # Qualquer dia/hora
        assert is_server_available(dev_server, day=5, start_h=15, duration=4) == True
    
    def test_with_occupied_tracking(self, dev_server):
        """Testa com tracking de ocupação."""
        occupied = {"Srv_Dev": [(10, 14)]}  # Segunda 10h-14h ocupado
        
        # Mesmo horário - deve estar indisponível
        assert is_server_available(
            dev_server, day=0, start_h=10, duration=2,
            server_occupied=occupied
        ) == False
        
        # Horário diferente - deve estar disponível
        assert is_server_available(
            dev_server, day=0, start_h=16, duration=2,
            server_occupied=occupied
        ) == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
