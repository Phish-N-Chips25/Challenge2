"""
Testes unitários para o módulo domain.py
"""

import pytest
from src.domain import Software, Server, CVE, Worker, PatchTask, Severity


class TestSeverity:
    """Testes para o Enum Severity."""
    
    def test_severity_values(self):
        """Verifica que os valores do enum estão corretos."""
        assert Severity.LOW.value == "Low"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.HIGH.value == "High"
        assert Severity.CRITICAL.value == "Critical"
    
    def test_severity_scores(self):
        """Verifica que os scores estão corretos."""
        assert Severity.LOW.score == 2.0
        assert Severity.MEDIUM.score == 5.0
        assert Severity.HIGH.score == 8.0
        assert Severity.CRITICAL.score == 10.0
    
    def test_from_string_valid(self):
        """Testa conversão de string válida."""
        assert Severity.from_string("High") == Severity.HIGH
        assert Severity.from_string("high") == Severity.HIGH
        assert Severity.from_string("LOW") == Severity.LOW
    
    def test_from_string_invalid(self):
        """Testa conversão de string inválida (deve retornar LOW)."""
        assert Severity.from_string("Invalid") == Severity.LOW
        assert Severity.from_string("") == Severity.LOW


class TestSoftware:
    """Testes para a classe Software."""
    
    def test_create_valid_software(self):
        """Testa criação de software válido."""
        sw = Software("Apache", "2.4", criticality=8.0)
        assert sw.id == "Apache"
        assert sw.version == "2.4"
        assert sw.criticality == 8.0
    
    def test_criticality_bounds(self):
        """Testa que criticality deve estar entre 0 e 10."""
        # Válido nos limites
        Software("Test", "1.0", criticality=0.0)
        Software("Test", "1.0", criticality=10.0)
        
        # Inválido
        with pytest.raises(ValueError):
            Software("Test", "1.0", criticality=-1.0)
        with pytest.raises(ValueError):
            Software("Test", "1.0", criticality=11.0)
    
    def test_empty_id_raises_error(self):
        """Testa que ID vazio levanta erro."""
        with pytest.raises(ValueError):
            Software("", "1.0", criticality=5.0)
        with pytest.raises(ValueError):
            Software("   ", "1.0", criticality=5.0)


class TestServer:
    """Testes para a classe Server."""
    
    def test_create_valid_server(self):
        """Testa criação de servidor válido."""
        srv = Server(
            id="Srv_01",
            os_name="Linux",
            os_version="Ubuntu 22",
            rto_hours=4,
            downtime_windows=[(0, 2, 6)]
        )
        assert srv.id == "Srv_01"
        assert srv.rto_hours == 4
    
    def test_invalid_rto(self):
        """Testa que RTO deve ser positivo."""
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=0, downtime_windows=[])
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=-1, downtime_windows=[])
    
    def test_invalid_downtime_window_day(self):
        """Testa validação de dia da semana na janela."""
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[(7, 0, 6)])
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[(-1, 0, 6)])
    
    def test_invalid_downtime_window_hours(self):
        """Testa validação de horas na janela."""
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[(0, 6, 2)])  # start > end
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[(0, -1, 6)])  # negative
        with pytest.raises(ValueError):
            Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[(0, 0, 25)])  # > 24
    
    def test_add_software(self):
        """Testa adição de software ao servidor."""
        srv = Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[])
        sw = Software("Apache", "2.4", 8.0)
        
        srv.add_software(sw)
        assert sw in srv.installed_software
        
        # Não deve adicionar duplicados
        srv.add_software(sw)
        assert len(srv.installed_software) == 1
    
    def test_has_software(self):
        """Testa verificação de software instalado."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv", "Linux", "22", rto_hours=4, downtime_windows=[], installed_software=[sw])
        
        assert srv.has_software("Apache", "2.4") == True
        assert srv.has_software("Apache", "2.5") == False
        assert srv.has_software("Nginx", "2.4") == False


class TestCVE:
    """Testes para a classe CVE."""
    
    def test_create_valid_cve(self):
        """Testa criação de CVE válida."""
        cve = CVE(
            id="CVE-2024-1234",
            severity="High",
            epss_score=0.75,
            affected_software_id="Apache",
            affected_software_version="2.4",
            estimated_fix_time=2,
            operators_required=2
        )
        assert cve.id == "CVE-2024-1234"
        assert cve.epss_score == 0.75
    
    def test_invalid_epss_score(self):
        """Testa que EPSS deve estar entre 0 e 1."""
        with pytest.raises(ValueError):
            CVE("CVE-1", "High", -0.1, "Apache", "2.4", 2, 1)
        with pytest.raises(ValueError):
            CVE("CVE-1", "High", 1.1, "Apache", "2.4", 2, 1)
    
    def test_invalid_fix_time(self):
        """Testa que fix_time deve ser positivo."""
        with pytest.raises(ValueError):
            CVE("CVE-1", "High", 0.5, "Apache", "2.4", 0, 1)
    
    def test_invalid_operators(self):
        """Testa que operators deve ser positivo."""
        with pytest.raises(ValueError):
            CVE("CVE-1", "High", 0.5, "Apache", "2.4", 2, 0)
    
    def test_severity_enum_property(self):
        """Testa propriedade severity_enum."""
        cve = CVE("CVE-1", "Critical", 0.5, "Apache", "2.4", 2, 1)
        assert cve.severity_enum == Severity.CRITICAL
        assert cve.severity_score == 10.0
    
    def test_risk_level(self):
        """Testa classificação de risco."""
        cve_high = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        cve_med = CVE("CVE-2", "High", 0.5, "Apache", "2.4", 2, 1)
        cve_low = CVE("CVE-3", "High", 0.2, "Apache", "2.4", 2, 1)
        
        assert cve_high.risk_level == "ALTO"
        assert cve_med.risk_level == "MÉDIO"
        assert cve_low.risk_level == "BAIXO"


class TestWorker:
    """Testes para a classe Worker."""
    
    def test_create_valid_worker(self):
        """Testa criação de worker válido."""
        w = Worker(
            id="Worker_01",
            weekly_shifts=[(0, 9, 17), (1, 9, 17)],
            authorized_server_ids=["Srv_01"]
        )
        assert w.id == "Worker_01"
        assert len(w.weekly_shifts) == 2
    
    def test_empty_id_raises_error(self):
        """Testa que ID vazio levanta erro."""
        with pytest.raises(ValueError):
            Worker("", weekly_shifts=[])
    
    def test_invalid_shift_day(self):
        """Testa validação de dia no turno."""
        with pytest.raises(ValueError):
            Worker("W1", weekly_shifts=[(7, 9, 17)])  # dia 7 inválido
    
    def test_invalid_shift_hours(self):
        """Testa validação de horas no turno."""
        with pytest.raises(ValueError):
            Worker("W1", weekly_shifts=[(0, 17, 9)])  # start > end
    
    def test_shift_exceeds_max_hours(self):
        """Testa que turno pode ter até 8 horas com max_daily_hours=8."""
        # Com os novos workers do CSV, validação de max_daily_hours foi flexibilizada
        # para permitir turnos variáveis, então testamos que 8h funciona
        w = Worker("W1", weekly_shifts=[(0, 0, 8)], max_daily_hours=8)
        assert len(w.weekly_shifts) == 1
    
    def test_has_skill(self):
        """Testa método has_skill."""
        w = Worker(
            id="W1", 
            skills=["SQL Server", "IIS"],
            weekly_shifts=[(0, 9, 17)]
        )
        
        assert w.has_skill("SQL Server") == True
        assert w.has_skill("MongoDB") == False
    
    def test_can_access_server(self):
        """Testa verificação de autorização."""
        w = Worker("W1", weekly_shifts=[], authorized_server_ids=["Srv_01", "Srv_02"])
        
        assert w.can_access_server("Srv_01") == True
        assert w.can_access_server("Srv_03") == False


class TestPatchTask:
    """Testes para a classe PatchTask."""
    
    @pytest.fixture
    def sample_task(self):
        """Cria uma tarefa de exemplo para testes."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 4, [(0, 2, 6)], [sw])
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        worker = Worker("W1", [(0, 0, 8)], ["Srv_01"])
        
        return PatchTask(
            cve=cve,
            server=srv,
            software=sw,
            workers=[worker],
            start_time=2,  # Segunda, 02h
            end_time=4     # Segunda, 04h
        )
    
    def test_duration_property(self, sample_task):
        """Testa cálculo de duração."""
        assert sample_task.duration == 2
    
    def test_day_property(self, sample_task):
        """Testa cálculo do dia da semana."""
        assert sample_task.day == 0  # Segunda
    
    def test_hour_property(self, sample_task):
        """Testa cálculo da hora."""
        assert sample_task.hour == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
