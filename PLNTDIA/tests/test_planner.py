"""
Testes unitários para o módulo planner.py
"""

import pytest
from src.domain import Software, Server, CVE, Worker, PatchTask
from src.planner import (
    create_simple_schedule,
    create_schedule_with_metrics,
    ResourceTracker,
    ScheduleMetrics
)


class TestResourceTracker:
    """Testes para a classe ResourceTracker."""
    
    @pytest.fixture
    def setup_tracker(self):
        """Configura tracker para testes."""
        workers = [
            Worker(id="W1", weekly_shifts=[(0, 0, 8), (1, 0, 8)], authorized_server_ids=["Srv_01"]),
            Worker(id="W2", weekly_shifts=[(0, 8, 16)], authorized_server_ids=["Srv_01"])
        ]
        servers = [
            Server("Srv_01", "Linux", "22", 4, [(0, 0, 24)])
        ]
        return ResourceTracker(workers, servers)
    
    def test_reserve_worker(self, setup_tracker):
        """Testa reserva de worker."""
        tracker = setup_tracker
        tracker.reserve_worker("W1", 2, 4)  # Segunda 02h-04h
        
        assert (2, 4) in tracker.worker_occupied["W1"]
        assert tracker.worker_daily_hours["W1"][0] == 2  # 2h no dia 0
    
    def test_reserve_server(self, setup_tracker):
        """Testa reserva de servidor."""
        tracker = setup_tracker
        tracker.reserve_server("Srv_01", 2, 4)
        
        assert (2, 4) in tracker.server_occupied["Srv_01"]
        assert tracker.server_daily_hours["Srv_01"][0] == 2
    
    def test_worker_utilization(self, setup_tracker):
        """Testa cálculo de utilização de worker."""
        tracker = setup_tracker
        
        # W1 tem 16h disponíveis (8h * 2 dias)
        tracker.reserve_worker("W1", 0, 4)  # 4h no dia 0
        tracker.reserve_worker("W1", 24, 28)  # 4h no dia 1
        
        util = tracker.get_worker_utilization("W1")
        assert util == 50.0  # 8h de 16h = 50%
    
    def test_server_utilization(self, setup_tracker):
        """Testa cálculo de utilização de servidor."""
        tracker = setup_tracker
        
        # Srv_01 tem 24h disponíveis (1 dia inteiro)
        tracker.reserve_server("Srv_01", 0, 6)  # 6h
        
        util = tracker.get_server_utilization("Srv_01")
        assert util == 25.0  # 6h de 24h = 25%


class TestScheduleMetrics:
    """Testes para ScheduleMetrics."""
    
    def test_success_rate(self):
        """Testa cálculo da taxa de sucesso."""
        metrics = ScheduleMetrics(
            total_tasks=10,
            scheduled_tasks=7,
            failed_tasks=3,
            worker_utilization={},
            server_utilization={}
        )
        assert metrics.success_rate == 70.0
    
    def test_success_rate_zero_tasks(self):
        """Testa taxa de sucesso com zero tarefas."""
        metrics = ScheduleMetrics(
            total_tasks=0,
            scheduled_tasks=0,
            failed_tasks=0,
            worker_utilization={},
            server_utilization={}
        )
        assert metrics.success_rate == 100.0


class TestCreateSimpleSchedule:
    """Testes para create_simple_schedule."""
    
    @pytest.fixture
    def simple_scenario(self):
        """Cenário simples para testes."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 4, [(0, 0, 24)], [sw])
        
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        cve.final_priority_score = 8.0
        
        worker = Worker(id="W1", weekly_shifts=[(0, 0, 8)], authorized_server_ids=["Srv_01"])
        
        tasks = [(cve, srv, sw)]
        workers = [worker]
        
        return tasks, workers
    
    def test_schedule_single_task(self, simple_scenario):
        """Testa agendamento de uma única tarefa."""
        tasks, workers = simple_scenario
        
        schedule = create_simple_schedule(tasks, workers, verbose=False)
        
        assert len(schedule) == 1
        assert schedule[0].cve.id == "CVE-1"
        assert schedule[0].server.id == "Srv_01"
    
    def test_no_worker_available(self):
        """Testa quando não há worker disponível."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 4, [(0, 2, 6)], [sw])  # Janela 02h-06h
        
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        cve.final_priority_score = 8.0
        
        # Worker trabalha das 9h às 17h - não coincide com janela do servidor
        worker = Worker(id="W1", weekly_shifts=[(0, 9, 17)], authorized_server_ids=["Srv_01"])
        
        schedule = create_simple_schedule([(cve, srv, sw)], [worker], verbose=False)
        
        assert len(schedule) == 0
    
    def test_no_authorization(self):
        """Testa quando worker não tem autorização."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 4, [(0, 0, 24)], [sw])
        
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        cve.final_priority_score = 8.0
        
        # Worker não tem autorização para Srv_01
        worker = Worker(id="W1", weekly_shifts=[(0, 0, 8)], authorized_server_ids=["Srv_02"])
        
        schedule = create_simple_schedule([(cve, srv, sw)], [worker], verbose=False)
        
        assert len(schedule) == 0
    
    def test_priority_ordering(self):
        """Testa que tarefas são ordenadas por prioridade."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 24, [(0, 0, 24)], [sw])
        
        cve_high = CVE("CVE-HIGH", "Critical", 0.9, "Apache", "2.4", 1, 1)
        cve_high.final_priority_score = 9.0
        
        cve_low = CVE("CVE-LOW", "Low", 0.1, "Apache", "2.4", 1, 1)
        cve_low.final_priority_score = 2.0
        
        worker = Worker(id="W1", weekly_shifts=[(0, 0, 8)], authorized_server_ids=["Srv_01"])
        
        # Passar em ordem inversa à prioridade
        tasks = [(cve_low, srv, sw), (cve_high, srv, sw)]
        
        schedule = create_simple_schedule(tasks, [worker], verbose=False)
        
        assert len(schedule) == 2
        # Primeira tarefa agendada deve ser a de maior prioridade
        assert schedule[0].cve.id == "CVE-HIGH"
    
    def test_worker_not_double_booked(self):
        """Testa que worker não é agendado para 2 tarefas simultâneas."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 24, [(0, 0, 24)], [sw])
        
        cve1 = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        cve1.final_priority_score = 8.0
        
        cve2 = CVE("CVE-2", "High", 0.7, "Apache", "2.4", 2, 1)
        cve2.final_priority_score = 7.0
        
        # Apenas 1 worker com turno curto
        worker = Worker(id="W1", weekly_shifts=[(0, 0, 4)], authorized_server_ids=["Srv_01"])
        
        tasks = [(cve1, srv, sw), (cve2, srv, sw)]
        
        schedule = create_simple_schedule(tasks, [worker], verbose=False)
        
        # Só deve agendar 1 tarefa (2h) porque só há 4h disponíveis
        # e as tarefas não podem sobrepor
        assert len(schedule) == 2
        
        # Verificar que não há sobreposição
        for i, task1 in enumerate(schedule):
            for task2 in schedule[i+1:]:
                # Verificar se os mesmos workers estão em tarefas que se sobrepõem
                common_workers = set(w.id for w in task1.workers) & set(w.id for w in task2.workers)
                if common_workers:
                    # Se há workers em comum, as tarefas não devem sobrepor
                    assert task1.end_time <= task2.start_time or task2.end_time <= task1.start_time
    
    def test_requires_multiple_operators(self):
        """Testa tarefa que requer múltiplos operadores."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 4, [(0, 0, 24)], [sw])
        
        # CVE que precisa de 2 pessoas
        cve = CVE("CVE-1", "Critical", 0.9, "Apache", "2.4", 2, 2)
        cve.final_priority_score = 9.0
        
        # Apenas 1 worker
        worker1 = Worker(id="W1", weekly_shifts=[(0, 0, 8)], authorized_server_ids=["Srv_01"])
        
        # Com 1 worker - não deve conseguir agendar
        schedule = create_simple_schedule([(cve, srv, sw)], [worker1], verbose=False)
        assert len(schedule) == 0
        
        # Com 2 workers - deve conseguir
        worker2 = Worker(id="W2", weekly_shifts=[(0, 0, 8)], authorized_server_ids=["Srv_01"])
        schedule = create_simple_schedule([(cve, srv, sw)], [worker1, worker2], verbose=False)
        assert len(schedule) == 1
        assert len(schedule[0].workers) == 2


class TestCreateScheduleWithMetrics:
    """Testes para create_schedule_with_metrics."""
    
    def test_returns_metrics(self):
        """Testa que retorna métricas junto com o schedule."""
        sw = Software("Apache", "2.4", 8.0)
        srv = Server("Srv_01", "Linux", "22", 4, [(0, 0, 24)], [sw])
        
        cve = CVE("CVE-1", "High", 0.8, "Apache", "2.4", 2, 1)
        cve.final_priority_score = 8.0
        
        worker = Worker(id="W1", weekly_shifts=[(0, 0, 8)], authorized_server_ids=["Srv_01"])
        
        schedule, metrics = create_schedule_with_metrics([(cve, srv, sw)], [worker])
        
        assert len(schedule) == 1
        assert isinstance(metrics, ScheduleMetrics)
        assert metrics.total_tasks == 1
        assert metrics.scheduled_tasks == 1
        assert metrics.failed_tasks == 0
        assert "W1" in metrics.worker_utilization
        assert "Srv_01" in metrics.server_utilization


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
