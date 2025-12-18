"""
Módulo de Planeamento (Scheduler)

Implementa o algoritmo de agendamento de patches usando abordagem Greedy.
Inclui tracking de recursos para evitar conflitos.
"""

# Ficheiro: src/planner.py
from typing import List, Tuple, Dict, Optional
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
import logging

from .domain import Server, CVE, Software, Worker, PatchTask
from .logic import is_server_available, is_worker_available, MAX_DAILY_HOURS_DEFAULT

logger = logging.getLogger(__name__)


@dataclass
class ScheduleMetrics:
    """Métricas do resultado do agendamento."""
    total_tasks: int
    scheduled_tasks: int
    failed_tasks: int
    worker_utilization: Dict[str, float]  # worker_id -> % utilização
    server_utilization: Dict[str, float]  # server_id -> % utilização
    
    @property
    def success_rate(self) -> float:
        """Taxa de sucesso do agendamento."""
        if self.total_tasks == 0:
            return 100.0
        return (self.scheduled_tasks / self.total_tasks) * 100.0
    
    def __repr__(self):
        return (
            f"ScheduleMetrics(total={self.total_tasks}, "
            f"scheduled={self.scheduled_tasks}, "
            f"success_rate={self.success_rate:.1f}%)"
        )


class ResourceTracker:
    """
    Rastreia a ocupação de recursos (workers e servidores).
    
    Resolve o bug onde um worker podia ser agendado para 2 tarefas simultâneas.
    """
    
    def __init__(self, workers: List[Worker], servers: List[Server]):
        self.workers = {w.id: w for w in workers}
        self.servers = {s.id: s for s in servers}
        
        # Slots ocupados: (start_absolute_hour, end_absolute_hour)
        self.worker_occupied: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        self.server_occupied: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        
        # Horas trabalhadas por dia: worker_id -> {day -> hours}
        self.worker_daily_hours: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        
        # Horas de manutenção por servidor por dia
        self.server_daily_hours: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    
    def reserve_worker(self, worker_id: str, start: int, end: int):
        """Reserva um worker para um período."""
        self.worker_occupied[worker_id].append((start, end))
        day = (start // 24) % 7
        duration = end - start
        self.worker_daily_hours[worker_id][day] += duration
        logger.debug(f"Worker {worker_id} reservado: {start}h-{end}h (dia {day})")
    
    def reserve_server(self, server_id: str, start: int, end: int):
        """Reserva um servidor para um período."""
        self.server_occupied[server_id].append((start, end))
        day = (start // 24) % 7
        duration = end - start
        self.server_daily_hours[server_id][day] += duration
        logger.debug(f"Server {server_id} reservado: {start}h-{end}h (dia {day})")
    
    def get_worker_utilization(self, worker_id: str, weeks: int = 1) -> float:
        """Calcula % de utilização de um worker."""
        worker = self.workers.get(worker_id)
        if not worker:
            return 0.0
        
        total_available = sum(
            end - start 
            for day, start, end in worker.weekly_shifts
        ) * weeks  # Multiplicar pelo número de semanas
        
        if total_available == 0:
            return 0.0
        
        total_worked = sum(self.worker_daily_hours[worker_id].values())
        return (total_worked / total_available) * 100.0
    
    def get_server_utilization(self, server_id: str, weeks: int = 1) -> float:
        """Calcula % de utilização das janelas de manutenção de um servidor."""
        server = self.servers.get(server_id)
        if not server:
            return 0.0
        
        total_available = sum(
            end - start 
            for day, start, end in server.downtime_windows
        ) * weeks  # Multiplicar pelo número de semanas
        
        if total_available == 0:
            return 0.0
        
        total_used = sum(self.server_daily_hours[server_id].values())
        return (total_used / total_available) * 100.0


def create_simple_schedule(
    tasks: List[Tuple[CVE, Server, Software]], 
    workers: List[Worker],
    max_daily_hours: int = MAX_DAILY_HOURS_DEFAULT,
    verbose: bool = True
) -> List[PatchTask]:
    """
    Cria um agendamento de patches usando algoritmo Greedy.
    
    Algoritmo:
    1. Ordena tarefas por prioridade (maior primeiro)
    2. Para cada tarefa, procura o primeiro slot disponível
    3. Verifica disponibilidade de servidor E workers
    4. Reserva recursos e adiciona ao schedule
    
    Args:
        tasks: Lista de (CVE, Server, Software) a agendar
        workers: Lista de workers disponíveis
        max_daily_hours: Limite de horas por dia por worker
        verbose: Se deve imprimir progresso
        
    Returns:
        Lista de PatchTask agendadas
        
    Note:
        Esta versão corrige o bug onde workers podiam ser
        agendados para múltiplas tarefas simultâneas.
    """
    schedule = []
    
    # Inicializar tracker de recursos
    # Usar dict para eliminar duplicados por ID (Server não é hashable)
    servers_dict = {s.id: s for _, s, _ in tasks}
    servers_in_tasks = list(servers_dict.values())
    tracker = ResourceTracker(workers, servers_in_tasks)
    
    # Ordenar por Prioridade (maior primeiro)
    sorted_tasks = sorted(tasks, key=lambda x: x[0].final_priority_score, reverse=True)
    
    if verbose:
        logger.info(f"A tentar agendar {len(sorted_tasks)} tarefas...")
        print(f"-> A tentar agendar {len(sorted_tasks)} tarefas...")

    failed_reasons: Dict[str, int] = defaultdict(int)

    for cve, server, software in sorted_tasks:
        result = _try_schedule_single_task(
            cve, server, software, workers, tracker, max_daily_hours
        )
        
        if result:
            schedule.append(result)
        else:
            reason = _get_failure_reason(cve, server, workers, tracker, max_daily_hours)
            failed_reasons[reason] += 1
            if verbose:
                print(f"⚠️  FALHOU: {cve.id} no {server.id} -> Motivo: {reason}")
                logger.warning(f"Falha ao agendar {cve.id} no {server.id}: {reason}")

    # Log de resumo
    if verbose and failed_reasons:
        print("\n📊 Resumo de Falhas:")
        for reason, count in sorted(failed_reasons.items(), key=lambda x: -x[1]):
            print(f"   {reason}: {count}")

    return schedule


def _try_schedule_single_task(
    cve: CVE,
    server: Server,
    software: Software,
    workers: List[Worker],
    tracker: ResourceTracker,
    max_daily_hours: int,
    availability_manager=None,
    planning_weeks: int = 1,
    start_date: Optional[date] = None
) -> Optional[PatchTask]:
    """
    Tenta agendar uma única tarefa.
    
    Args:
        availability_manager: Gestor de disponibilidade com férias da equipa
        planning_weeks: Número de semanas do horizonte de planeamento
        start_date: Data de início do planeamento (para verificar férias)
    
    Returns:
        PatchTask se conseguiu agendar, None caso contrário
    """
    # Data de início default é hoje
    if start_date is None:
        start_date = date.today()
    
    # Calcular total de horas disponíveis no horizonte de planeamento
    total_hours = 168 * planning_weeks  # 168 horas por semana
    
    # Procurar em todas as horas do horizonte de planeamento
    for absolute_hour in range(total_hours):
        day = (absolute_hour // 24) % 7
        hour_of_day = absolute_hour % 24
        
        # A. Servidor disponível?
        if not is_server_available(
            server, day, hour_of_day, cve.estimated_fix_time,
            server_occupied=tracker.server_occupied
        ):
            continue 
        
        # B. Encontrar workers disponíveis
        available_team = []
        for w in workers:
            # 1. Verificar permissão
            if not w.can_access_server(server.id):
                continue
            
            # 2. Verificar férias/ausências (se availability_manager disponível)
            if availability_manager is not None:
                # Calcular data real baseada na hora absoluta
                planning_day = absolute_hour // 24
                check_date = start_date + timedelta(days=planning_day)
                if not availability_manager.is_worker_available(w.id, check_date):
                    continue
            
            # 3. Verificar disponibilidade (turno + não ocupado + limite diário)
            if is_worker_available(
                w, day, hour_of_day, cve.estimated_fix_time,
                worker_occupied=tracker.worker_occupied,
                worker_daily_hours=tracker.worker_daily_hours,
                max_daily_hours=max_daily_hours
            ):
                available_team.append(w)
        
        # C. Temos gente suficiente?
        if len(available_team) >= cve.operators_required:
            # SUCESSO! Reservar recursos
            chosen_workers = available_team[:cve.operators_required]
            
            start_time = absolute_hour
            end_time = absolute_hour + cve.estimated_fix_time
            
            # Reservar servidor
            tracker.reserve_server(server.id, start_time, end_time)
            
            # Reservar workers
            for w in chosen_workers:
                tracker.reserve_worker(w.id, start_time, end_time)
            
            return PatchTask(
                cve=cve,
                server=server,
                software=software,
                workers=chosen_workers,
                start_time=start_time,
                end_time=end_time
            )
    
    return None


def _get_failure_reason(
    cve: CVE,
    server: Server,
    workers: List[Worker],
    tracker: ResourceTracker,
    max_daily_hours: int
) -> str:
    """Determina o motivo da falha no agendamento."""
    
    # Verificar se alguma janela do servidor é grande o suficiente
    max_window = max(
        (end - start for _, start, end in server.downtime_windows),
        default=0
    )
    if max_window < cve.estimated_fix_time:
        return f"Janela de servidor muito curta (max {max_window}h, precisa {cve.estimated_fix_time}h)"
    
    # Verificar se há workers autorizados
    authorized = [w for w in workers if w.can_access_server(server.id)]
    if len(authorized) < cve.operators_required:
        return f"Workers autorizados insuficientes ({len(authorized)}/{cve.operators_required})"
    
    # Verificar se há sobreposição de horários
    return "Sem slot compatível (servidor ocupado ou staff indisponível)"


def create_schedule_with_metrics(
    tasks: List[Tuple[CVE, Server, Software]], 
    workers: List[Worker],
    max_daily_hours: int = MAX_DAILY_HOURS_DEFAULT,
    planning_weeks: int = 1,
    availability_manager = None
) -> Tuple[List[PatchTask], ScheduleMetrics]:
    """
    Cria agendamento e retorna métricas detalhadas.
    
    Args:
        tasks: Lista de (CVE, Server, Software) a agendar
        workers: Lista de workers disponíveis
        max_daily_hours: Máximo de horas por dia por worker
        planning_weeks: Número de semanas do horizonte de planeamento
        availability_manager: Gestor de disponibilidade (férias, etc.)
    
    Returns:
        Tupla (lista de PatchTask, ScheduleMetrics)
    """
    # Inicializar tracker para métricas
    # Usar dict para eliminar duplicados por ID (Server não é hashable)
    servers_dict = {s.id: s for _, s, _ in tasks}
    servers_in_tasks = list(servers_dict.values())
    tracker = ResourceTracker(workers, servers_in_tasks)
    
    # Expandir horizonte de planeamento
    total_hours = planning_weeks * 168  # 168 horas por semana
    
    schedule = []
    sorted_tasks = sorted(tasks, key=lambda x: x[0].final_priority_score, reverse=True)
    
    logger.info(f"Horizonte de planeamento: {planning_weeks} semanas ({total_hours} horas)")
    
    for cve, server, software in sorted_tasks:
        result = _try_schedule_single_task(
            cve, server, software, workers, tracker, max_daily_hours,
            availability_manager=availability_manager,
            planning_weeks=planning_weeks
        )
        if result:
            schedule.append(result)
    
    # Calcular métricas
    worker_util = {w.id: tracker.get_worker_utilization(w.id, planning_weeks) for w in workers}
    server_util = {s.id: tracker.get_server_utilization(s.id, planning_weeks) for s in servers_in_tasks}
    
    metrics = ScheduleMetrics(
        total_tasks=len(tasks),
        scheduled_tasks=len(schedule),
        failed_tasks=len(tasks) - len(schedule),
        worker_utilization=worker_util,
        server_utilization=server_util
    )
    
    return schedule, metrics