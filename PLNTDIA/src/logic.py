"""
Módulo de Lógica de Negócio

Contém funções para:
- Encontrar servidores afetados por CVEs
- Calcular prioridades de patching
- Verificar disponibilidade de recursos
"""

from typing import List, Tuple, Dict, Set
from collections import defaultdict
import logging

from .domain import Server, CVE, Software, Worker

logger = logging.getLogger(__name__)


# --- CONSTANTES DE CONFIGURAÇÃO ---
# Pesos para fórmula de prioridade (devem somar 1.0)
WEIGHT_EPSS = 0.5           # Peso do score EPSS (ML)
WEIGHT_CRITICALITY = 0.3    # Peso da criticalidade do software
WEIGHT_SEVERITY = 0.2       # Peso da severidade CVSS

# Limites de horas
MAX_DAILY_HOURS_DEFAULT = 8  # Máximo de horas por dia por worker


def find_affected_servers(cve: CVE, servers: List[Server]) -> List[Tuple[Server, Software]]:
    """
    Encontra quais servidores têm o software vulnerável à CVE.
    
    Args:
        cve: A vulnerabilidade a procurar
        servers: Lista de servidores a verificar
        
    Returns:
        Lista de tuplas (Server, Software) afetados
        
    Example:
        >>> targets = find_affected_servers(cve, servers)
        >>> for server, software in targets:
        ...     print(f"{server.id} tem {software.id} vulnerável")
    """
    targets = []
    for srv in servers:
        for soft in srv.installed_software:
            # Compara ID e Versão (String exata por enquanto)
            # TODO: Implementar comparação semântica de versões (semver)
            if (soft.id == cve.affected_software_id and 
                soft.version == cve.affected_software_version):
                targets.append((srv, soft))
                logger.debug(f"CVE {cve.id} afeta {srv.id} via {soft.id}")
    return targets


def calculate_priority(cve: CVE, software: Software) -> float:
    """
    Calcula a prioridade/urgência de aplicar um patch.
    
    Fórmula: (EPSS * 50%) + (Criticalidade * 30%) + (Severidade * 20%)
    
    Args:
        cve: A vulnerabilidade com score EPSS e severidade
        software: O software afetado com sua criticalidade
        
    Returns:
        Score de prioridade (0.0 a 10.0)
        
    Note:
        - EPSS vem do modelo ML (probabilidade de exploração)
        - Criticalidade é o impacto no negócio se o software falhar
        - Severidade é a classificação CVSS da CVE
    """
    # Usar a nova propriedade do CVE para obter o score
    sev_score = cve.severity_score
    crit_score = software.criticality
    
    # Escalar EPSS de 0-1 para 0-10
    epss_scaled = cve.epss_score * 10.0
    
    # Aplicar fórmula ponderada
    priority = (
        (epss_scaled * WEIGHT_EPSS) + 
        (crit_score * WEIGHT_CRITICALITY) + 
        (sev_score * WEIGHT_SEVERITY)
    )
    
    logger.debug(
        f"Prioridade {cve.id}: EPSS={epss_scaled:.2f}*{WEIGHT_EPSS} + "
        f"Crit={crit_score:.2f}*{WEIGHT_CRITICALITY} + "
        f"Sev={sev_score:.2f}*{WEIGHT_SEVERITY} = {priority:.2f}"
    )
    
    return priority


def is_worker_available(
    worker: Worker, 
    day: int, 
    start_h: int, 
    duration: int,
    worker_occupied: Dict[str, List[Tuple[int, int]]] = None,
    worker_daily_hours: Dict[str, Dict[int, int]] = None,
    max_daily_hours: int = MAX_DAILY_HOURS_DEFAULT
) -> bool:
    """
    Verifica se um worker está disponível para uma tarefa.
    
    Verifica:
    1. Se o horário cabe dentro de algum turno do trabalhador
    2. Se o worker não está já ocupado nesse horário (se tracking ativo)
    3. Se o worker não excede o limite diário de horas (se tracking ativo)
    
    Args:
        worker: O trabalhador a verificar
        day: Dia da semana (0=Segunda, 6=Domingo)
        start_h: Hora de início (0-23)
        duration: Duração em horas
        worker_occupied: Dict com slots ocupados por worker (opcional)
        worker_daily_hours: Dict com horas trabalhadas por dia (opcional)
        max_daily_hours: Limite de horas por dia
        
    Returns:
        True se disponível, False caso contrário
    """
    required_end = start_h + duration
    
    # 1. Verificar se cabe no turno
    shift_ok = False
    for shift_day, shift_start, shift_end in worker.weekly_shifts:
        if shift_day == day:
            if shift_start <= start_h and required_end <= shift_end:
                shift_ok = True
                break
    
    if not shift_ok:
        return False
    
    # 2. Verificar se não está ocupado (se tracking ativo)
    if worker_occupied is not None:
        absolute_start = day * 24 + start_h
        absolute_end = absolute_start + duration
        
        for occ_start, occ_end in worker_occupied.get(worker.id, []):
            # Verifica sobreposição
            if not (absolute_end <= occ_start or absolute_start >= occ_end):
                logger.debug(f"Worker {worker.id} ocupado em {occ_start}-{occ_end}")
                return False
    
    # 3. Verificar limite diário de horas (se tracking ativo)
    if worker_daily_hours is not None:
        current_hours = worker_daily_hours.get(worker.id, {}).get(day, 0)
        if current_hours + duration > max_daily_hours:
            logger.debug(
                f"Worker {worker.id} excederia limite diário: "
                f"{current_hours}+{duration} > {max_daily_hours}"
            )
            return False
    
    return True


def is_server_available(
    server: Server, 
    day: int, 
    start_h: int, 
    duration: int,
    server_occupied: Dict[str, List[Tuple[int, int]]] = None
) -> bool:
    """
    Verifica se o servidor está disponível para manutenção.
    
    Verifica:
    1. Se o patch cabe dentro de alguma janela de downtime
    2. Se o servidor não está já em uso (se tracking ativo)
    
    Args:
        server: O servidor a verificar
        day: Dia da semana (0=Segunda, 6=Domingo)
        start_h: Hora de início (0-23)
        duration: Duração em horas
        server_occupied: Dict com slots ocupados por servidor (opcional)
        
    Returns:
        True se disponível, False caso contrário
    """
    required_end = start_h + duration
    
    # 1. Verificar se cabe na janela de manutenção
    window_ok = False
    for win_day, win_start, win_end in server.downtime_windows:
        if win_day == day:
            # Ex: Janela 02-06. Patch 03-05. (2 <= 3) E (5 <= 6). Válido.
            if win_start <= start_h and required_end <= win_end:
                window_ok = True
                break
    
    if not window_ok:
        return False
    
    # 2. Verificar se não está ocupado (se tracking ativo)
    if server_occupied is not None:
        absolute_start = day * 24 + start_h
        absolute_end = absolute_start + duration
        
        for occ_start, occ_end in server_occupied.get(server.id, []):
            # Verifica sobreposição
            if not (absolute_end <= occ_start or absolute_start >= occ_end):
                logger.debug(f"Server {server.id} ocupado em {occ_start}-{occ_end}")
                return False
    
    return True


def get_worker_utilization(
    worker: Worker,
    worker_daily_hours: Dict[str, Dict[int, int]],
    days: int = 7
) -> float:
    """
    Calcula a taxa de utilização de um worker.
    
    Args:
        worker: O trabalhador
        worker_daily_hours: Dict com horas trabalhadas por dia
        days: Número de dias a considerar
        
    Returns:
        Percentagem de utilização (0.0 a 100.0)
    """
    total_available = 0
    for day, start, end in worker.weekly_shifts:
        if day < days:
            total_available += (end - start)
    
    if total_available == 0:
        return 0.0
    
    total_worked = sum(
        worker_daily_hours.get(worker.id, {}).get(d, 0) 
        for d in range(days)
    )
    
    return (total_worked / total_available) * 100.0