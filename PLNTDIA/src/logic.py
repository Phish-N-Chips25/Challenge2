# src/logic.py
from typing import List, Tuple
from .domain import Server, CVE, Software, Worker

def get_patch_duration(severity: str) -> int:
    """
    Centraliza a estimativa de tempo (horas) baseada na severidade.
    Garante consistência entre a validação de RTO e o agendamento.
    """
    mapping = {
        "Critical": 4,
        "High": 2,
        "Medium": 1,
        "Low": 1
    }
    return mapping.get(severity, 1)

def find_affected_servers(cve: CVE, servers: List[Server]) -> List[Tuple[Server, Software]]:
    """Encontra quais servidores têm o software vulnerável."""
    targets = []
    for srv in servers:
        for soft in srv.installed_software:
            if (soft.id == cve.affected_software_id and 
                soft.version == cve.affected_software_version):
                targets.append((srv, soft))
    return targets

def calculate_priority(cve: CVE, software: Software) -> float:
    """Calcula urgência baseada no EPSS, Severidade e Criticalidade do Software."""
    try:
        sev_score = float(cve.severity)
    except ValueError:
        severity_map = {"Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 10.0}
        sev_score = severity_map.get(str(cve.severity).capitalize(), 2.0)
    
    crit_score = software.criticality
    epss_scaled = cve.epss_score * 10.0
    
    # Fórmula: 50% ML + 30% Negócio + 20% CVSS
    return (epss_scaled * 0.5) + (crit_score * 0.3) + (sev_score * 0.2)

def is_worker_available(worker: Worker, absolute_start_h: int, duration: int) -> bool:
    """
    Verifica disponibilidade usando modulo 168 para suportar múltiplas semanas.
    """
    # Converter tempo absoluto para tempo relativo da semana (0-167)
    rel_start = absolute_start_h % 168
    rel_end = rel_start + duration
    
    day = rel_start // 24
    hour_start = rel_start % 24
    hour_end = hour_start + duration

    for shift_day, shift_start, shift_end in worker.weekly_shifts:
        if shift_day == day:
            if shift_start <= hour_start and hour_end <= shift_end:
                return True
    return False

def is_server_available(server: Server, absolute_start_h: int, duration: int) -> bool:
    """
    Verifica janela de manutenção usando modulo 168.
    """
    rel_start = absolute_start_h % 168
    
    day = rel_start // 24
    hour_start = rel_start % 24
    hour_end = hour_start + duration
    
    for win_day, win_start, win_end in server.downtime_windows:
        if win_day == day:
            if win_start <= hour_start and hour_end <= win_end:
                return True
    return False

def prepare_patching_tasks(cves: List[CVE], servers: List[Server]) -> List[Tuple[CVE, Server, Software]]:
    """
    Cruza CVEs com Servidores.
    [SOFT RTO] Agora não filtra tarefas que excedem o RTO aqui. 
    Passa todas para o Planner, que decidirá se marca como 'Violação'.
    """
    tasks_to_plan = []
    
    print("-> A processar regras de negócio (RTO & Prioridades)...")

    for cve in cves:
        targets = find_affected_servers(cve, servers)
        if not targets: 
            continue

        # 1. Determinar a duração baseada na severidade (Regra Central)
        duration = get_patch_duration(cve.severity)

        for server, software in targets:
            # 2. Calcular Prioridade
            cve.final_priority_score = calculate_priority(cve, software)
            
            # 3. Validar RTO: A duração calculada é aceitável para este servidor?
            # [ALTERAÇÃO] Removemos o 'else' que descartava. 
            # Aceitamos a tarefa mesmo que duration > server.rto_hours.
            tasks_to_plan.append((cve, server, software))
            
            # Opcional: print para debug se necessário (apenas informativo)
            if duration > server.rto_hours:
                # print(f"⚠️ INFO: {cve.id} ({duration}h) excede RTO do {server.id} ({server.rto_hours}h), mas segue para planeamento.")
                pass
            
    return tasks_to_plan

# src/logic.py

LEVEL_RANK = {
    "Junior": 1,
    "Mid": 2,
    "Senior": 3
}

def can_worker_handle_level(worker_level: str, required_level: str) -> bool:
    """Verifica se o ranking do trabalhador chega para o exigido."""
    return LEVEL_RANK.get(worker_level, 0) >= LEVEL_RANK.get(required_level, 0)

# Custo por hora de cada nível (Exemplo em Euros)
LEVEL_HOURLY_RATE = {
    "Junior": 25.0,
    "Mid": 40.0,
    "Senior": 60.0
}