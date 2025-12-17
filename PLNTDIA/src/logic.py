from typing import List, Tuple
from .domain import Server, CVE, Software, Worker

def find_affected_servers(cve: CVE, servers: List[Server]) -> List[Tuple[Server, Software]]:
    """Encontra quais servidores têm o software vulnerável."""
    targets = []
    for srv in servers:
        for soft in srv.installed_software:
            # Compara ID e Versão (String exata por enquanto)
            if (soft.id == cve.affected_software_id and 
                soft.version == cve.affected_software_version):
                targets.append((srv, soft))
    return targets

def calculate_estimate_fix_time(cve: CVE, software: Software) -> int:
    """Estima tempo de correção (horas) baseado em CVSS v3 + contexto operacional. """

    # --- 1. Base time via CVSS ---
    base_score = getattr(cve, "base_score", None)
    if base_score is None:
        base_time = 2.0
    else:
        base_time = base_score / 2

    multiplier = 1.0

    # --- 2. Complexidade técnica ---
    attack_vector = getattr(cve, "attack_vector", "NETWORK")
    if attack_vector == "NETWORK":
        multiplier += 0.3
    elif attack_vector == "ADJACENT_NETWORK":
        multiplier += 0.2
    elif attack_vector == "LOCAL":
        multiplier += 0.1

    if getattr(cve, "attack_complexity", "LOW") == "HIGH":
        multiplier += 0.25

    privs = getattr(cve, "privileges_required", "NONE")
    if privs == "NONE":
        multiplier += 0.2
    elif privs == "LOW":
        multiplier += 0.1

    if getattr(cve, "user_interaction", "NONE") == "REQUIRED":
        multiplier += 0.15

    if getattr(cve, "scope", "UNCHANGED") == "CHANGED":
        multiplier += 0.25

    # --- 3. Software criticality ---
    multiplier += (software.criticality / 10) * 0.5

    # --- 4. Resultado final ---
    estimated = base_time * multiplier

    return max(1, int(round(estimated)))

def calculate_priority(cve: CVE, software: Software) -> float:
    """Calcula urgência baseada no EPSS, Severidade e Criticalidade do Software."""
    
    # 1. Tentar converter Severidade (Híbrido: aceita numérico ou texto)
    try:
        # Se já vier numérico no CSV (futuro)
        sev_score = float(cve.severity)
    except ValueError:
        # Se for texto (High, Medium...)
        severity_map = {"Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 10.0}
        sev_score = severity_map.get(cve.severity, 2.0)
    
    crit_score = software.criticality
    epss_scaled = cve.epss_score * 10.0
    
    # Fórmula: 50% ML + 30% Negócio + 20% CVSS
    return (epss_scaled * 0.5) + (crit_score * 0.3) + (sev_score * 0.2)

def is_worker_available(worker: Worker, day: int, start_h: int, duration: int) -> bool:
    """
    Verifica se o horário pedido cabe dentro de algum turno do trabalhador.
    """
    required_end = start_h + duration
    
    for shift_day, shift_start, shift_end in worker.weekly_shifts:
        if shift_day == day:
            if shift_start <= start_h and required_end <= shift_end:
                return True
    return False

def is_server_available(server: Server, day: int, start_h: int, duration: int) -> bool:
    """
    Verifica se o patch cabe dentro de alguma janela de manutenção do servidor.
    """
    required_end = start_h + duration
    
    for win_day, win_start, win_end in server.downtime_windows:
        # 1. É o dia certo?
        if win_day == day:
            # 2. Cabe na janela?
            # Ex: Janela 02-06. Patch 03-05. (2 <= 3) E (5 <= 6). Válido.
            if win_start <= start_h and required_end <= win_end:
                return True
    return False