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