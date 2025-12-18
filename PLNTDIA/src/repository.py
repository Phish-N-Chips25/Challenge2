"""
Módulo de Repositório de Dados

Contém funções para:
- Carregar dados dos ficheiros CSV
- Gerar cenários de stress test
- Persistência de dados
"""

# Ficheiro: src/repository.py
from typing import List, Tuple, Optional, Dict
from collections import defaultdict
import random
import json
import csv
import os
import logging

from .domain import Server, Software, CVE, Worker

logger = logging.getLogger(__name__)

# Seed padrão para reprodutibilidade
DEFAULT_SEED = 42

# Caminho base para os ficheiros CSV
CSV_BASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "csv")

# Mapeamento de criticidade por tipo de software
SOFTWARE_CRITICALITY = {
    "SQL Server": 10.0,
    "Active Directory": 10.0,
    "Exchange": 9.0,
    "SharePoint": 7.0,
    "IIS": 8.0,
    "Windows Server": 6.0,
    # Novos softwares
    "MySQL Server": 9.0,
    "Java": 8.0,
    "Oracle Database": 10.0,
    "PostgreSQL": 9.0,
    "WebLogic Server": 8.0,
    "Apache Tomcat": 7.0,
    "Nginx": 6.0,
    "Redis": 5.0,
    "Elasticsearch": 7.0,
    "Node.js": 6.0,
    ".NET Framework": 7.0,
    "ASP.NET Core": 7.0,
    "Python": 5.0,
    "Grafana": 6.0,
    "Prometheus": 6.0,
    "Zabbix": 6.0,
    "Kong Gateway": 7.0,
    "RabbitMQ": 7.0,
    "Fortinet FortiGate": 9.0,
    "CrowdStrike Falcon": 9.0,
    "Dynamics 365": 8.0,
}


def load_servers_from_csv(csv_path: str = None) -> List[Server]:
    """
    Carrega servidores do ficheiro CSV.
    
    Args:
        csv_path: Caminho para a pasta CSV (usa padrão se não especificado)
        
    Returns:
        Lista de Server
    """
    if csv_path is None:
        csv_path = CSV_BASE_PATH
    
    servers_file = os.path.join(csv_path, "servers.csv")
    windows_file = os.path.join(csv_path, "server_windows.csv")
    apps_file = os.path.join(csv_path, "server_applications.csv")
    
    # 1. Carregar informações básicas dos servidores
    servers_dict: Dict[str, Server] = {}
    
    with open(servers_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            srv = Server(
                id=row['id'],
                os_name=row['os_name'],
                os_version=row['os_version'],
                rto_hours=int(row['rto_hours']),
                downtime_windows=[],
                environment=row.get('environment', 'PROD'),
                application_group=row.get('application_group', ''),
                dependency_group=row.get('dependency_group', '')
            )
            servers_dict[srv.id] = srv
    
    logger.info(f"Carregados {len(servers_dict)} servidores de {servers_file}")
    
    # 2. Carregar janelas de manutenção
    with open(windows_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            server_id = row['server_id']
            if server_id in servers_dict:
                window = (
                    int(row['day']),
                    int(row['start_h']),
                    int(row['end_h'])
                )
                servers_dict[server_id].downtime_windows.append(window)
    
    logger.info(f"Carregadas janelas de manutenção de {windows_file}")
    
    # 3. Carregar software instalado
    with open(apps_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            server_id = row['server_id']
            if server_id in servers_dict:
                software_name = row['affected_software']
                software_version = row['affected_version']
                criticality = SOFTWARE_CRITICALITY.get(software_name, 5.0)
                
                sw = Software(
                    id=software_name,
                    version=software_version,
                    criticality=criticality
                )
                servers_dict[server_id].add_software(sw)
    
    logger.info(f"Carregado software de {apps_file}")
    
    return list(servers_dict.values())


def load_workers_from_csv(
    csv_path: str = None,
    servers: List[Server] = None
) -> List[Worker]:
    """
    Carrega técnicos do ficheiro CSV.
    
    Args:
        csv_path: Caminho para a pasta CSV
        servers: Lista de servidores (para definir autorizações)
        
    Returns:
        Lista de Worker
        
    Nota sobre os turnos:
        - Trabalhadores regulares: Segunda a Sexta com horário definido no CSV
        - Trabalhadores on_call: Também disponíveis aos fins-de-semana
        - Servidores PROD têm janelas de madrugada (1h-5h), então criamos
          turnos noturnos para os on_call
    """
    if csv_path is None:
        csv_path = CSV_BASE_PATH
    
    team_file = os.path.join(csv_path, "team.csv")
    workers = []
    
    # Obter IDs de servidores por tipo (para autorização baseada em nível)
    prod_servers = []
    test_servers = []
    dev_servers = []
    
    if servers:
        for srv in servers:
            if srv.environment == "PROD" or "PROD" in srv.id:
                prod_servers.append(srv.id)
            elif srv.environment == "TEST" or "TEST" in srv.id or "UAT" in srv.id:
                test_servers.append(srv.id)
            elif srv.environment == "DEV" or "DEV" in srv.id:
                dev_servers.append(srv.id)
    
    with open(team_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            tech_id = row['tech_id']
            tech_name = row['tech_name']
            level = row['level']
            skills = row['skills'].split(';') if row['skills'] else []
            
            work_start = float(row['work_start_h'])
            lunch_start = float(row['lunch_start_h'])
            lunch_end = float(row['lunch_end_h'])
            work_end = float(row['work_end_h'])
            on_call = row['on_call'] == '1'
            
            # Converter horário para turnos semanais
            weekly_shifts = []
            
            # Dias normais: Segunda (0) a Sexta (4)
            for day in range(5):
                # Turno da manhã
                if work_start < lunch_start:
                    weekly_shifts.append((day, int(work_start), int(lunch_start)))
                # Turno da tarde
                if lunch_end < work_end:
                    weekly_shifts.append((day, int(lunch_end), int(work_end)))
            
            # Trabalhadores on_call também trabalham fins-de-semana e turnos noturnos
            # para cobrir janelas de manutenção (TEST/DEV: 18h-24h dias úteis, 8h-24h fins de semana)
            if on_call:
                # DIAS ÚTEIS NOTURNO: Cobrir janelas de manutenção 18h-24h (Segunda a Sexta)
                for day in range(5):  # Segunda (0) a Sexta (4)
                    weekly_shifts.append((day, 18, 24))  # Turno noturno 18h-24h
                
                # FIM-DE-SEMANA: Turnos completos para TEST/DEV (8h-24h disponível)
                # Sábado (dia 5) e Domingo (dia 6)
                for day in [5, 6]:
                    # Turno da madrugada
                    weekly_shifts.append((day, 0, 8))
                    # Turno da manhã/tarde (horário normal)
                    weekly_shifts.append((day, 8, 20))
                    # Turno da noite
                    weekly_shifts.append((day, 20, 24))
                
                # PROD NOTURNO: Seniors e Mids on_call fazem turnos de madrugada
                # (janelas PROD são 2h-6h no domingo e 2h-5h quarta-feira)
                if level in ["Senior", "Mid"]:
                    for day in [2, 6]:  # Quarta e Domingo (dias com janelas PROD)
                        weekly_shifts.append((day, 0, 6))  # Turno noturno 0h-6h
            else:
                # Trabalhadores não on_call também podem fazer fins-de-semana (horário normal)
                # para ajudar em TEST/DEV
                for day in [5, 6]:
                    # Turno da manhã
                    if work_start < lunch_start:
                        weekly_shifts.append((day, int(work_start), int(lunch_start)))
                    # Turno da tarde
                    if lunch_end < work_end:
                        weekly_shifts.append((day, int(lunch_end), int(work_end)))
            
            # Definir autorizações baseadas no nível
            # OTIMIZAÇÃO: Mids on-call também podem aceder a PROD (sob supervisão)
            if level == "Senior":
                # Seniors podem aceder a tudo
                authorized = prod_servers + test_servers + dev_servers
            elif level == "Mid" and on_call:
                # Mids on-call podem aceder a PROD (trabalham com Seniors)
                authorized = prod_servers + test_servers + dev_servers
            elif level == "Mid":
                # Mids regulares só TEST e DEV
                authorized = test_servers + dev_servers
            else:  # Junior
                # Juniors só podem aceder a DEV
                authorized = dev_servers
            
            worker = Worker(
                id=tech_id,
                name=tech_name,
                level=level,
                skills=skills,
                weekly_shifts=weekly_shifts,
                authorized_server_ids=authorized,
                on_call=on_call
            )
            workers.append(worker)
    
    logger.info(f"Carregados {len(workers)} técnicos de {team_file}")
    return workers


def load_data_from_csv(csv_path: str = None) -> Tuple[List[Server], List[Worker]]:
    """
    Carrega todos os dados dos ficheiros CSV.
    
    Args:
        csv_path: Caminho para a pasta CSV
        
    Returns:
        Tupla (servidores, workers)
    """
    servers = load_servers_from_csv(csv_path)
    workers = load_workers_from_csv(csv_path, servers)
    
    return servers, workers


def generate_cves_for_infrastructure(
    servers: List[Server],
    n_cves: int = 50,
    seed: Optional[int] = DEFAULT_SEED
) -> List[CVE]:
    """
    Gera CVEs que afetam o software instalado na infraestrutura.
    
    Args:
        servers: Lista de servidores com software instalado
        n_cves: Número de CVEs a gerar
        seed: Seed para reprodutibilidade
        
    Returns:
        Lista de CVE
    """
    if seed is not None:
        random.seed(seed)
    
    # Recolher todos os softwares únicos instalados
    software_set = set()
    for srv in servers:
        for sw in srv.installed_software:
            software_set.add((sw.id, sw.version))
    
    software_list = list(software_set)
    
    if not software_list:
        logger.warning("Nenhum software encontrado nos servidores!")
        return []
    
    cves = []
    for i in range(n_cves):
        # Escolher um software aleatório que existe na infraestrutura
        target_sw_id, target_sw_version = random.choice(software_list)
        
        severity = random.choice(["Low", "Medium", "High", "Critical"])
        epss = round(random.uniform(0.01, 0.99), 3)
        
        # Determinar requisitos baseados na severidade
        if severity == "Critical":
            ops = 2
            fix_time = random.randint(2, 4)
        elif severity == "High":
            ops = random.choice([1, 2])
            fix_time = random.randint(1, 3)
        else:
            ops = 1
            fix_time = random.randint(1, 2)
        
        cve = CVE(
            id=f"CVE-2025-{1000+i}",
            severity=severity,
            epss_score=epss,
            affected_software_id=target_sw_id,
            affected_software_version=target_sw_version,
            estimated_fix_time=fix_time,
            operators_required=ops
        )
        cves.append(cve)
    
    logger.info(f"Geradas {len(cves)} CVEs para a infraestrutura")
    return cves


def get_mock_data() -> Tuple[List[Server], List[CVE], List[Worker]]:
    """
    Carrega dados dos ficheiros CSV e gera CVEs.
    
    Returns:
        Tupla (servidores, cves, workers)
    """
    servers, workers = load_data_from_csv()
    cves = generate_cves_for_infrastructure(servers)
    
    logger.info(f"Mock data carregada: {len(servers)} servidores, {len(cves)} CVEs, {len(workers)} workers")
    return servers, cves, workers


def generate_stress_test_data(
    n_servers: int = None,  # Ignorado - usa CSV
    n_cves: int = 50,
    n_workers: int = None,  # Ignorado - usa CSV
    seed: Optional[int] = DEFAULT_SEED
) -> Tuple[List[Server], List[CVE], List[Worker]]:
    """
    Carrega dados dos CSV e gera CVEs para stress test.
    
    Args:
        n_servers: Ignorado (usa dados do CSV)
        n_cves: Número de CVEs a gerar
        n_workers: Ignorado (usa dados do CSV)
        seed: Seed para reprodutibilidade
        
    Returns:
        Tupla (servidores, cves, workers)
    """
    servers, workers = load_data_from_csv()
    cves = generate_cves_for_infrastructure(servers, n_cves, seed)
    
    logger.info(
        f"Dados carregados: {len(servers)} servidores, "
        f"{len(cves)} CVEs, {len(workers)} workers"
    )
    
    return servers, cves, workers


def save_scenario_to_json(
    servers: List[Server], 
    cves: List[CVE], 
    workers: List[Worker],
    filename: str
) -> None:
    """
    Salva um cenário em ficheiro JSON para reutilização.
    
    Args:
        servers: Lista de servidores
        cves: Lista de CVEs
        workers: Lista de workers
        filename: Caminho do ficheiro de output
    """
    data = {
        "servers": [
            {
                "id": s.id,
                "os_name": s.os_name,
                "os_version": s.os_version,
                "rto_hours": s.rto_hours,
                "downtime_windows": s.downtime_windows,
                "installed_software": [
                    {"id": sw.id, "version": sw.version, "criticality": sw.criticality}
                    for sw in s.installed_software
                ]
            }
            for s in servers
        ],
        "cves": [
            {
                "id": c.id,
                "severity": c.severity,
                "epss_score": c.epss_score,
                "affected_software_id": c.affected_software_id,
                "affected_software_version": c.affected_software_version,
                "estimated_fix_time": c.estimated_fix_time,
                "operators_required": c.operators_required
            }
            for c in cves
        ],
        "workers": [
            {
                "id": w.id,
                "name": w.name,
                "level": w.level,
                "skills": w.skills,
                "weekly_shifts": w.weekly_shifts,
                "authorized_server_ids": w.authorized_server_ids,
                "on_call": w.on_call
            }
            for w in workers
        ]
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Cenário salvo em {filename}")


def load_scenario_from_json(filename: str) -> Tuple[List[Server], List[CVE], List[Worker]]:
    """
    Carrega um cenário de um ficheiro JSON.
    
    Args:
        filename: Caminho do ficheiro de input
        
    Returns:
        Tupla (servidores, cves, workers)
    """
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Reconstituir Servidores
    servers = []
    for s_data in data["servers"]:
        software_list = [
            Software(sw["id"], sw["version"], sw["criticality"])
            for sw in s_data["installed_software"]
        ]
        srv = Server(
            id=s_data["id"],
            os_name=s_data["os_name"],
            os_version=s_data["os_version"],
            rto_hours=s_data["rto_hours"],
            downtime_windows=[tuple(w) for w in s_data["downtime_windows"]],
            installed_software=software_list
        )
        servers.append(srv)
    
    # Reconstituir CVEs
    cves = [
        CVE(
            id=c["id"],
            severity=c["severity"],
            epss_score=c["epss_score"],
            affected_software_id=c["affected_software_id"],
            affected_software_version=c["affected_software_version"],
            estimated_fix_time=c["estimated_fix_time"],
            operators_required=c["operators_required"]
        )
        for c in data["cves"]
    ]
    
    # Reconstituir Workers
    workers = [
        Worker(
            id=w["id"],
            name=w.get("name", ""),
            level=w.get("level", "Junior"),
            skills=w.get("skills", []),
            weekly_shifts=[tuple(s) for s in w["weekly_shifts"]],
            authorized_server_ids=w["authorized_server_ids"],
            on_call=w.get("on_call", False)
        )
        for w in data["workers"]
    ]
    
    logger.info(f"Cenário carregado de {filename}")
    return servers, cves, workers