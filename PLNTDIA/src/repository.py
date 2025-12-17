# src/repository.py
import pandas as pd
from typing import List, Dict, Tuple
from .domain import Server, Software, CVE, Worker

# ==========================================
# 1. FUNÇÕES DE LEITURA DE CSV (ATIVAS)
# ==========================================

def load_server_applications(csv_path: str) -> Dict[str, List[Software]]:
    """
    PASSO 1: Lê o inventário de software.
    Retorna um dicionário ligando ID do Servidor -> Lista de Software.
    """
    inventory_map = {}
    try:
        df = pd.read_csv(csv_path)
        # Limpar espaços nos nomes das colunas
        df.columns = [c.strip() for c in df.columns]
    except FileNotFoundError:
        print(f"❌ Erro: Ficheiro {csv_path} não encontrado.")
        return {}

    print(f"-> A processar {len(df)} linhas de inventário de software...")

    for _, row in df.iterrows():
        srv_id = row['server_id']
        
        # Tenta ler criticidade do CSV, senão usa o DEFAULT
        if 'criticality' in row:
            crit = float(row['criticality'])
        else:
            # Fallback seguro procurando por várias colunas de nome possível
            sw_name = row.get('software_id', row.get('affected_software', 'Unknown'))
            crit = DEFAULT_CRITICALITY.get(sw_name, 5.0)

        # Normalizar nome da coluna do software
        sw_col = 'software_id' if 'software_id' in row else 'affected_software'
        ver_col = 'version' if 'version' in row else 'affected_version'

        new_sw = Software(
            id=row[sw_col], 
            version=str(row.get(ver_col, '1.0')),
            criticality=crit
        )

        if srv_id not in inventory_map:
            inventory_map[srv_id] = []
        inventory_map[srv_id].append(new_sw)
        
    return inventory_map

def load_servers(csv_path: str, inventory_map: Dict[str, List[Software]]) -> List[Server]:
    """
    PASSO 2: Lê os dados técnicos dos servidores e associa o software carregado no Passo 1.
    """
    servers = []
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"❌ Erro: Ficheiro {csv_path} não encontrado.")
        return []

    print(f"-> A processar {len(df)} servidores...")

    for _, row in df.iterrows():
        srv_id = row['id']
        # Buscar software do mapa anterior
        software_list = inventory_map.get(srv_id, [])

        new_server = Server(
            id=srv_id,
            os_name=row['os_name'],
            os_version=row['os_version'],
            rto_hours=int(row['rto_hours']),
            downtime_windows=[], # Será preenchido no passo seguinte
            installed_software=software_list
        )
        servers.append(new_server)
        
    return servers

def load_server_windows(csv_path: str, servers: List[Server]):
    """
    PASSO 3: Lê as janelas de manutenção e anexa aos servidores existentes.
    (Modifica a lista 'servers' in-place).
    """
    server_map = {srv.id: srv for srv in servers}
    
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"❌ Erro: Ficheiro {csv_path} não encontrado.")
        return

    print(f"-> A processar {len(df)} regras de janela de manutenção...")
    count = 0
    for _, row in df.iterrows():
        srv_id = row['server_id']
        if srv_id in server_map:
            # Tupla (Dia, Inicio, Fim)
            window = (int(row['day']), int(row['start_h']), int(row['end_h']))
            server_map[srv_id].downtime_windows.append(window)
            count += 1

def load_workers(csv_path: str, servers: List[Server]) -> List[Worker]:
    """
    PASSO 4: Lê técnicos, calcula turnos (com almoço) e define permissões baseadas em Skills.
    """
    workers = []
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"❌ Erro: Ficheiro {csv_path} não encontrado.")
        return []

    print(f"-> A processar {len(df)} técnicos e a cruzar skills...")

    for _, row in df.iterrows():
        # Parse básico
        w_id = row['tech_id']
        name = row['tech_name']
        level = row['level']
        skills = [s.strip() for s in str(row['skills']).split(';')]
        
        # Calcular Turnos
        shifts = []
        start = int(row['work_start_h'])
        lunch_in = int(row['lunch_start_h'])
        lunch_out = int(row['lunch_end_h'])
        end = int(row['work_end_h'])
        is_on_call = int(row['on_call']) == 1

        for day in range(5): 
            if lunch_in > start: shifts.append((day, start, lunch_in)) # Manhã
            if end > lunch_out: shifts.append((day, lunch_out, end))   # Tarde
                
        # Lógica ON CALL
        if is_on_call:
            for day in range(5): shifts.append((day, 0, 8)) # Noites semana
            shifts.append((5, 0, 24)) # Sábado
            shifts.append((6, 0, 24)) # Domingo

        # Cruzar Skills com Servidores para definir authorized_server_ids
        auth_ids = []
        for srv in servers:
            has_permission = False
            
            # 1. Por Software
            for soft in srv.installed_software:
                if soft.id in skills: 
                    has_permission = True
                    break
            
            # 2. Por Sistema Operativo (Opcional)
            if not has_permission:
                if "Windows Server" in skills and "Windows" in srv.os_name:
                    has_permission = True
                elif "Linux" in skills and "Linux" in srv.os_name:
                    has_permission = True

            if has_permission:
                auth_ids.append(srv.id)

        workers.append(Worker(
            id=w_id, name=name, level=level, skills=skills,
            weekly_shifts=shifts, authorized_server_ids=auth_ids
        ))

    return workers

def load_cves(csv_path: str) -> List[CVE]:
    """
    PASSO 5: Lê a lista de vulnerabilidades (Problemas Reais) a partir de um CSV.
    """
    cves = []
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"❌ Erro: Ficheiro {csv_path} não encontrado.")
        return []

    print(f"-> A carregar {len(df)} CVEs do ficheiro...")

    for _, row in df.iterrows():
        new_cve = CVE(
            id=row['id'],
            severity=row['severity'],
            epss_score=float(row['epss']),
            affected_software_id=row['software'],
            affected_software_version=str(row['version']),
            operators_required=int(row['ops'])
        )
        cves.append(new_cve)
        
    return cves

def initialize_infrastructure_from_csv():
    """
    Função Mestra: Carrega toda a infraestrutura física e humana.
    Nota: As CVEs são carregadas à parte na main.py.
    """
    print("\n--- A CARREGAR INFRAESTRUTURA REAL ---")
    sw_map = load_server_applications("data/server_applications.csv") 
    servers = load_servers("data/servers.csv", sw_map)
    load_server_windows("data/server_windows.csv", servers)
    workers = load_workers("data/workers.csv", servers)
    
    print(f"✅ Infraestrutura Carregada: {len(servers)} Servidores, {len(workers)} Técnicos.\n")
    return servers, workers


# ==========================================
# 2. LEGADO / MOCK DATA (DESATIVADO)
# ==========================================
'''
import random

def generate_cves_for_real_infra(servers, n_cves=50):
    """(LEGADO) Gera vulnerabilidades simuladas baseadas no software instalado."""
    real_cves = []
    installed_software_pool = []
    for s in servers:
        installed_software_pool.extend(s.installed_software)
    
    unique_sw = list({(sw.id, sw.version) for sw in installed_software_pool})
    print(f"-> A gerar {n_cves} CVEs simuladas para {len(unique_sw)} softwares detetados...")

    for i in range(n_cves):
        if not unique_sw: break
        target_name, target_version = random.choice(unique_sw)
        severity = random.choice(["Low", "Medium", "High", "Critical"])
        epss = random.uniform(0.01, 0.99)
        
        if severity == "Critical":
            ops = 2; fix_time = random.randint(2, 4)
        else:
            ops = 1; fix_time = random.randint(1, 2)
            
        cve = CVE(
            id=f"CVE-SIM-{1000+i}", severity=severity, epss_score=epss,
            affected_software_id=target_name, affected_software_version=target_version,
            estimated_fix_time=fix_time, operators_required=ops
        )
        real_cves.append(cve) 
    return real_cves

def get_mock_data():
    """(LEGADO) Cria dados fictícios hardcoded."""
    # ... (código antigo omitido para poupar espaço) ...
    pass

def generate_stress_test_data(n_servers=20, n_cves=50, n_workers=5):
    """(LEGADO) Gera cenário aleatório puro."""
    # ... (código antigo omitido para poupar espaço) ...
    pass
'''