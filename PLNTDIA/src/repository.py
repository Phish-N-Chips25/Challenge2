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
        
        # Ler criticidade do CSV (valor padrão 5.0 caso não exista)
        crit = float(row.get('criticality', 5.0))

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
    workers = []
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        return []

    for _, row in df.iterrows():
        w_id = row['tech_id']
        name = row['tech_name']
        level = row['level']
        # .strip() para evitar erros de espaços invisíveis no CSV
        skills = [s.strip() for s in str(row['skills']).split(';')]
        
        shifts = []
        # USAR FLOAT em vez de INT para suportar 7.5, 11.5, etc.
        start = float(row['work_start_h'])
        lunch_in = float(row['lunch_start_h'])
        lunch_out = float(row['lunch_end_h'])
        end = float(row['work_end_h'])
        is_on_call = int(row['on_call']) == 1
        
        # NOVO: Ler os dias de trabalho específicos (ex: "0;1;2;3;4" ou "5;6")
        work_days_str = str(row['work_days']).split(';')
        work_days = [int(d) for d in work_days_str]

        # Criar turnos normais APENAS para os dias definidos no CSV
        for day in work_days: 
            if lunch_in > start: 
                shifts.append((day, start, lunch_in))
            if end > lunch_out: 
                shifts.append((day, lunch_out, end))
                
        if is_on_call:
            # Lógica ON CALL original:
            # Noites de semana (Cobre a janela de PROD das 01h-05h)
            for day in range(5): 
                shifts.append((day, 0, 8)) 
            # Fins de semana totais (Cobre DEV/UAT se ainda não tiver turno lá)
            shifts.append((5, 0, 24)) 
            shifts.append((6, 0, 24)) 

        auth_ids = []
        for srv in servers:
            has_perm = False
            # Comparação de software (Skills)
            for soft in srv.installed_software:
                if soft.id in skills:
                    has_perm = True; break
            
            # Comparação de SO
            if not has_perm:
                if "Windows Server" in skills and "Windows" in srv.os_name:
                    has_perm = True
                elif "Linux" in skills and "Linux" in srv.os_name:
                    has_perm = True

            if has_perm:
                auth_ids.append(srv.id)

        # Criamos o objeto Worker (agora o is_on_call é usado pelo planner para os limites de 8h/12h)
        workers.append(Worker(w_id, name, level, skills, shifts, auth_ids, is_on_call))
        
    print(f"--- DEBUG STAFF ---")
    for w in workers:
        print(f"ID: {w.id} | Nome: {w.name} | Servidores Autorizados: {len(w.authorized_server_ids)}")
        
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
    workers = load_workers("data/team.csv", servers)
    
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