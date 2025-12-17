# Ficheiro: src/repository.py
from .domain import Server, Software, CVE, Worker
import random

def get_mock_data():
    # --- SOFTWARE & SERVIDORES ---
    sw_apache_crit = Software("Apache", "2.4", criticality=10.0)
    sw_python_med = Software("Python", "3.9", criticality=5.0)
    
    srv1 = Server(
        id="Srv_Production", os_name="Linux", os_version="Ubuntu 22", 
        rto_hours=2,
        downtime_windows=[(0, 2, 6), (1, 2, 6)], 
        installed_software=[sw_apache_crit]
    )
    
    srv2 = Server(
        id="Srv_Development", os_name="Windows", os_version="Server 2019", 
        rto_hours=24,
        downtime_windows=[(0, 0, 24)], 
        installed_software=[sw_python_med]
    )

    # --- CVEs ---
    # CVE Crítica: Precisa de 2 pessoas
    cve1 = CVE("CVE-2024-9999", "Critical", 0.95, "Apache", "2.4", 2, 2)
    # CVE Baixa: Precisa de 1 pessoa
    cve2 = CVE("CVE-2024-1111", "Low", 0.10, "Python", "3.9", 1, 1)

    # --- WORKERS ---
    
    # João (Dia): Vamos dar permissão APENAS para Produção
    shifts_joao = [(d, 9, 17) for d in range(5)]
    w1 = Worker(
        id="João_Day", 
        weekly_shifts=shifts_joao,
        authorized_server_ids=["Srv_Production"] # Configuração explícita
    )

    # Maria (Noite): Vamos dar permissão para TUDO (Prod e Dev)
    shifts_maria = [(d, 0, 8) for d in range(5)]
    w2 = Worker(
        id="Maria_Night", 
        weekly_shifts=shifts_maria,
        authorized_server_ids=["Srv_Production", "Srv_Development"]
    )

    # Pedro (Noite): Vamos dar permissão APENAS para Produção
    shifts_pedro = [(d, 0, 8) for d in range(5)]
    w3 = Worker(
        id="Pedro_Night", 
        weekly_shifts=shifts_pedro,
        authorized_server_ids=["Srv_Production"]
    )

    return [srv1, srv2], [cve1, cve2], [w1, w2, w3]


def generate_stress_test_data(n_servers=20, n_cves=50, n_workers=5):
    """Gera um cenário complexo e aleatório para testar os limites."""
    
    # 1. Softwares Possíveis
    soft_catalog = [
        Software("Apache", "2.4", 10.0),
        Software("Nginx", "1.18", 8.0),
        Software("Python", "3.9", 5.0),
        Software("PostgreSQL", "13", 10.0),
        Software("Redis", "6.0", 6.0)
    ]
    
    servers = []
    # 2. Gerar Servidores
    for i in range(n_servers):
        # Aleatoriamente decide se é Prod (janela curta) ou Dev (janela longa)
        is_prod = random.choice([True, False])
        
        if is_prod:
            # Janela difícil: Ter e Qui, 02h-05h
            windows = [(1, 2, 5), (3, 2, 5)] 
            rto = 4
            srv_id = f"Srv_Prod_{i:02d}"
        else:
            # Janela fácil: Todos os dias, 00h-24h
            windows = [(d, 0, 24) for d in range(7)]
            rto = 24
            srv_id = f"Srv_Dev_{i:02d}"
            
        srv = Server(id=srv_id, os_name="Linux", os_version="Unknown", rto_hours=rto, downtime_windows=windows)
        
        # Instalar 1 ou 2 softwares aleatórios
        installed = random.sample(soft_catalog, k=random.randint(1, 2))
        for sw in installed:
            srv.add_software(sw)
        
        servers.append(srv)

    # 3. Gerar Workers
    workers = []
    for i in range(n_workers):
        # Alguns experientes (acesso a tudo), outros juniores (só Dev)
        is_senior = random.choice([True, False])
        
        # Turnos: Uns de dia, outros de noite
        start_h = random.choice([0, 8, 16]) # Turnos 00-08, 08-16, 16-24
        shifts = [(d, start_h, start_h+8) for d in range(5)]
        
        if is_senior:
            # Acesso a todos os servidores gerados
            auth_ids = [s.id for s in servers]
            role = "Senior"
        else:
            # Acesso apenas aos servidores de Dev
            auth_ids = [s.id for s in servers if "Dev" in s.id]
            role = "Junior"
            
        w = Worker(id=f"Op_{i}_{role}", weekly_shifts=shifts, authorized_server_ids=auth_ids)
        workers.append(w)

    # 4. Gerar CVEs
    cves = []
    for i in range(n_cves):
        # Escolher um software alvo aleatório
        target_sw = random.choice(soft_catalog)
        
        severity = random.choice(["Low", "Medium", "High", "Critical"])
        epss = random.uniform(0.01, 0.99)
        
        # Se for crítico, precisa de 2 pessoas e demora mais
        if severity == "Critical":
            ops = 2
            fix_time = random.randint(2, 4)
        else:
            ops = 1
            fix_time = random.randint(1, 2)
            
        cve = CVE(
            id=f"CVE-2025-{1000+i}",
            severity=severity,
            epss_score=epss,
            affected_software_id=target_sw.id,
            affected_software_version=target_sw.version,
            estimated_fix_time=fix_time,
            operators_required=ops
        )
        cves.append(cve)

    return servers, cves, workers