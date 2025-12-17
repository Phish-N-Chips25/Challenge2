# Ficheiro: src/repository.py
from .domain import Server, Software, CVE, Worker

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