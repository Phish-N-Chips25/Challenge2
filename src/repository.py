from .domain import Server, Software, CVE, Worker

def get_mock_data():
    # --- SOFTWARES ---
    # Apache crítico no Servidor Web
    sw_apache_crit = Software("Apache", "2.4", criticality=10.0)
    # Python ferramenta interna (menos crítico)
    sw_python_med = Software("Python", "3.9", criticality=5.0)
    
    # --- SERVIDORES ---
    # Srv 1: Crítico, RTO apertado (2h), Janela só de madrugada (Seg e Ter)
    srv1 = Server(
        id="Srv_Production", os_name="Linux", os_version="Ubuntu 22", 
        rto_hours=2,
        downtime_windows=[(0, 2, 6), (1, 2, 6)], # Seg e Ter, das 02h as 06h
        installed_software=[sw_apache_crit]
    )
    
    # Srv 2: Dev, RTO folgado (24h), Janela dia todo (Segunda)
    srv2 = Server(
        id="Srv_Development", os_name="Windows", os_version="Server 2019", 
        rto_hours=24,
        downtime_windows=[(0, 0, 24)], 
        installed_software=[sw_python_med]
    )

    # --- CVEs ---
    # CVE 1: Afeta Apache. Alto Risco.
    cve1 = CVE(
        id="CVE-2024-9999", severity="Critical", epss_score=0.95,
        affected_software_id="Apache", affected_software_version="2.4",
        estimated_fix_time=2, operators_required=2
    )

    # CVE 2: Afeta Python. Baixo Risco.
    cve2 = CVE(
        id="CVE-2024-1111", severity="Low", epss_score=0.10,
        affected_software_id="Python", affected_software_version="3.9",
        estimated_fix_time=1, operators_required=1
    )

    # --- WORKERS (AJUSTADO PARA O NOVO DOMÍNIO) ---
    
    # João: Trabalha de Seg(0) a Sex(4), das 09h às 17h
    shifts_joao = []
    for day in range(5): 
        shifts_joao.append((day, 9, 17))
        
    w1 = Worker(id="João_Day", weekly_shifts=shifts_joao)

    # Maria: Trabalha de Seg(0) a Sex(4), da 00h às 08h
    shifts_maria = []
    for day in range(5):
        shifts_maria.append((day, 0, 8))

    w2 = Worker(id="Maria_Night", weekly_shifts=shifts_maria)

    return [srv1, srv2], [cve1, cve2], [w1, w2]