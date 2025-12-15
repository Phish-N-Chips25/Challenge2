# Ficheiro: src/utils.py
import random
from .entities import Server, Patch, Operator

def generate_random_infrastructure(n_servers=20, n_patches=50, n_ops=5):
    """
    Gera uma infraestrutura aleatória de grande escala para testes de carga.
    """
    servers = []
    patches = []
    operators = []
    
    # --- 1. GERAR SERVIDORES ---
    # Tipos de perfis de servidor
    os_types = ["Linux", "Windows"]
    
    for i in range(n_servers):
        s_id = f"Srv_{i:02d}"
        os_type = random.choice(os_types)
        
        # Decide aleatoriamente a criticalidade
        rand_crit = random.random()
        
        if rand_crit > 0.8: 
            # 20% são CRÍTICOS (Bancos de Dados, Core)
            crit = 10.0
            cost = 2000.0
            # Janela muito restrita: Domingo 00h-06h
            windows = [(6, 0, 6)] 
            suffix = "_Core"
        elif rand_crit > 0.5:
            # 30% são MÉDIOS (Web Servers, Apps Internas)
            crit = 6.0
            cost = 500.0
            # Janela: Todas as noites (00h-06h)
            windows = [(d, 0, 6) for d in range(7)]
            suffix = "_App"
        else:
            # 50% são BAIXOS (Dev, Testes)
            crit = 2.0
            cost = 50.0
            # Janela: Aberta quase sempre (ex: 20h às 08h todos os dias)
            windows = [(d, 20, 24) for d in range(7)] + [(d, 0, 8) for d in range(7)]
            suffix = "_Dev"

        servers.append(Server(
            id=f"{s_id}{suffix}",
            os=os_type,
            criticality=crit,
            maintenance_windows=windows,
            downtime_cost=cost
        ))

    # --- 2. GERAR PATCHES ---
    for i in range(n_patches):
        # Escolhe um servidor alvo aleatório
        target_server = random.choice(servers)
        
        # Decide severidade/risco
        rand_risk = random.random()
        if rand_risk > 0.8:
            severity = "Critical"
            risk = random.uniform(0.7, 0.99)
            duration = random.randint(2, 4) # Patches demorados
        elif rand_risk > 0.4:
            severity = "Medium"
            risk = random.uniform(0.3, 0.69)
            duration = random.randint(1, 2)
        else:
            severity = "Low"
            risk = random.uniform(0.01, 0.29)
            duration = 1

        patches.append(Patch(
            id=f"CVE-{random.randint(2023, 2025)}-{random.randint(1000, 9999)}",
            risk_score=risk,
            severity=severity,
            estimated_time=duration,
            affected_os=target_server.os, # Tem de bater certo com o servidor
            operators_needed=1, # Simplificação para escala
            server_id=target_server.id
        ))

    # --- 3. GERAR OPERADORES (STAFF) ---
    # Garantir que temos cobertura para todos os horários
    
    # Operadores de Dia (Seg-Sex, 09-18)
    operators.append(Operator("Op_Day_Linux", ["Linux"], (9, 18)))
    operators.append(Operator("Op_Day_Win", ["Windows"], (9, 18)))
    
    # Operadores de Noite (Seg-Sex, 18-02) - Importante para janelas noturnas
    operators.append(Operator("Op_Night_Linux", ["Linux"], (18, 26))) # 26 = 02h da manhã (simplificado)
    operators.append(Operator("Op_Night_Win", ["Windows"], (18, 26)))
    
    # Operador de Fim de Semana (O Salvador dos críticos)
    # Se pediste mais operadores na função, criamos genéricos
    extra_ops = n_ops - 4
    for i in range(extra_ops):
        operators.append(Operator(
            id=f"Op_Weekend_{i}", 
            skills=["Linux", "Windows"], 
            shift=(0, 24) # Disponibilidade total Sáb/Dom (via logica do optimizer)
        ))

    return servers, patches, operators