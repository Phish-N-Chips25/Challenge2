# app.py
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import sys

# Garante que todos os paths relativos (ex: data/*.csv, web/*) funcionam
# mesmo quando o script é executado a partir de outra pasta.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

# --- IMPORTAÇÕES ORIGINAIS DO MAIN.PY ---
from src.repository import initialize_infrastructure_from_csv, load_cves
# [ATUALIZADO] Adicionei calculate_priority aqui
from src.logic import prepare_patching_tasks, calculate_priority 
from src.planner import create_genetic_schedule
from src.reporting import export_schedule_report, export_schedule_json
from src.domain import CVE, FailedTask
from src.emergency import solve_emergency # A nova lógica blindada

app = Flask(__name__, static_folder='web')
CORS(app)

# --- VARIÁVEIS GLOBAIS (Inicializadas vazias) ---
# Necessário para que o Flask aceda aos dados gerados na inicialização
SERVERS = []
WORKERS = []
REAL_CVES = []
TASKS_TO_PLAN = []
FINAL_SCHEDULE = []
FAILURES = []
LOGS_AG = []
TOTAL_HOURS = 0
PLANNING_WEEKS = 4

# ==========================================
# ROTAS DA API (A Camada Nova)
# ==========================================

@app.route('/')
def index():
    """Serve a página HTML principal"""
    return send_from_directory('web', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    """Serve ficheiros estáticos (CSS, JS, JSON gerado)"""
    return send_from_directory('web', path)

@app.route('/data/<path:filename>')
def data_files(filename):
    """Serve CSVs e outros ficheiros de dados usados pelo frontend (ex: team.csv)."""
    return send_from_directory('data', filename)

@app.route('/schedule.json')
def get_schedule_json():
    """
    Rota explícita para garantir que o frontend recebe sempre o JSON mais recente.
    Lê o ficheiro que o export_schedule_json acabou de escrever.
    """
    return send_from_directory('web', 'schedule.json')

@app.route('/api/software_inventory')
def get_software_list():
    """Retorna lista única de software instalado na infraestrutura"""
    unique_software = set()
    for srv in SERVERS:
        for soft in srv.installed_software:
            unique_software.add(soft.id)
    
    return jsonify(sorted(list(unique_software)))


@app.route('/api/server_cves')
def get_server_cves():
    """Retorna a correlação Servidor -> CVEs (match por software_id + version)."""
    server_rows = []

    # Para cada servidor, ver quais CVEs batem no inventário instalado
    for srv in SERVERS:
        matched = []
        max_priority = 0.0

        for cve in REAL_CVES:
            for soft in srv.installed_software:
                if soft.id == cve.affected_software_id and soft.version == cve.affected_software_version:
                    priority = float(calculate_priority(cve, soft))
                    if priority > max_priority:
                        max_priority = priority

                    matched.append({
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "epss": float(cve.epss_score),
                        "software": {
                            "id": soft.id,
                            "version": soft.version,
                            "criticality": float(getattr(soft, 'criticality', 0.0)),
                        },
                        "operators_required": int(cve.operators_required),
                        "priority": priority,
                    })
                    break

        # Ordenar CVEs por prioridade desc, depois EPSS desc
        matched.sort(key=lambda x: (x.get('priority', 0.0), x.get('epss', 0.0)), reverse=True)

        server_rows.append({
            "server": {
                "id": srv.id,
                "environment": srv.environment,
                "os_name": srv.os_name,
                "os_version": srv.os_version,
                "rto_hours": int(srv.rto_hours),
            },
            "cves": matched,
            "cve_count": len(matched),
            "max_priority": max_priority,
        })

    # Ordenar servidores com mais CVEs primeiro; depois por env_rank e id
    env_rank = {"DEV": 1, "UAT": 2, "PROD": 3}
    server_rows.sort(key=lambda r: (-r.get('cve_count', 0), env_rank.get(r['server']['environment'], 99), r['server']['id']))

    payload = {
        "total_servers": len(server_rows),
        "total_cves": len(REAL_CVES),
        "rows": server_rows,
    }
    return jsonify(payload)

@app.route('/api/emergency', methods=['POST'])
def trigger_emergency():
    global FINAL_SCHEDULE, FAILURES 
    
    data = request.json
    print(f"\n🚨 [API] Pedido de Emergência Recebido: {data['cve_id']}")
    
    # Debug: Contar tarefas antes
    count_before = len(FINAL_SCHEDULE)

    # 1. Criar objeto CVE com os dados REAIS do formulário
    # NOTA: Forçamos severidade "Critical" para assumir o pior cenário (janela máxima)
    emergency_cve = CVE(
        id=data['cve_id'],
        severity="Critical",            # <--- ALTERADO: Fixo em "Critical" por segurança
        epss_score=float(data['epss']), # Dinâmico (0.0 a 1.0)
        affected_software_id=data['software'],
        affected_software_version="Emergency_Patch",
        operators_required=int(data['operators'])
    )

    # 2. Encontrar o objeto Software na infraestrutura para saber o "Business Value"
    target_software_obj = None
    for srv in SERVERS:
        for soft in srv.installed_software:
            if soft.id == data['software']:
                target_software_obj = soft
                break
        if target_software_obj: break
    
    if not target_software_obj:
        return jsonify({"success": False, "message": "Software não encontrado na infraestrutura."})

    # 3. CÁLCULO INTELIGENTE DA PRIORIDADE 🧠
    # Calculamos o score real base (ex: 8.5) usando a lógica do projeto
    base_priority = calculate_priority(emergency_cve, target_software_obj)
    
    # Adicionamos um "Boost de Pânico" (+2.0) porque é uma intervenção fora de horas.
    EMERGENCY_BOOST = 4.0
    emergency_cve.final_priority_score = base_priority + EMERGENCY_BOOST

    print(f"   📊 Score Base: {base_priority:.2f} + Boost: {EMERGENCY_BOOST} = Final: {emergency_cve.final_priority_score:.2f}")

    # 4. Executar lógica de agendamento (ATUALIZADO PARA RECEBER 3 VALORES)
    # success: True/False
    # rescheduled_tasks: Lista de tarefas que mudaram de hora (salvas)
    # final_failures: Lista de tarefas que foram canceladas (sacrificadas)
    success, rescheduled_tasks, final_failures = solve_emergency(
        FINAL_SCHEDULE, 
        emergency_cve, 
        SERVERS, 
        WORKERS, 
        TOTAL_HOURS
    )

    if success:
        # Debug: Verificar se entrou mesmo
        count_after = len(FINAL_SCHEDULE)
        print(f"   📈 Tarefas no calendário: {count_before} -> {count_after}")
        
        # PROVA DE VIDA: Encontrar a tarefa na lista e imprimir no terminal
        found_em = [t for t in FINAL_SCHEDULE if t.cve.id == data['cve_id']]
        
        # --- NOVO RELATÓRIO DE TERMINAL DETALHADO ---
        print("==================================================")
        print(f"🚨 RELATÓRIO PÓS-EMERGÊNCIA: {data['cve_id']}")
        print(f"   Resultado: {'✅ SUCESSO' if success else '❌ FALHA PARCIAL'}")
        print("--------------------------------------------------")
        
        print(f"   🔄 Tarefas Reagendadas (Salvas): {len(rescheduled_tasks)}")
        if rescheduled_tasks:
            print("      (Foram movidas para abrir espaço, sem serem canceladas)")
            for t in rescheduled_tasks:
                print(f"      -> ♻️  {t.server.id} [{t.cve.id}]: Nova hora {t.start_time}h-{t.end_time}h")

        print("--------------------------------------------------")
        print(f"   💀 Tarefas Sacrificadas (Removidas): {len(final_failures)}")
        if final_failures:
            print("      (Não houve espaço/recursos para estas tarefas)")
            for f in final_failures:
                print(f"      -> ❌ {f.server.id} [{f.cve.id}]: {f.reason}")
                
        print("==================================================")

        # Atualizar lista global de falhas
        FAILURES.extend(final_failures)
        
        # Adicionar nota GRANDE no log do ficheiro
        logs_extra = [
            "==================================================",
            f"🚨 INTERVENÇÃO DE EMERGÊNCIA: {data['cve_id']}",
            f"   Agendado em {len(found_em)} servidores.",
            f"   Prioridade Final: {emergency_cve.final_priority_score:.2f} (Boost Aplicado)",
            f"   Tarefas Reagendadas (Salvas): {len(rescheduled_tasks)}",
            f"   Tarefas Sacrificadas (Removidas): {len(final_failures)}",
            "=================================================="
        ]
        
        export_schedule_report(
            FINAL_SCHEDULE, 
            FAILURES, 
            len(TASKS_TO_PLAN) + 1, 
            LOGS_AG + logs_extra, 
            filename="relatorio_pos_emergencia.txt"
        )
        
        export_schedule_json(FINAL_SCHEDULE, FAILURES)
        print("🔄 Ficheiros atualizados.")

    response = {
        "success": success,
        "rescheduled_count": len(rescheduled_tasks),
        "sacrificed_count": len(final_failures),
        "details": [f"Salvos: {len(rescheduled_tasks)} | Sacrificados: {len(final_failures)}"]
    }
    return jsonify(response)

# ==========================================
# FUNÇÃO DE INICIALIZAÇÃO
# ==========================================
def initialize_system():
    """
    Corre toda a lógica do main.py original ANTES do servidor web arrancar.
    """
    # Declarar globais para preencher
    global SERVERS, WORKERS, REAL_CVES, TASKS_TO_PLAN, FINAL_SCHEDULE, FAILURES, LOGS_AG, TOTAL_HOURS, PLANNING_WEEKS

    print("========================================")
    print("   SISTEMA DE ESCALONAMENTO (WEB API)")
    print("========================================")
    
    # --- BLOCO DE INPUT RESTAURADO ---
    try:
        print("\nEscolha o horizonte de planeamento:")
        print("1 - Uma Semana")
        print("2 - Um Mês (4 semanas) [Recomendado]")
        print("3 - Três Meses (12 semanas)")
        print("4 - Personalizado (digite o nº de semanas)")
        
        # O input bloqueia aqui até tu responderes
        opcao = input("\nOpção: ") 

        if opcao == "1":
            PLANNING_WEEKS = 1
        elif opcao == "2":
            PLANNING_WEEKS = 4
        elif opcao == "3":
            PLANNING_WEEKS = 12
        elif opcao == "4":
            valor = input("Digite o número de semanas: ")
            PLANNING_WEEKS = int(valor) if valor.isdigit() else 4
        else:
            print("Opção inválida. Usando 4 semanas (Padrão).")
            PLANNING_WEEKS = 4

    except (Exception, KeyboardInterrupt):
        # Fallback caso haja erro no input
        print(f"Input interrompido. Usando padrão de 4 semanas.")
        PLANNING_WEEKS = 4

    TOTAL_HOURS = PLANNING_WEEKS * 168

    print(f"=== INICIALIZAÇÃO DO SISTEMA ===")
    print(f"-> Horizonte definido: {PLANNING_WEEKS} semanas ({TOTAL_HOURS}h)")

    # 1. Carregar Infraestrutura (IGUAL AO MAIN)
    SERVERS, WORKERS = initialize_infrastructure_from_csv()

    # 2. Carregar CVEs (IGUAL AO MAIN)
    REAL_CVES = load_cves("data/cves.csv")

    # 3. Preparar Tarefas (IGUAL AO MAIN)
    TASKS_TO_PLAN = prepare_patching_tasks(REAL_CVES, SERVERS)
    print(f"-> Tarefas validadas para processamento: {len(TASKS_TO_PLAN)}")

    # 4. EXECUTAR O ALGORITMO GENÉTICO (IGUAL AO MAIN)
    print("🧬 A executar Algoritmo Genético (pode demorar alguns segundos)...")
    FINAL_SCHEDULE, FAILURES, LOGS_AG = create_genetic_schedule(
        TASKS_TO_PLAN, 
        WORKERS, 
        max_hours=TOTAL_HOURS,
        pop_size=50,    # Mantido do teu main.py
        generations=1   # Mantido do teu main.py
    )

    # 5. & 6. EXPORTAR RESULTADOS INICIAIS (IGUAL AO MAIN)
    export_schedule_report(FINAL_SCHEDULE, FAILURES, len(TASKS_TO_PLAN), LOGS_AG)
    export_schedule_json(FINAL_SCHEDULE, FAILURES) 
    print("✅ Sistema inicializado e ficheiros exportados!")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    # 1. Primeiro corremos a lógica de negócio (Input + AG)
    initialize_system()
    
    # 2. Depois arrancamos o servidor Web
    # IMPORTANTE: use_reloader=False evita que o script corra 2 vezes e peça input novamente
    print("🚀 A arrancar servidor Web em http://localhost:5000 ...")
    app.run(debug=True, port=5000, use_reloader=False)