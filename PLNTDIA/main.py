# main.py
from src.repository import initialize_infrastructure_from_csv, load_cves
from src.logic import prepare_patching_tasks
from src.planner import create_genetic_schedule 
# [ATUALIZADO] Adicionei a importação do export_schedule_json
from src.reporting import export_schedule_report, export_schedule_json

def main():
    #print("========================================")
    print("   SISTEMA DE ESCALONAMENTO DE PATCHES")
    print("========================================")
    
    # PERGUNTA AO UTILIZADOR
    try:
        print("\nEscolha o horizonte de planeamento:")
        print("1 - Uma Semana")
        print("2 - Um Mês (4 semanas)")
        print("3 - Três Meses (12 semanas)")
        print("4 - Personalizado (digite o nº de semanas)")
        
        opcao = input("\nOpção: ")

        if opcao == "1":
            weeks = 1
        elif opcao == "2":
            weeks = 4
        elif opcao == "3":
            weeks = 12
        elif opcao == "4":
            valor = input("Digite o número de semanas: ")
            weeks = int(valor) if valor.isdigit() else 1
        else:
            print("Opção inválida. Usando 1 semana.")
            weeks = 1

    except ValueError:
        weeks = 1

    TOTAL_HOURS = weeks * 168
    
    print(f"=== INICIALIZAÇÃO DO SISTEMA (AG) ===")
    print(f"-> Horizonte de planeamento: {weeks} semana(s) ({TOTAL_HOURS}h)")
    
    # 1. Carregar Infraestrutura
    servers, workers = initialize_infrastructure_from_csv()
    
    # 2. Carregar CVEs
    cves = load_cves("data/cves.csv")
    
    if not cves:
        print("⚠️  Aviso: Nenhuma CVE carregada.")
        return

    # 3. Preparar Tarefas (Prioridades, RTO, etc.)
    tasks_to_plan = prepare_patching_tasks(cves, servers)
    print(f"-> Tarefas validadas para processamento: {len(tasks_to_plan)}")

    # 4. EXECUTAR O ALGORITMO GENÉTICO
    # Agora recebemos 3 valores: Schedule, Failures e Logs
    # [AJUSTE] Valores otimizados para o cenário de 300 servidores (Equilíbrio Rapidez/Qualidade)
    final_schedule, failures, logs_ag = create_genetic_schedule(
        tasks_to_plan, 
        workers, 
        max_hours=TOTAL_HOURS,
        pop_size=50,     # Ajustado para 50 (Suficiente para variar as ordens)
        generations=30   # Ajustado para 30 (Convergência rápida com planner inteligente)
    )
    
    # 5. Exportar Resultados (TXT)
    # Passamos a lista de 'failures' para o relatório detalhado
    export_schedule_report(final_schedule, failures, len(tasks_to_plan), logs_ag)
    
    # 6. Exportar Resultados (JSON para Frontend)
    # [NOVO] Gera o ficheiro para o calendário web
    export_schedule_json(final_schedule)

if __name__ == "__main__":
    main()