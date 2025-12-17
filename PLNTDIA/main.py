# main.py
from src.repository import initialize_infrastructure_from_csv, load_cves # <--- Importar load_cves
from src.logic import prepare_patching_tasks
from src.planner import create_simple_schedule
from src.reporting import export_schedule_report

def main():
    print("=== INICIALIZAÇÃO DO SISTEMA ===")
    
    # 1. Carregar Infraestrutura (Servidores, Técnicos, Janelas, Apps)
    servers, workers = initialize_infrastructure_from_csv()
    
    # 2. Carregar CVEs do CSV (Dados Reais!)
    # Substituímos o generate_cves_for_real_infra por isto:
    cves = load_cves("data/cves.csv")
    
    if not cves:
        print("⚠️  Aviso: Nenhuma CVE carregada. O planeamento será vazio.")
        return

    # 3. Processar Lógica de Negócio (Prioridades e Filtros)
    tasks_to_plan = prepare_patching_tasks(cves, servers)
    print(f"-> Tarefas validadas para agendamento: {len(tasks_to_plan)}")

    # 4. Executar Algoritmo de Planeamento
    final_schedule = create_simple_schedule(tasks_to_plan, workers)
    
    # 5. Exportar Resultados
    export_schedule_report(final_schedule, len(tasks_to_plan))

if __name__ == "__main__":
    main()