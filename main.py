from src.repository import get_mock_data
from src.logic import find_affected_servers, calculate_priority
from src.planner import create_simple_schedule 

# Mapeamento para ficar bonito no print
DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}

def main():
    filename = "relatorio_analise.txt"
    with open(filename, "w", encoding="utf-8") as f:
        def log(texto=""):
            print(texto)
            f.write(texto + "\n")

        log("=== 1. CARREGAMENTO E ANÁLISE ===")
        servers, cves, workers = get_mock_data()
        
        # Lista temporária para guardar o que precisa de ser feito
        # Formato: [(CVE, Server, Software), ...]
        tasks_to_plan = []

        for cve in cves:
            targets = find_affected_servers(cve, servers)
            for server, software in targets:
                # Calcular prioridade
                cve.final_priority_score = calculate_priority(cve, software)
                
                # Só adicionamos se respeitar o RTO (Regra Rígida)
                if cve.estimated_fix_time <= server.rto_hours:
                    tasks_to_plan.append((cve, server, software))
                else:
                    log(f"❌ DESCARTADO: {cve.id} excede RTO do {server.id}")

        log(f"Total de tarefas válidas para agendar: {len(tasks_to_plan)}\n")

        log("=== 2. AGENDAMENTO (GREEDY) ===")
        # Chama o nosso novo planner
        final_schedule = create_simple_schedule(tasks_to_plan, workers)
        
        log(f"Conseguimos agendar {len(final_schedule)} de {len(tasks_to_plan)} tarefas.\n")
        
        log("=== 3. PLANO FINAL ===")
        # Ordenar cronologicamente para ser fácil de ler
        final_schedule.sort(key=lambda x: x.start_time)
        
        for task in final_schedule:
            day_idx = (task.start_time // 24) % 7
            hour = task.start_time % 24
            day_name = DAYS_MAP[day_idx]
            
            log(f"🗓️  [{day_name} {hour:02d}h] {task.cve.id} ({task.cve.severity})")
            log(f"    Maquina: {task.server.id} | Soft: {task.software.id}")
            log(f"    Técnico: {task.worker.id}")
            log("-" * 30)

    print(f"\n[SUCESSO] Relatório gerado em '{filename}'")

if __name__ == "__main__":
    main()