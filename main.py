# Ficheiro: main.py
from src.repository import generate_stress_test_data # <--- MUDANÇA AQUI
from src.logic import find_affected_servers, calculate_priority
from src.planner import create_simple_schedule 

# Mapeamento para ficar bonito no print
DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}

def main():
    filename = "relatorio_analise.txt"
    with open(filename, "w", encoding="utf-8") as f:
        
        # Função auxiliar de log (Escreve no terminal e no ficheiro)
        def log(texto=""):
            print(texto)
            f.write(texto + "\n")

        log("=== 1. STRESS TEST (GERAÇÃO AUTOMÁTICA) ===")
        
        # MUDANÇA AQUI: Gerar cenário complexo em vez de usar os dados manuais
        # Podes brincar com estes números (ex: 100 CVEs, 3 Workers) para ver o sistema falhar
        servers, cves, workers = generate_stress_test_data(n_servers=20, n_cves=50, n_workers=5)
        
        log(f"-> Cenário Gerado: {len(servers)} Servidores | {len(cves)} CVEs | {len(workers)} Técnicos\n")
        
        # Lista temporária para guardar o que precisa de ser feito
        # Formato: [(CVE, Server, Software), ...]
        tasks_to_plan = []

        log("-> A calcular prioridades e verificar RTO...")
        
        for cve in cves:
            targets = find_affected_servers(cve, servers)
            
            # Se a CVE não afetar nenhum servidor, passamos à frente
            if not targets:
                continue

            for server, software in targets:
                # Calcular prioridade
                cve.final_priority_score = calculate_priority(cve, software)
                
                # Só adicionamos se respeitar o RTO (Regra Rígida)
                if cve.estimated_fix_time <= server.rto_hours:
                    tasks_to_plan.append((cve, server, software))
                else:
                    # Nota: Com muitos dados, isto pode encher o log, descomenta se quiseres ver
                    # log(f"❌ DESCARTADO: {cve.id} excede RTO do {server.id}")
                    pass

        log(f"-> Total de tarefas válidas identificadas: {len(tasks_to_plan)}\n")

        log("=== 2. AGENDAMENTO (GREEDY) ===")
        # Chama o nosso planner
        final_schedule = create_simple_schedule(tasks_to_plan, workers)
        
        total_tasks = len(tasks_to_plan)
        scheduled_tasks = len(final_schedule)
        failed_tasks = total_tasks - scheduled_tasks
        
        log(f"\nRESUMO DO PLANEAMENTO:")
        log(f"✅ Agendadas: {scheduled_tasks}")
        log(f"⚠️  Falhadas:  {failed_tasks}")
        log(f"📊 Taxa de Sucesso: {(scheduled_tasks/total_tasks)*100:.1f}%\n")
        
        log("=== 3. PLANO FINAL (Amostra) ===")
        # Ordenar cronologicamente
        final_schedule.sort(key=lambda x: x.start_time)
        
        # Mostrar apenas as primeiras 20 para não encher o ecrã se forem muitas
        for i, task in enumerate(final_schedule):
            # Formatação de dia e hora
            day_idx = (task.start_time // 24) % 7
            hour = task.start_time % 24
            day_name = DAYS_MAP[day_idx]
            end_abs = task.end_time
            end_h = end_abs % 24
            
            # Formatar nomes da equipa
            team_names = ", ".join([w.id for w in task.workers])
            
            log(f"🗓️  [{day_name} {hour:02d}h-{end_h:02d}h] {task.cve.id} ({task.cve.severity})")
            log(f"    Maquina: {task.server.id} | Soft: {task.software.id}")
            log(f"    Equipa:  {team_names}")
            log("-" * 30)

    print(f"\n[SUCESSO] Relatório gerado em '{filename}'")

if __name__ == "__main__":
    main()