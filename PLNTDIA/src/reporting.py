# src/reporting.py
from .domain import PatchTask

DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}

def export_schedule_report(schedule: list[PatchTask], total_requested: int, filename="relatorio_final.txt"):
    """Gera o ficheiro de texto com o resultado final."""
    
    scheduled_count = len(schedule)
    failed_count = total_requested - scheduled_count
    success_rate = (scheduled_count / total_requested * 100) if total_requested > 0 else 0

    with open(filename, "w", encoding="utf-8") as f:
        def log(text): 
            f.write(text + "\n")
            print(text)

        log("=== RELATÓRIO DE EXECUÇÃO ===")
        log(f"✅ Agendadas: {scheduled_count}")
        log(f"⚠️  Falhadas:  {failed_count}")
        log(f"📊 Taxa de Sucesso: {success_rate:.1f}%\n")
        
        log("=== DETALHE DO PLANO (CRONOLÓGICO) ===")
        
        # Ordenar
        schedule.sort(key=lambda x: x.start_time)

        for task in schedule:
            day_idx = (task.start_time // 24) % 7
            hour = task.start_time % 24
            day_name = DAYS_MAP[day_idx]
            end_h = task.end_time % 24
            
            # Lista de nomes (agora temos o worker.name disponível do CSV)
            team_names = ", ".join([w.name for w in task.workers])

            log(f"🗓️  [{day_name} {hour:02d}h-{end_h:02d}h] {task.cve.id} ({task.cve.severity})")
            log(f"    Alvo: {task.server.id} ({task.server.os_name}) -> {task.software.id}")
            log(f"    Staff: {team_names}")
            log("-" * 30)
            
    print(f"\n[SUCESSO] Relatório guardado em '{filename}'")