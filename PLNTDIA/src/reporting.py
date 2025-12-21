# src/reporting.py
from .domain import PatchTask
from .logic import LEVEL_HOURLY_RATE

DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}

def export_schedule_report(schedule: list[PatchTask], total_requested: int, logs=None, filename="relatorio_final.txt"):
    """Gera o relatório completo com pipelines detalhados e carga diária/semanal."""
    
    scheduled_count = len(schedule)
    failed_count = total_requested - scheduled_count
    success_rate = (scheduled_count / total_requested * 100) if total_requested > 0 else 0

    # --- LÓGICA DE MÉTRICAS DE PIPELINE (Reposta conforme tinhas) ---
    pipeline_map = {} 
    for task in schedule:
        key = (task.server.chain_id, task.cve.id)
        if key not in pipeline_map:
            pipeline_map[key] = set()
        pipeline_map[key].add(task.server.environment)

    full_pipes, test_only, dev_only = 0, 0, 0
    for envs in pipeline_map.values():
        if {"DEV", "UAT", "PROD"}.issubset(envs): full_pipes += 1
        elif {"DEV", "UAT"}.issubset(envs): test_only += 1
        elif "DEV" in envs: dev_only += 1

    # --- LÓGICA DE CARGA DIÁRIA E SEMANAL ---
    worker_stats = {}
    for task in schedule:
        duration = task.end_time - task.start_time
        day_abs = task.start_time // 24
        week_idx = task.start_time // 168
        day_in_week = day_abs % 7
        
        for w in task.workers:
            if w.name not in worker_stats:
                worker_stats[w.name] = {"weeks": {}, "days": {}, "level": w.level}
            
            # Acumular por semana
            worker_stats[w.name]["weeks"][week_idx] = worker_stats[w.name]["weeks"].get(week_idx, 0) + duration
            # Acumular por dia (usamos o dia absoluto para não misturar Segundas de semanas diferentes)
            worker_stats[w.name]["days"][day_abs] = worker_stats[w.name]["days"].get(day_abs, 0) + duration

    with open(filename, "w", encoding="utf-8") as f:
        if logs:
            f.write("=== HISTÓRICO DE EXECUÇÃO ===\n")
            for line in logs: f.write(line + "\n")
            f.write("\n" + "="*40 + "\n\n")
            
        def log(text): 
            f.write(text + "\n")
            print(text)

        log("="*40)
        log("       RELATÓRIO DE GESTÃO DE PATCHING")
        log("="*40)
        
        log("\n--- ESTATÍSTICAS GERAIS ---")
        log(f"✅ Total de Patches Agendados: {scheduled_count}")
        log(f"⚠️  Total de Patches Falhados:  {failed_count}")
        log(f"📊 Taxa de Sucesso Global:    {success_rate:.1f}%")

        log("\n--- MÉTRICAS DE PIPELINE (Cadeia de Valor) ---")
        log(f"🚀 Pipelines Completos (DEV+UAT+PROD): {full_pipes}")
        log(f"🧪 Apenas Testes (DEV+UAT):           {test_only}")
        log(f"🛠️  Retidos em Dev (Apenas DEV):      {dev_only}")
        
        total_started = full_pipes + test_only + dev_only
        efficiency = (full_pipes / total_started * 100) if total_started > 0 else 0
        log(f"📈 Eficiência de Entrega em PROD:     {efficiency:.1f}%")

        log("\n--- ANÁLISE DE CARGA (DIÁRIA E SEMANAL) ---")
        total_plan_cost = 0.0
        for name in sorted(worker_stats.keys()):
            s = worker_stats[name]
            total_h = sum(s["weeks"].values())
            cost = total_h * LEVEL_HOURLY_RATE.get(s["level"], 0)
            total_plan_cost += cost
            
            log(f"👤 {name.ljust(15)} ({s['level']})")
            
            # Mostrar resumo semanal
            weeks_str = " | ".join([f"Sem {wk+1}: {hr}h" for wk, hr in sorted(s["weeks"].items())])
            log(f"   Semanal: {weeks_str}")
            
            # Mostrar detalhe diário (apenas dias com trabalho)
            days_detail = []
            for d_abs in sorted(s["days"].keys()):
                d_name = DAYS_MAP[d_abs % 7]
                hr = s["days"][d_abs]
                days_detail.append(f"{d_name}(D{d_abs}): {hr}h")
            log(f"   Diário:  " + " | ".join(days_detail))
            
            log(f"   Custo Total: {cost:,.2f}€")
            log("-" * 30)

        log(f"\n💰 CUSTO TOTAL ESTIMADO: {total_plan_cost:,.2f}€")

        log("\n" + "="*40)
        log("   DETALHE CRONOLÓGICO E PRIORIDADES")
        log("="*40)
        
        schedule.sort(key=lambda x: x.start_time)
        for task in schedule:
            d_idx = (task.start_time // 24) % 7
            h_start = task.start_time % 24
            h_end = task.end_time % 24
            
            log(f"🗓️  [{task.server.environment}] {DAYS_MAP[d_idx]} {h_start:02d}h-{h_end:02d}h | {task.cve.id}")
            log(f"    Prioridade: {task.cve.final_priority_score:.2f} | App: {task.software.id}")
            log(f"    Equipa:     " + ", ".join([f"{w.name} ({w.level})" for w in task.workers]))
            log("-" * 40)
            
    print(f"\n[SUCESSO] Relatório detalhado gerado em '{filename}'")