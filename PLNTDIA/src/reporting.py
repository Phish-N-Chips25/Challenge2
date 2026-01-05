# src/reporting.py
import json
import os
from datetime import datetime, timedelta
from .domain import PatchTask, FailedTask  # <--- [ALTERADO] Adicionado FailedTask
from .logic import LEVEL_HOURLY_RATE

DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}

# [ALTERADO] Adicionado 'failures: list[FailedTask]' como segundo argumento
def export_schedule_report(schedule: list[PatchTask], failures: list[FailedTask], total_requested: int, logs=None, filename="relatorio_final.txt"):
    """Gera o relatório completo com pipelines detalhados e carga diária/semanal."""
    
    scheduled_count = len(schedule)
    
    # [ALTERADO] Calculamos as falhas diretamente pelo tamanho da lista de falhas
    failed_count = len(failures) 
    
    success_rate = (scheduled_count / total_requested * 100) if total_requested > 0 else 0

    # [NOVO] Contar infrações de Soft RTO
    rto_breaches = sum(1 for t in schedule if t.rto_violation)

    # --- LÓGICA DE MÉTRICAS DE PIPELINE ---
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
            # Acumular por dia
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
        
        # [NOVO] Linha de alerta de RTO
        if rto_breaches > 0:
            log(f"🚨 Agendados com Violação de RTO: {rto_breaches} (Requerem Aprovação)")
            
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
            
            weeks_str = " | ".join([f"Sem {wk+1}: {hr}h" for wk, hr in sorted(s["weeks"].items())])
            log(f"   Semanal: {weeks_str}")
            
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
            
            # [NOVO] Lógica visual para RTO Breach
            icon = "🗓️ "
            alert_tag = ""
            if task.rto_violation:
                icon = "🚨"
                alert_tag = " | [RTO BREACH]"
            
            log(f"{icon} [{task.server.environment}] {DAYS_MAP[d_idx]} {h_start:02d}h-{h_end:02d}h | {task.cve.id}{alert_tag}")
            log(f"    Prioridade: {task.cve.final_priority_score:.2f} | App: {task.software.id}")
            log(f"    Equipa:     " + ", ".join([f"{w.name} ({w.level})" for w in task.workers]))
            log("-" * 40)
            
        # [NOVO] SECÇÃO DE FALHAS DETALHADA
        if failures:
            log("\n" + "="*40)
            log("   ❌ RELATÓRIO DE TAREFAS FALHADAS")
            log("="*40)
            for fail in failures:
                log(f"❌ [{fail.server.environment}] {fail.server.id} | {fail.cve.id}")
                log(f"   MOTIVO: {fail.reason}")
                log("-" * 40)
            
    print(f"\n[SUCESSO] Relatório detalhado gerado em '{filename}'")

def export_schedule_json(schedule: list[PatchTask], failures: list[FailedTask] | None = None, filename="web/schedule.json"):
    """
    [NOVO] Exporta para JSON compatível com FullCalendar.
    Permite visualizar o plano no browser.
    """
    # Criar pasta web se não existir
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    events = []
    
    #  - Calculamos a próxima segunda-feira como base
    today = datetime.now()
    days_ahead = 7 - today.weekday()
    base_date = today.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)

    for task in schedule:
        # Converter horas absolutas em Datas Reais (ISO 8601)
        start_dt = base_date + timedelta(hours=task.start_time)
        end_dt = base_date + timedelta(hours=task.end_time)
        
        # Cores por Ambiente (Visualização Rápida)
        bg_color = "#3788d8" # Default Blue
        border_color = "#3788d8"
        
        if task.server.environment == "PROD": 
            bg_color = "#d9534f" # Vermelho
            border_color = "#d9534f"
        elif task.server.environment == "UAT": 
            bg_color = "#f0ad4e" # Laranja
            border_color = "#f0ad4e"
        elif task.server.environment == "DEV": 
            bg_color = "#5cb85c" # Verde
            border_color = "#5cb85c"
            
        title = f"{task.server.id}"
        
        # Se houve violação de RTO, destacamos a Preto
        if task.rto_violation:
            bg_color = "#000000" 
            border_color = "#d9534f"
            title = "⚠️ " + title

        events.append({
            "title": title,
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
            "backgroundColor": bg_color,
            "borderColor": border_color,
            # Guardamos detalhes na descrição para o popup do calendário
            "description": f"CVE: {task.cve.id}\nApp: {task.software.id}\nTechs: {', '.join([w.name for w in task.workers])}",
            "extendedProps": {
                "environment": task.server.environment,
                "priority": task.cve.final_priority_score
            }
        })

    failures_payload = []
    if failures:
        for fail in failures:
            failures_payload.append({
                "server": {
                    "id": fail.server.id,
                    "environment": fail.server.environment,
                },
                "cve": {"id": fail.cve.id},
                "reason": fail.reason,
            })

    payload = {
        "events": events,
        "failures": failures_payload,
    }

    with open(filename, "w", encoding='utf-8') as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)
    
    print(f"[JSON] Dados para Frontend exportados para '{filename}'")