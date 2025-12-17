# Ficheiro: src/planner.py
from typing import List, Tuple
from .domain import Server, CVE, Software, Worker, PatchTask
from .logic import is_server_available, is_worker_available

def create_simple_schedule(
    tasks: List[Tuple[CVE, Server, Software]], 
    workers: List[Worker]
) -> List[PatchTask]:
    
    schedule = []
    
    # Ordenar por Prioridade
    sorted_tasks = sorted(tasks, key=lambda x: x[0].final_priority_score, reverse=True)
    
    print(f"-> A tentar agendar {len(sorted_tasks)} tarefas...")

    for cve, server, software in sorted_tasks:
        scheduled = False
        reason_fail = "Sem Janela de Servidor compatível"
        
        for absolute_hour in range(168):
            day = (absolute_hour // 24) % 7
            hour_of_day = absolute_hour % 24
            
            # A. Servidor disponível?
            if not is_server_available(server, day, hour_of_day, cve.estimated_fix_time):
                continue 
            
            reason_fail = "Staff Indisponível (Horário ou Permissão)"

            # B. Staff disponível?
            available_team = []
            for w in workers:
                # 1. VERIFICAR PERMISSÃO EXPLÍCITA (A tua regra)
                if server.id not in w.authorized_server_ids:
                    continue # Não tem permissão para este servidor

                # 2. VERIFICAR HORÁRIO
                if is_worker_available(w, day, hour_of_day, cve.estimated_fix_time):
                    available_team.append(w)
            
            # Temos gente suficiente?
            if len(available_team) >= cve.operators_required:
                # SUCESSO!
                
                # Selecionar TODOS os necessários
                chosen_workers = available_team[:cve.operators_required]
                
                new_task = PatchTask(
                    cve=cve,
                    server=server,
                    software=software,
                    workers=chosen_workers, # <--- Guardamos a lista (plural)
                    start_time=absolute_hour,
                    end_time=absolute_hour + cve.estimated_fix_time
                )
                schedule.append(new_task)
                scheduled = True
                break 
        
        if not scheduled:
            print(f"⚠️  FALHOU: {cve.id} no {server.id} -> Motivo: {reason_fail}")

    return schedule