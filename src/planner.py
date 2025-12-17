from typing import List, Tuple
from .domain import Server, CVE, Software, Worker, PatchTask
from .logic import is_server_available, is_worker_available

def create_simple_schedule(
    tasks: List[Tuple[CVE, Server, Software]], 
    workers: List[Worker]
) -> List[PatchTask]:
    
    schedule = []
    
    # 1. Ordenar tarefas por Prioridade (Críticos primeiro!)
    # A tupla é (cve, server, software). cve.final_priority_score já foi calculado no main.
    sorted_tasks = sorted(tasks, key=lambda x: x[0].final_priority_score, reverse=True)
    
    print(f"-> A tentar agendar {len(sorted_tasks)} tarefas por ordem de prioridade...")

    for cve, server, software in sorted_tasks:
        scheduled = False
        
        # 2. Percorrer a semana toda (Dia 0 a 6, Hora 0 a 23)
        # Total de horas numa semana = 168
        for absolute_hour in range(168):
            day = (absolute_hour // 24) % 7
            hour_of_day = absolute_hour % 24
            
            # A. O Servidor pode parar agora?
            if not is_server_available(server, day, hour_of_day, cve.estimated_fix_time):
                continue # Servidor ocupado ou fora de janela, tenta próxima hora
            
            # B. Existe algum Operário disponível?
            # Precisamos de encontrar N operários (cve.operators_required)
            available_team = []
            for w in workers:
                if is_worker_available(w, day, hour_of_day, cve.estimated_fix_time):
                    available_team.append(w)
            
            # Temos gente suficiente?
            if len(available_team) >= cve.operators_required:
                # SUCESSO! Encontrámos um horário.
                
                # Vamos simplificar e pegar no primeiro operário disponível
                chosen_worker = available_team[0] 
                
                new_task = PatchTask(
                    cve=cve,
                    server=server,
                    software=software,
                    worker=chosen_worker,
                    start_time=absolute_hour,
                    end_time=absolute_hour + cve.estimated_fix_time
                )
                schedule.append(new_task)
                scheduled = True
                break # Sai do loop das horas, passa para a próxima CVE
        
        if not scheduled:
            print(f"⚠️ IMPOSSÍVEL AGENDAR: {cve.id} no {server.id} (Não há coincidência de Janela + Staff)")

    return schedule