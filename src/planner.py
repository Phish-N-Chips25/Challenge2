from typing import List, Tuple, Dict, Set
from .domain import Server, CVE, Software, Worker, PatchTask
from .logic import is_server_available, is_worker_available

def create_simple_schedule(
    tasks: List[Tuple[CVE, Server, Software]], 
    workers: List[Worker]
) -> List[PatchTask]:
    
    schedule = []
    
    # --- MAPA DE OCUPAÇÃO (REALISMO) ---
    # Guardamos quem/o que está ocupado numa determinada hora absoluta.
    # Sets contêm strings tipo "WorkerID_Hora" ou "ServerID_Hora"
    busy_workers: Set[str] = set()
    busy_servers: Set[str] = set()

    # Ordenar por Prioridade
    sorted_tasks = sorted(tasks, key=lambda x: x[0].final_priority_score, reverse=True)
    
    print(f"-> A tentar agendar {len(sorted_tasks)} tarefas com restrições FÍSICAS...")

    for cve, server, software in sorted_tasks:
        scheduled = False
        reason_fail = "Sem Janela de Servidor"
        
        # Percorrer todas as horas da semana (0 a 167)
        for absolute_hour in range(168):
            day = (absolute_hour // 24) % 7
            hour_of_day = absolute_hour % 24
            duration = cve.estimated_fix_time
            
            # --- 1. VERIFICAÇÃO DO SERVIDOR ---
            
            # A. Janela de Manutenção (A porta está aberta?)
            if not is_server_available(server, day, hour_of_day, duration):
                continue 
            
            # B. O Servidor já está ocupado com outro patch nesta hora?
            is_server_busy = False
            for h in range(absolute_hour, absolute_hour + duration):
                if f"{server.id}_{h}" in busy_servers:
                    is_server_busy = True
                    break
            
            if is_server_busy:
                reason_fail = "Servidor Ocupado (Colisão de Patches)"
                continue # Tenta próxima hora

            reason_fail = "Staff Indisponível (Permissão, Turno ou Ocupação)"

            # --- 2. VERIFICAÇÃO DO STAFF ---
            available_team = []
            for w in workers:
                # A. Permissão (RBAC)
                if server.id not in w.authorized_server_ids:
                    continue

                # B. Turno (Está a trabalhar?)
                if not is_worker_available(w, day, hour_of_day, duration):
                    continue
                
                # C. Ocupação (Já está a fazer outra coisa?) <--- A CORREÇÃO
                is_worker_busy = False
                for h in range(absolute_hour, absolute_hour + duration):
                    if f"{w.id}_{h}" in busy_workers:
                        is_worker_busy = True
                        break
                
                if not is_worker_busy:
                    available_team.append(w)
            
            # Temos gente suficiente?
            if len(available_team) >= cve.operators_required:
                # SUCESSO! AGENDAR!
                
                chosen_workers = available_team[:cve.operators_required]
                
                # MARCAR OCUPAÇÃO (Reservar os recursos)
                # 1. Marcar Servidor Ocupado
                for h in range(absolute_hour, absolute_hour + duration):
                    busy_servers.add(f"{server.id}_{h}")
                
                # 2. Marcar Técnicos Ocupados
                for w in chosen_workers:
                    for h in range(absolute_hour, absolute_hour + duration):
                        busy_workers.add(f"{w.id}_{h}")

                new_task = PatchTask(
                    cve=cve,
                    server=server,
                    software=software,
                    workers=chosen_workers,
                    start_time=absolute_hour,
                    end_time=absolute_hour + duration
                )
                schedule.append(new_task)
                scheduled = True
                break 
        
        if not scheduled:
            # Descomenta o print se quiseres ver o spam de falhas
            # print(f"⚠️  FALHOU: {cve.id} ({server.id}) -> {reason_fail}")
            pass

    return schedule