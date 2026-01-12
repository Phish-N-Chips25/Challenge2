# src/emergency.py
from typing import List, Tuple, Dict, Set
from .domain import PatchTask, CVE, Server, Software, Worker, FailedTask
from .logic import get_patch_duration, calculate_priority, is_server_available, is_worker_available, LEVEL_RANK

# --- CONFIGURAÇÃO DE LEIS LABORAIS ---
MAX_DAILY_NORMAL = 10
MAX_DAILY_ONCALL = 12
MAX_WEEKLY_NORMAL = 40
MAX_WEEKLY_ONCALL = 48

# ==========================================
# FUNÇÕES AUXILIARES
# ==========================================

def get_daily_workload(worker: Worker, target_day: int, schedule: List[PatchTask]) -> int:
    """Calcula quantas horas o técnico já tem agendadas para um dia específico."""
    total = 0
    for t in schedule:
        if worker not in t.workers: continue
        if (t.start_time // 24) == target_day:
            total += (t.end_time - t.start_time)
    return total

def get_weekly_workload(worker: Worker, target_hour: int, schedule: List[PatchTask]) -> int:
    """Calcula horas totais na semana onde cai a 'target_hour'."""
    target_week = target_hour // 168
    total = 0
    for t in schedule:
        if worker not in t.workers: continue
        if (t.start_time // 168) == target_week:
            total += (t.end_time - t.start_time)
    return total

def get_downstream_tasks(parent_task: PatchTask, schedule: List[PatchTask]) -> List[PatchTask]:
    """Encontra dependentes para cascata."""
    dependents = []
    parent_chain = parent_task.server.chain_id
    parent_cve = parent_task.cve.id
    parent_rank = parent_task.server.env_rank
    for t in schedule:
        if t.server.chain_id == parent_chain and t.cve.id == parent_cve:
            if t.server.env_rank > parent_rank:
                dependents.append(t)
    return dependents

def attempt_reschedule(task: PatchTask, schedule: List[PatchTask], servers: List[Server], workers: List[Worker], max_hours: int, pipeline_constraints: Dict[Tuple[str, str, str], int]) -> bool:
    """FASE 2: TETRIS DE RECUPERAÇÃO."""
    server = task.server
    cve = task.cve
    duration = get_patch_duration(cve.severity)
    
    start_search = 0
    if server.environment == "UAT":
        start_search = pipeline_constraints.get((server.chain_id, cve.id, "DEV"))
        if start_search is None: return False 
    elif server.environment == "PROD":
        start_search = pipeline_constraints.get((server.chain_id, cve.id, "UAT"))
        if start_search is None: return False 

    capable_candidates = []
    for w in workers:
        if server.id not in w.authorized_server_ids: continue
        if hasattr(w, 'skills') and task.software.id not in w.skills: continue
        capable_candidates.append(w)

    if len(capable_candidates) < cve.operators_required: return False

    scheduled = False
    
    for hour in range(start_search, max_hours):
        if scheduled: break
        end_time = hour + duration
        current_day = hour // 24
        
        if not is_server_available(server, hour, duration): continue
        
        conflicts_srv = any(
            t.server.id == server.id and not (t.end_time <= hour or t.start_time >= end_time)
            for t in schedule
        )
        if conflicts_srv: continue
        
        # Seleção de candidatos disponíveis na hora
        available_now = []
        for w in capable_candidates:
            if not is_worker_available(w, hour, duration): continue
            
            is_busy = any(
                w in t.workers and not (t.end_time <= hour or t.start_time >= end_time)
                for t in schedule
            )
            if is_busy: continue

            daily_limit = MAX_DAILY_ONCALL if w.is_on_call else MAX_DAILY_NORMAL
            if (get_daily_workload(w, current_day, schedule) + duration) > daily_limit: continue

            weekly_limit = MAX_WEEKLY_ONCALL if w.is_on_call else MAX_WEEKLY_NORMAL
            if (get_weekly_workload(w, hour, schedule) + duration) > weekly_limit: continue
            
            available_now.append(w)

        final_team = []
        if server.environment == "PROD":
            seniors = [w for w in available_now if w.level == "Senior"]
            if not seniors: continue
            seniors.sort(key=lambda w: get_weekly_workload(w, hour, schedule))
            final_team.append(seniors[0])
            needed_others = cve.operators_required - 1
            if needed_others > 0:
                others = [w for w in available_now if w.id != seniors[0].id]
                others.sort(key=lambda w: (LEVEL_RANK.get(w.level, 99), get_weekly_workload(w, hour, schedule)))
                if len(others) >= needed_others:
                    final_team.extend(others[:needed_others])
                else:
                    continue
        else:
            available_now.sort(key=lambda w: (LEVEL_RANK.get(w.level, 99), get_weekly_workload(w, hour, schedule)))
            if len(available_now) >= cve.operators_required:
                final_team = available_now[:cve.operators_required]
            else:
                continue
        
        if len(final_team) == cve.operators_required:
            task.start_time = hour
            task.end_time = end_time
            task.workers = final_team 
            task.rto_violation = duration > server.rto_hours 
            schedule.append(task)
            pipeline_constraints[(server.chain_id, cve.id, server.environment)] = end_time
            scheduled = True
            print(f"      ♻️  SALVO! {task.server.id} reagendado para {hour}h-{end_time}h.")

    return scheduled

# ==========================================
# FUNÇÃO PRINCIPAL
# ==========================================

def solve_emergency(current_schedule: List[PatchTask], emergency_cve: CVE, servers: List[Server], workers: List[Worker], max_hours: int) -> Tuple[bool, List[PatchTask], List[FailedTask]]:
    """HEURÍSTICA DE EMERGÊNCIA (Segura: 1 Senior Min em PROD)."""
    print(f"\n🚨 [EMERGÊNCIA] A tentar agendar {emergency_cve.id} (Prio Ajustada: {emergency_cve.final_priority_score:.2f})...")
    
    final_failures = [] 
    targets = []
    for srv in servers:
        for soft in srv.installed_software:
            if soft.id == emergency_cve.affected_software_id:
                targets.append((srv, soft))
    targets.sort(key=lambda x: x[0].env_rank)
    
    new_tasks_created = []
    displaced_tasks_objects: List[PatchTask] = [] 
    chain_completion_times = {} 
    failed_chains = set()
    global_success = True
    
    KILL_BUFFER = 2.0

    for server, software in targets:
        if server.chain_id in failed_chains:
            print(f"   🚫 Ignorado {server.id}: Dependência anterior falhou.")
            final_failures.append(FailedTask(emergency_cve, server, "Zero Day: Falha na Dependência (Pipeline)"))
            continue

        duration = get_patch_duration(emergency_cve.severity)
        scheduled_this_stage = False
        is_rto_breach = duration > server.rto_hours
        
        start_search = 0
        if server.environment == "UAT":
            prev_end = chain_completion_times.get((server.chain_id, "DEV"))
            if prev_end is None:
                failed_chains.add(server.chain_id)
                final_failures.append(FailedTask(emergency_cve, server, "Zero Day: Aguarda DEV (Falhou)"))
                continue
            start_search = prev_end
        elif server.environment == "PROD":
            prev_end = chain_completion_times.get((server.chain_id, "UAT"))
            if prev_end is None:
                failed_chains.add(server.chain_id)
                final_failures.append(FailedTask(emergency_cve, server, "Zero Day: Aguarda UAT (Falhou)"))
                continue
            start_search = prev_end

        capable_candidates = []
        for w in workers:
            if server.id not in w.authorized_server_ids: continue
            if hasattr(w, 'skills') and software.id not in w.skills: continue
            capable_candidates.append(w)
        
        if len(capable_candidates) < emergency_cve.operators_required:
            print(f"   🚫 Falha {server.id}: Sem técnicos qualificados.")
            failed_chains.add(server.chain_id)
            final_failures.append(FailedTask(emergency_cve, server, "Zero Day: Sem técnicos com Skill/Auth"))
            continue

        for hour in range(start_search, max_hours):
            if scheduled_this_stage: break
            end_time = hour + duration
            current_day = hour // 24
            
            if not is_server_available(server, hour, duration): continue
            
            # --- CONFLITOS NO SERVIDOR ---
            conflicts_on_server = any(
                t.server.id == server.id and not (t.end_time <= hour or t.start_time >= end_time)
                for t in current_schedule
            )
            tasks_to_displace = [
                t for t in current_schedule 
                if t.server.id == server.id and not (t.end_time <= hour or t.start_time >= end_time)
            ]
            can_displace = all(
                t.cve.final_priority_score < (emergency_cve.final_priority_score - KILL_BUFFER) 
                for t in tasks_to_displace
            )
            if conflicts_on_server and not can_displace: continue
            
            # --- SELEÇÃO DE EQUIPA (COM TROCA EM DIAS CHEIOS) ---
            available_now = []
            for w in capable_candidates:
                if not is_worker_available(w, hour, duration): continue
                
                # 1. Identificar conflitos deste worker
                w_tasks_conflict = [
                    t for t in current_schedule 
                    if w in t.workers and not (t.end_time <= hour or t.start_time >= end_time)
                ]
                
                # 2. Verificar se os conflitos podem ser mortos
                can_kill_worker_tasks = False
                if w_tasks_conflict:
                    if all(t.cve.final_priority_score < (emergency_cve.final_priority_score - KILL_BUFFER) for t in w_tasks_conflict):
                        can_kill_worker_tasks = True
                    else:
                        continue # Não pode matar tarefa do worker -> Worker Ocupado
                
                # 3. Calcular Carga "Líquida" (Descontando as tarefas que vamos matar)
                daily_limit = MAX_DAILY_ONCALL if w.is_on_call else MAX_DAILY_NORMAL
                current_daily_load = get_daily_workload(w, current_day, current_schedule)
                
                # Se vamos matar tarefas, as horas delas deixam de contar!
                if can_kill_worker_tasks:
                    hours_freed = sum((t.end_time - t.start_time) for t in w_tasks_conflict if (t.start_time // 24) == current_day)
                    adjusted_daily_load = current_daily_load - hours_freed
                else:
                    adjusted_daily_load = current_daily_load

                if (adjusted_daily_load + duration) > daily_limit: continue

                weekly_limit = MAX_WEEKLY_ONCALL if w.is_on_call else MAX_WEEKLY_NORMAL
                current_weekly_load = get_weekly_workload(w, hour, current_schedule)
                
                if can_kill_worker_tasks:
                     hours_freed_weekly = sum((t.end_time - t.start_time) for t in w_tasks_conflict)
                     adjusted_weekly_load = current_weekly_load - hours_freed_weekly
                else:
                     adjusted_weekly_load = current_weekly_load

                if (adjusted_weekly_load + duration) > weekly_limit: continue

                # 4. Adicionar à lista de disponíveis
                available_now.append({"worker": w, "tasks_to_kill": w_tasks_conflict})

            # --- CONSTRUÇÃO DA EQUIPA ---
            final_team_candidates = []
            
            if server.environment == "PROD":
                seniors = [x for x in available_now if x["worker"].level == "Senior"]
                if not seniors: continue 
                seniors.sort(key=lambda x: len(x["tasks_to_kill"]))
                final_team_candidates.append(seniors[0])
                
                needed_others = emergency_cve.operators_required - 1
                if needed_others > 0:
                    others = [x for x in available_now if x["worker"].id != seniors[0]["worker"].id]
                    others.sort(key=lambda x: (LEVEL_RANK.get(x["worker"].level, 99), len(x["tasks_to_kill"])))
                    if len(others) >= needed_others:
                        final_team_candidates.extend(others[:needed_others])
                    else:
                        continue
            else:
                available_now.sort(key=lambda x: (LEVEL_RANK.get(x["worker"].level, 99), len(x["tasks_to_kill"])))
                if len(available_now) >= emergency_cve.operators_required:
                    final_team_candidates = available_now[:emergency_cve.operators_required]
                else:
                    continue

            # Confirmar Agendamento
            final_workers = [x["worker"] for x in final_team_candidates]
            
            # Usar Dicionário por ID para evitar "unhashable PatchTask"
            victims_map = {id(t): t for t in tasks_to_displace}
            for x in final_team_candidates:
                for t in x["tasks_to_kill"]:
                    victims_map[id(t)] = t
            
            for v in victims_map.values():
                if v in current_schedule:
                    family = [v] + get_downstream_tasks(v, current_schedule)
                    for member in family:
                        if member in current_schedule:
                            current_schedule.remove(member)
                            displaced_tasks_objects.append(member)
                            print(f"   👋 Desalojado temporariamente: {member.server.id} ({member.cve.id})")

            new_task = PatchTask(emergency_cve, server, software, final_workers, hour, end_time, rto_violation=is_rto_breach)
            current_schedule.append(new_task)
            new_tasks_created.append(new_task)
            
            chain_completion_times[(server.chain_id, server.environment)] = end_time
            scheduled_this_stage = True
            
            print(f"   ✅ Agendado Emergência em {server.id} ({hour}h-{end_time}h)")
        
        if not scheduled_this_stage:
            print(f"   ❌ Falha Crítica na Emergência em {server.id}.")
            failed_chains.add(server.chain_id)
            final_failures.append(FailedTask(emergency_cve, server, "Zero Day: Não foi possível agendar (Sem Recursos/Janela)"))
            
    if not new_tasks_created:
        print("   ⚠️ Rollback: Restaurando calendário original.")
        for t in displaced_tasks_objects:
            current_schedule.append(t)
        # [CORREÇÃO] Retornar as falhas reais em vez de lista vazia
        return False, [], final_failures

    print(f"\n🚑 A tentar salvar {len(displaced_tasks_objects)} tarefas desalojadas...")
    displaced_tasks_objects.sort(key=lambda x: (x.server.env_rank, x.start_time))
    pipeline_fix_constraints = {}
    
    for task in displaced_tasks_objects:
        saved = attempt_reschedule(task, current_schedule, servers, workers, max_hours, pipeline_fix_constraints)
        if not saved:
            msg = f"Desalojado por Emergência {emergency_cve.id} (Sem vaga alternativa)"
            final_failures.append(FailedTask(task.cve, task.server, msg)) 
            print(f"      💀 Falhou definitivamente: {task.server.id}")
            
    return True, displaced_tasks_objects, final_failures