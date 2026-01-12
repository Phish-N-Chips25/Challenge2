# src/planner.py
import random
from typing import List, Tuple, Dict, Set
from .domain import Server, CVE, Software, Worker, PatchTask, FailedTask
# [ATUALIZADO] Importamos check_labor_limits para consistência total com a Emergência
from .logic import (
    is_server_available, 
    is_worker_available, 
    get_patch_duration, 
    LEVEL_RANK, 
    LEVEL_HOURLY_RATE,
    check_labor_limits # <--- A função que garante que ninguém passa das 40h/48h
)

def calculate_fitness(schedule: List[PatchTask], total_tasks: int) -> float:
    """
    O CORAÇÃO DO AG: Quanto maior o score, melhor o plano.
    Equilibra: Prioridade, Bónus de Pipeline, Mentoria e Custo.
    """
    if not schedule: return 0.0
    
    score = 0.0
    pipelines_completos = set()
    total_cost = 0.0 
    workers_used = set() 

    for task in schedule:
        # 1. Recompensa por Prioridade (Severidade + EPSS)
        score += task.cve.final_priority_score
        
        # 2. Bónus por chegar a PROD (Incentiva fechar o ciclo)
        if task.server.environment == "PROD":
            score += 50
            pipelines_completos.add(f"{task.server.chain_id}_{task.cve.id}")
            
        # 3. BÓNUS MENTORIA (Equipa Mista)
        # Se a equipa tiver Juniores misturados com Mids/Seniores, ganha pontos extra.
        if len(task.workers) > 1:
            levels = [w.level for w in task.workers]
            for w in task.workers: workers_used.add(w.id) 
            if "Junior" in levels and ("Senior" in levels or "Mid" in levels):
                score += 30 
        else:
            for w in task.workers: workers_used.add(w.id)

        # Cálculo de Custo Financeiro
        duration = task.end_time - task.start_time
        for w in task.workers:
            hourly_rate = LEVEL_HOURLY_RATE.get(w.level, 0)
            total_cost += hourly_rate * duration
            
        # [NOVO] Penalização por Violação de RTO (Soft RTO)
        # Se a flag estiver ativa, penalizamos mas não "matamos" o plano.
        if task.rto_violation:
            score -= 500.0
            
    # 4. Recompensa extra por Pipelines Completos
    score += len(pipelines_completos) * 100

    # 5. Penalização por Custo (Preferimos planos mais baratos)
    score -= (total_cost / 100.0)
    
    # 6. Penalização por Técnicos Ociosos (Queremos a equipa toda a trabalhar)
    TOTAL_STAFF_COUNT = 10 
    missing_workers = TOTAL_STAFF_COUNT - len(workers_used)
    score -= (missing_workers * 100) 

    # 7. PENALIZAÇÃO "NUCLEAR" POR FALHAS DE AGENDAMENTO
    # Se uma tarefa ficar por fazer, a penalização é massiva.
    scheduled_count = len(schedule)
    failed_count = total_tasks - scheduled_count
    if failed_count > 0:
        score -= (failed_count * 100000.0)
        
    return score


def decode_chromosome(chromosome: List[int], tasks: List[Tuple], workers: List[Worker], max_hours: int) -> Tuple[List[PatchTask], List[FailedTask]]:
    """
    Transforma a 'ordem' (gene) num calendário real.
    
    ESTRUTURA:
    1. Multi-Pass Loop (Externo): Resolve dependências fora de ordem.
    2. Unified Search (Interno): Procura vaga ideal e vaga de recurso (fallback) no mesmo loop de horas.
    """
    schedule = []
    failures = [] 
    
    busy_workers: Set[str] = set()
    busy_servers: Set[str] = set()
    pipeline_success: Dict[Tuple[str, str, str], int] = {}

    worker_daily_load: Dict[Tuple[str, int], float] = {}
    worker_weekly_load: Dict[Tuple[str, int], float] = {}

    pending_tasks = [tasks[i] for i in chromosome]

    # [MANTIDO] Loop Multi-Pass para resolução de dependências (Seção 6.3 do Relatório)
    while True:
        progress_made = False 
        remaining_tasks = []  
        current_round_failures = {} 

        for task_tuple in pending_tasks:
            cve, server, software = task_tuple
            duration = get_patch_duration(cve.severity)
            min_start_hour = 0
            can_proceed = True
            fail_reason = "Sem disponibilidade (Recursos/Janela)" 
            
            # --- Lógica de Dependência (Cadeia de Valor) ---
            env, chain = server.environment, server.chain_id
            if env == "UAT":
                if (chain, cve.id, "DEV") in pipeline_success:
                    min_start_hour = pipeline_success[(chain, cve.id, "DEV")]
                else: 
                    can_proceed = False 
                    fail_reason = "Bloqueado: Aguarda DEV"
            elif env == "PROD":
                if (chain, cve.id, "UAT") in pipeline_success:
                    min_start_hour = pipeline_success[(chain, cve.id, "UAT")]
                else: 
                    can_proceed = False
                    fail_reason = "Bloqueado: Aguarda UAT"

            if not can_proceed: 
                remaining_tasks.append(task_tuple)
                current_round_failures[f"{cve.id}_{server.id}"] = fail_reason
                continue

            scheduled = False
            best_rto_breach_option = None # "Bolso" para guardar a opção de recurso (Violação RTO)

            # [ALTERADO] ESTRATÉGIA DE PROCURA UNIFICADA (Smart Greedy)
            # Percorre as horas uma única vez.
            # - Se encontrar vaga perfeita (Sem violação) -> Agenda e pára.
            # - Se encontrar vaga imperfeita (Com violação) -> Guarda e continua a procurar melhor.
            for absolute_hour in range(min_start_hour, max_hours):
                if scheduled: break
                
                # Verificar Disponibilidade do Servidor
                if not is_server_available(server, absolute_hour, duration): continue
                if any(f"{server.id}_{h}" in busy_servers for h in range(absolute_hour, absolute_hour + duration)):
                    continue
                
                current_day = absolute_hour // 24
                current_week = absolute_hour // 168

                # 1. Pool de Candidatos (Verifica Skills, Horário e Leis Laborais)
                available_pool = []
                for w in workers:
                    if server.id not in w.authorized_server_ids: continue
                    if hasattr(w, 'skills') and software.id not in w.skills: continue
                    if not is_worker_available(w, absolute_hour, duration): continue

                    hours_today = worker_daily_load.get((w.id, current_day), 0)
                    hours_this_week = worker_weekly_load.get((w.id, current_week), 0)
                    
                    if not check_labor_limits(w, duration, hours_today, hours_this_week):
                        continue

                    if not any(f"{w.id}_{h}" in busy_workers for h in range(absolute_hour, absolute_hour + duration)):
                        available_pool.append(w)
                
                if len(available_pool) < cve.operators_required: continue

                # 2. Seleção de Equipa
                potential_chosen = []
                seniors = [w for w in available_pool if w.level == "Senior"]
                others = [w for w in available_pool if w.level != "Senior"] 

                # Ordenar por carga para balanceamento
                seniors.sort(key=lambda w: worker_weekly_load.get((w.id, current_week), 0))
                others.sort(key=lambda w: (LEVEL_RANK.get(w.level, 0), worker_weekly_load.get((w.id, current_week), 0)))

                if server.environment == "PROD":
                    if not seniors: continue 
                    potential_chosen.append(seniors.pop(0))
                    slots_needed = cve.operators_required - 1
                    if slots_needed > 0:
                        pool_rest = others + seniors 
                        if len(pool_rest) < slots_needed: continue
                        potential_chosen.extend(pool_rest[:slots_needed])
                else:
                    pool_all = others + seniors 
                    potential_chosen = pool_all[:cve.operators_required]

                if len(potential_chosen) == cve.operators_required:
                    # Temos Vaga e Equipa. Decisão:
                    is_rto_violation = (duration > server.rto_hours)

                    if not is_rto_violation:
                        # CENÁRIO IDEAL: Cumpre RTO. Agendar imediatamente.
                        end_time = absolute_hour + duration
                        
                        # Commit
                        for h in range(absolute_hour, end_time): busy_servers.add(f"{server.id}_{h}")
                        for w in potential_chosen:
                            for h in range(absolute_hour, end_time): busy_workers.add(f"{w.id}_{h}")
                            worker_daily_load[(w.id, current_day)] = worker_daily_load.get((w.id, current_day), 0) + duration
                            worker_weekly_load[(w.id, current_week)] = worker_weekly_load.get((w.id, current_week), 0) + duration

                        schedule.append(PatchTask(cve, server, software, potential_chosen, absolute_hour, end_time, rto_violation=False))
                        pipeline_success[(chain, cve.id, env)] = end_time
                        scheduled = True
                        progress_made = True
                        break # Sai do loop de procura, tarefa resolvida.
                    
                    else:
                        # CENÁRIO IMPERFEITO: Viola RTO.
                        # Se ainda não temos uma opção de recurso guardada, guardamos esta.
                        # Continuamos o loop na esperança de encontrar um cenário ideal mais à frente.
                        if best_rto_breach_option is None:
                            best_rto_breach_option = {
                                "hour": absolute_hour,
                                "workers": list(potential_chosen),
                                "day": current_day,
                                "week": current_week
                            }

            # --- FIM DO LOOP DE PROCURA ---
            
            # Se não agendou o ideal, mas temos um "Plano B" (com violação RTO) guardado:
            if not scheduled and best_rto_breach_option:
                opt = best_rto_breach_option
                end_time = opt["hour"] + duration
                
                for h in range(opt["hour"], end_time): busy_servers.add(f"{server.id}_{h}")
                for w in opt["workers"]:
                    for h in range(opt["hour"], end_time): busy_workers.add(f"{w.id}_{h}")
                    worker_daily_load[(w.id, opt["day"])] = worker_daily_load.get((w.id, opt["day"]), 0) + duration
                    worker_weekly_load[(w.id, opt["week"])] = worker_weekly_load.get((w.id, opt["week"]), 0) + duration
                
                schedule.append(PatchTask(cve, server, software, opt["workers"], opt["hour"], end_time, rto_violation=True))
                pipeline_success[(chain, cve.id, env)] = end_time
                scheduled = True
                progress_made = True

            if not scheduled:
                remaining_tasks.append(task_tuple)
                if f"{cve.id}_{server.id}" not in current_round_failures:
                    current_round_failures[f"{cve.id}_{server.id}"] = "Sem Recursos/Janela"
        
        # Lógica Multi-Pass: Se não houve progresso nesta volta completa, paramos.
        if not progress_made:
            for t_fail in remaining_tasks:
                cve_f, server_f, _ = t_fail
                reason = current_round_failures.get(f"{cve_f.id}_{server_f.id}", "Desconhecido")
                failures.append(FailedTask(cve_f, server_f, reason))
            break
        
        pending_tasks = remaining_tasks
        if not pending_tasks:
            break 

    return schedule, failures

def create_genetic_schedule(tasks, workers, max_hours, pop_size=100, generations=150):
    """
    Função Mestra que coordena a evolução (Aleatória, mas com Decode Inteligente).
    """
    num_tasks = len(tasks)
    # [ALTERADO] Agora retorna 3 valores (Schedule, Failures, Logs)
    if num_tasks == 0: return [], [], [] 

    logs = []
    # População 100% Aleatória
    population = [random.sample(range(num_tasks), num_tasks) for _ in range(pop_size)]
    
    best_schedule = []
    best_failures = [] # [NOVO] Variável para guardar as falhas do melhor plano
    best_fitness = -float('inf') 

    msg_start = f"-> A iniciar evolução genética ({generations} gerações) com Gestão Inteligente"
    print(msg_start)
    logs.append(msg_start)

    for gen in range(generations):
        results = []
        for chromo in population:
            # [ATENÇÃO] O decode agora retorna 2 valores: o plano e a lista de falhas
            current_schedule, current_failures = decode_chromosome(chromo, tasks, workers, max_hours)
            
            fit = calculate_fitness(current_schedule, num_tasks)
            results.append((fit, chromo))
            
            if fit > best_fitness:
                best_fitness = fit
                best_schedule = current_schedule
                best_failures = current_failures
        
        # Ordenar por Fitness
        results.sort(key=lambda x: x[0], reverse=True)
        
        # Elitismo
        new_population = [r[1] for r in results[:20]] 
        
        while len(new_population) < pop_size:
            if random.random() < 0.3:
                new_population.append(random.sample(range(num_tasks), num_tasks))
            else:
                parent = random.choice(results[:30])[1]
                child = parent[:]
                for _ in range(3):
                    idx1, idx2 = random.sample(range(num_tasks), 2)
                    child[idx1], child[idx2] = child[idx2], child[idx1]
                new_population.append(child)
            
        population = new_population

        # [ALTERADO] Adicionei a contagem de falhas ao log visual
        gen_msg = f"   Geração {gen:02d}: Melhor Fitness = {best_fitness:.2f} | Falhas: {len(best_failures)}"
        print(gen_msg)
        logs.append(gen_msg)

    # [ALTERADO] Retorna a tripla: Plano, Falhas, Logs
    return best_schedule, best_failures, logs