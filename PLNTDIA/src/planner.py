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
    [ATUALIZADO] Agora usa check_labor_limits e valida Skills.
    """
    schedule = []
    failures = [] # Lista para guardar os falhados
    
    busy_workers: Set[str] = set()
    busy_servers: Set[str] = set()
    pipeline_success: Dict[Tuple[str, str, str], int] = {}

    # Controladores de Fadiga (Diária e Semanal)
    worker_daily_load: Dict[Tuple[str, int], float] = {}
    worker_weekly_load: Dict[Tuple[str, int], float] = {}

    # Lista inicial de tarefas baseada na ordem do cromossoma
    pending_tasks = [tasks[i] for i in chromosome]

    # [NOVO] Loop infinito para reavaliação (Multi-Pass)
    while True:
        progress_made = False # Controla se conseguimos agendar algo nesta volta
        remaining_tasks = []  # Tarefas que não conseguimos agendar nesta volta
        
        # Dicionário temporário para guardar o motivo da falha nesta volta
        current_round_failures = {} 

        for task_tuple in pending_tasks:
            cve, server, software = task_tuple
            duration = get_patch_duration(cve.severity)
            min_start_hour = 0
            can_proceed = True
            fail_reason = "Sem disponibilidade (Recursos/Janela)" # Motivo default
            
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

            # --- TENTATIVA 1: MODO OTIMIZADO (Poupar Seniores, Mentoria + RTO RÍGIDO) ---
            for absolute_hour in range(min_start_hour, max_hours):
                if scheduled: break
                
                # [NOVO] Filtro RTO Rígido: Se violar a política, não agendamos nesta fase.
                if duration > server.rto_hours: continue

                # Verificar Disponibilidade do Servidor
                if not is_server_available(server, absolute_hour, duration): continue
                if any(f"{server.id}_{h}" in busy_servers for h in range(absolute_hour, absolute_hour + duration)):
                    continue
                
                current_day = absolute_hour // 24
                current_week = absolute_hour // 168

                # 1. Recolher TODOS os técnicos disponíveis nesta hora (Pool de Candidatos)
                available_pool = []
                for w in workers:
                    # Filtros Básicos
                    if server.id not in w.authorized_server_ids: continue
                    
                    # [NOVO] Validação de Skill (Consistência com Emergency)
                    if hasattr(w, 'skills') and software.id not in w.skills: continue

                    if not is_worker_available(w, absolute_hour, duration): continue

                    # [ATUALIZADO] Verificação de Limites Legais (Centralizada)
                    hours_today = worker_daily_load.get((w.id, current_day), 0)
                    hours_this_week = worker_weekly_load.get((w.id, current_week), 0)
                    
                    if not check_labor_limits(w, duration, hours_today, hours_this_week):
                        continue

                    # Verificação de Ocupação no Horário
                    if not any(f"{w.id}_{h}" in busy_workers for h in range(absolute_hour, absolute_hour + duration)):
                        available_pool.append(w)
                
                # Se não houver gente suficiente, tenta na próxima hora
                if len(available_pool) < cve.operators_required: continue

                # --- SELEÇÃO INTELIGENTE DE EQUIPA ---
                potential_chosen = []
                
                # Separar técnicos por nível (Seniores vs Resto)
                seniors = [w for w in available_pool if w.level == "Senior"]
                others = [w for w in available_pool if w.level != "Senior"] # Juniores e Mids

                # Critério de Desempate: Quem trabalhou menos nesta semana (Balanceamento de Carga)
                seniors.sort(key=lambda w: worker_weekly_load.get((w.id, current_week), 0))
                others.sort(key=lambda w: (LEVEL_RANK.get(w.level, 0), worker_weekly_load.get((w.id, current_week), 0)))

                if server.environment == "PROD":
                    # REGRA PROD: Obrigatório pelo menos 1 Senior
                    if not seniors: continue # Sem Senior disponível, não podemos fazer PROD
                    
                    potential_chosen.append(seniors.pop(0))
                    
                    slots_needed = cve.operators_required - 1
                    if slots_needed > 0:
                        pool_rest = others + seniors 
                        if len(pool_rest) < slots_needed: continue
                        potential_chosen.extend(pool_rest[:slots_needed])
                else:
                    # REGRA DEV/UAT: Tenta NÃO usar Seniores
                    pool_all = others + seniors 
                    potential_chosen = pool_all[:cve.operators_required]

                # Agendar se equipa estiver completa
                if len(potential_chosen) == cve.operators_required:
                    end_time = absolute_hour + duration
                    
                    for h in range(absolute_hour, end_time):
                        busy_servers.add(f"{server.id}_{h}")
                    
                    for w in potential_chosen:
                        for h in range(absolute_hour, end_time):
                            busy_workers.add(f"{w.id}_{h}")
                        
                        worker_daily_load[(w.id, current_day)] = worker_daily_load.get((w.id, current_day), 0) + duration
                        worker_weekly_load[(w.id, current_week)] = worker_weekly_load.get((w.id, current_week), 0) + duration

                    # [NOVO] Passamos rto_violation=False
                    schedule.append(PatchTask(cve, server, software, potential_chosen, absolute_hour, end_time, rto_violation=False))
                    pipeline_success[(chain, cve.id, env)] = end_time
                    scheduled = True
                    progress_made = True

            # --- TENTATIVA 2: MODO "FALLBACK" (Desespero + SOFT RTO) ---
            if not scheduled:
                for absolute_hour in range(min_start_hour, max_hours):
                    if scheduled: break

                    # [NOVO] Detetar Violação de RTO (Soft RTO)
                    is_violation = False
                    if duration > server.rto_hours:
                        is_violation = True

                    if not is_server_available(server, absolute_hour, duration): continue
                    if any(f"{server.id}_{h}" in busy_servers for h in range(absolute_hour, absolute_hour + duration)): continue
                    
                    current_day = absolute_hour // 24
                    current_week = absolute_hour // 168

                    available_pool = []
                    for w in workers:
                        if server.id not in w.authorized_server_ids: continue
                        
                        # [NOVO] Validação Skill (Mesmo no Fallback)
                        if hasattr(w, 'skills') and software.id not in w.skills: continue

                        if not is_worker_available(w, absolute_hour, duration): continue
                        
                        # [ATUALIZADO] Verificação de Limites Legais (Centralizada)
                        hours_today = worker_daily_load.get((w.id, current_day), 0)
                        hours_this_week = worker_weekly_load.get((w.id, current_week), 0)
                        
                        if not check_labor_limits(w, duration, hours_today, hours_this_week):
                            continue

                        if any(f"{w.id}_{h}" in busy_workers for h in range(absolute_hour, absolute_hour + duration)): continue
                        
                        available_pool.append(w)
                    
                    if len(available_pool) < cve.operators_required: continue

                    # SELEÇÃO SIMPLIFICADA (Sem regras de "Poupança")
                    potential_chosen = []
                    
                    if server.environment == "PROD":
                        seniors = [w for w in available_pool if w.level == "Senior"]
                        if not seniors: continue
                        potential_chosen.append(seniors[0])
                        others = [w for w in available_pool if w.id != seniors[0].id]
                        if len(others) >= cve.operators_required - 1:
                            potential_chosen.extend(others[:cve.operators_required - 1])
                    else:
                        potential_chosen = available_pool[:cve.operators_required]

                    if len(potential_chosen) == cve.operators_required:
                        # Agendar (Modo Fallback)
                        end_time = absolute_hour + duration
                        for h in range(absolute_hour, end_time): busy_servers.add(f"{server.id}_{h}")
                        for w in potential_chosen:
                            for h in range(absolute_hour, end_time): busy_workers.add(f"{w.id}_{h}")
                            worker_daily_load[(w.id, current_day)] = worker_daily_load.get((w.id, current_day), 0) + duration
                            worker_weekly_load[(w.id, current_week)] = worker_weekly_load.get((w.id, current_week), 0) + duration
                        
                        # [NOVO] Passamos a flag de violação
                        schedule.append(PatchTask(cve, server, software, potential_chosen, absolute_hour, end_time, rto_violation=is_violation))
                        pipeline_success[(chain, cve.id, env)] = end_time
                        scheduled = True
                        progress_made = True
            
            # Se não foi agendado em nenhuma tentativa, vai para a lista de restantes
            if not scheduled:
                remaining_tasks.append(task_tuple)
                if f"{cve.id}_{server.id}" not in current_round_failures:
                    current_round_failures[f"{cve.id}_{server.id}"] = "Sem Recursos/Janela"
        
        # [NOVO] Fim do loop for (passagem pela lista de pendentes).
        if not progress_made:
            for t_fail in remaining_tasks:
                cve_f, server_f, _ = t_fail
                reason = current_round_failures.get(f"{cve_f.id}_{server_f.id}", "Desconhecido")
                failures.append(FailedTask(cve_f, server_f, reason))
            break
        
        pending_tasks = remaining_tasks
        if not pending_tasks:
            break # Tudo agendado!

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

    msg_start = f"-> A iniciar evolução genética ({generations} gerações) com Gestão Inteligente + Fallback..."
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