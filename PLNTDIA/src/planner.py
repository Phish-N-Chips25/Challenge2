import random
from typing import List, Tuple, Dict, Set
from .domain import Server, CVE, Software, Worker, PatchTask, FailedTask
# Certifica-te que LEVEL_RANK está no logic.py (como definimos antes)
from .logic import is_server_available, is_worker_available, get_patch_duration, LEVEL_RANK, can_worker_handle_level, LEVEL_HOURLY_RATE

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
        # 500 pontos é suficiente para o AG tentar evitar, mas aceitar se não houver opção.
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
    # [ALTERADO] Aumentado para 100.000 para garantir que o Fallback é sempre preferido a falhar
    scheduled_count = len(schedule)
    failed_count = total_tasks - scheduled_count
    if failed_count > 0:
        score -= (failed_count * 100000.0)
        
    return score


def decode_chromosome(chromosome: List[int], tasks: List[Tuple], workers: List[Worker], max_hours: int) -> Tuple[List[PatchTask], List[FailedTask]]:
    """
    Transforma a 'ordem' (gene) num calendário real.
    [ATUALIZADO] Agora retorna (schedule, failures) e identifica motivos de falha.
    
    ESTRATÉGIA DE GESTÃO DE RH (Heurística Best-Fit):
    1. PROD: Exige 1 Senior (Regra de Ouro) + tenta preencher resto com Juniores (Mentoria).
    2. DEV/UAT: Evita usar Seniores se houver Juniores/Mids disponíveis (Poupança de Recursos).
    3. BALANCEAMENTO: Em caso de empate, escolhe quem trabalhou menos horas na semana.
    4. [NOVO] FALLBACK + SOFT RTO: Se a estratégia otimizada falhar, tenta agendar "como der" (aceitando violação de RTO).
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
                    if not is_worker_available(w, absolute_hour, duration): continue

                    # [CORREÇÃO] Removido o filtro de nível aqui para permitir Junior em PROD
                    # A validação de Senior obrigatório é feita na seleção abaixo.
                    
                    # Verificação de Limites Legais (Diário)
                    limit_day = 12 if w.is_on_call else 8
                    hours_today = worker_daily_load.get((w.id, current_day), 0)
                    if hours_today + duration > limit_day: continue

                    # Verificação de Limites Legais (Semanal)
                    limit_week = 48 if w.is_on_call else 40
                    hours_this_week = worker_weekly_load.get((w.id, current_week), 0)
                    if hours_this_week + duration > limit_week: continue

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
                
                # Nos 'others', preferimos Juniores (Rank 1) primeiro para ser barato, depois Carga
                others.sort(key=lambda w: (LEVEL_RANK.get(w.level, 0), worker_weekly_load.get((w.id, current_week), 0)))

                if server.environment == "PROD":
                    # REGRA PROD: Obrigatório pelo menos 1 Senior
                    if not seniors: continue # Sem Senior disponível, não podemos fazer PROD
                    
                    # 1. Aloca o Senior mais livre (para cumprir a regra)
                    potential_chosen.append(seniors.pop(0))
                    
                    # 2. Preenche o resto das vagas
                    slots_needed = cve.operators_required - 1
                    if slots_needed > 0:
                        # Preferência: Usar 'others' (Juniors/Mids) para ganhar Mentoria e poupar outros Seniores
                        pool_rest = others + seniors 
                        if len(pool_rest) < slots_needed: continue
                        potential_chosen.extend(pool_rest[:slots_needed])
                
                else:
                    # REGRA DEV/UAT: Tenta NÃO usar Seniores (guarda-os para PROD e tarefas críticas)
                    # Coloca os seniors no fim da fila de prioridade
                    pool_all = others + seniors 
                    potential_chosen = pool_all[:cve.operators_required]

                # Agendar se equipa estiver completa
                if len(potential_chosen) == cve.operators_required:
                    end_time = absolute_hour + duration
                    
                    # Registar ocupação do servidor
                    for h in range(absolute_hour, end_time):
                        busy_servers.add(f"{server.id}_{h}")
                    
                    # Registar ocupação dos técnicos e atualizar cargas horárias
                    for w in potential_chosen:
                        for h in range(absolute_hour, end_time):
                            busy_workers.add(f"{w.id}_{h}")
                        
                        worker_daily_load[(w.id, current_day)] = worker_daily_load.get((w.id, current_day), 0) + duration
                        worker_weekly_load[(w.id, current_week)] = worker_weekly_load.get((w.id, current_week), 0) + duration

                    # [NOVO] Passamos rto_violation=False porque passou no filtro rígido acima
                    schedule.append(PatchTask(cve, server, software, potential_chosen, absolute_hour, end_time, rto_violation=False))
                    pipeline_success[(chain, cve.id, env)] = end_time
                    scheduled = True
                    progress_made = True

            # --- TENTATIVA 2: MODO "FALLBACK" (Desespero + SOFT RTO) ---
            # Se a tentativa otimizada falhou (ex: não encontrou Juniores para DEV),
            # tentamos novamente aceitando QUALQUER equipa válida (ex: Seniores em DEV),
            # desde que cumpra os requisitos mínimos técnicos e de segurança.
            if not scheduled:
                for absolute_hour in range(min_start_hour, max_hours):
                    if scheduled: break

                    # (Repetimos as verificações de disponibilidade básica...)
                    
                    # [NOVO] Detetar Violação de RTO (Soft RTO)
                    is_violation = False
                    if duration > server.rto_hours:
                        is_violation = True
                    # NOTA: Não fazemos 'continue' aqui. Aceitamos a violação.

                    if not is_server_available(server, absolute_hour, duration): continue
                    if any(f"{server.id}_{h}" in busy_servers for h in range(absolute_hour, absolute_hour + duration)): continue
                    
                    current_day = absolute_hour // 24
                    current_week = absolute_hour // 168

                    available_pool = []
                    for w in workers:
                        if server.id not in w.authorized_server_ids: continue
                        if not is_worker_available(w, absolute_hour, duration): continue
                        
                        # [CORREÇÃO] Removido o filtro de nível aqui também
                        
                        # Filtros de Fadiga (Mantêm-se)
                        limit_day = 12 if w.is_on_call else 8
                        if worker_daily_load.get((w.id, current_day), 0) + duration > limit_day: continue
                        limit_week = 48 if w.is_on_call else 40
                        if worker_weekly_load.get((w.id, current_week), 0) + duration > limit_week: continue
                        if any(f"{w.id}_{h}" in busy_workers for h in range(absolute_hour, absolute_hour + duration)): continue
                        
                        available_pool.append(w)
                    
                    if len(available_pool) < cve.operators_required: continue

                    # SELEÇÃO SIMPLIFICADA (Sem regras de "Poupança")
                    potential_chosen = []
                    
                    if server.environment == "PROD":
                        # PROD continua a exigir Senior, isso é inegociável
                        seniors = [w for w in available_pool if w.level == "Senior"]
                        if not seniors: continue
                        potential_chosen.append(seniors[0])
                        others = [w for w in available_pool if w.id != seniors[0].id]
                        if len(others) >= cve.operators_required - 1:
                            potential_chosen.extend(others[:cve.operators_required - 1])
                    else:
                        # DEV/UAT: Aceita os primeiros N disponíveis, mesmo que sejam Seniores
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
                # Se chegou aqui, é porque tentou todas as horas e falhou.
                # Se não era dependência, é falta de recurso.
                if f"{cve.id}_{server.id}" not in current_round_failures:
                    current_round_failures[f"{cve.id}_{server.id}"] = "Sem Recursos/Janela"
        
        # [NOVO] Fim do loop for (passagem pela lista de pendentes).
        # Verificamos se houve progresso. Se não houve, paramos para evitar loop infinito.
        if not progress_made:
            # Ao sair do loop, processar os falhados definitivos para retorno
            for t_fail in remaining_tasks:
                cve_f, server_f, _ = t_fail
                reason = current_round_failures.get(f"{cve_f.id}_{server_f.id}", "Desconhecido")
                failures.append(FailedTask(cve_f, server_f, reason))
            break
        
        # [NOVO] Atualizamos a lista de tarefas para a próxima volta (apenas as que sobraram)
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
    # População 100% Aleatória (O Decode Inteligente faz o trabalho pesado de alocação)
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
            
            # Guardamos apenas o fitness e o cromossoma para a seleção natural
            results.append((fit, chromo))
            
            if fit > best_fitness:
                best_fitness = fit
                best_schedule = current_schedule
                best_failures = current_failures # [NOVO] Atualizamos as falhas do melhor candidato
        
        # Ordenar por Fitness
        results.sort(key=lambda x: x[0], reverse=True)
        
        # Elitismo: Mantém Top 20
        new_population = [r[1] for r in results[:20]] 
        
        while len(new_population) < pop_size:
            # Mutação Radical (30%): Troca totalmente a ordem para explorar novas semanas
            if random.random() < 0.3:
                new_population.append(random.sample(range(num_tasks), num_tasks))
            else:
                # Mutação Swap Multiplo (Refinamento)
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