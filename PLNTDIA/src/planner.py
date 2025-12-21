import random
from typing import List, Tuple, Dict, Set
from .domain import Server, CVE, Software, Worker, PatchTask
from .logic import is_server_available, is_worker_available, get_patch_duration, LEVEL_RANK, can_worker_handle_level, LEVEL_HOURLY_RATE

def calculate_fitness(schedule: List[PatchTask], total_tasks: int) -> float:
    """
    O CORAÇÃO DO AG: Quanto maior o score, melhor o plano.
    Agora equilibrando Eficácia (Patches), Segurança (Níveis) e Custo (Euros).
    """
    if not schedule: return 0.0
    
    # Importamos a tabela de preços do logic.py
    from .logic import LEVEL_HOURLY_RATE

    score = 0.0
    pipelines_completos = set()
    total_cost = 0.0 # Para calcular o custo total do plano
    workers_used = set() # NOVO: Para identificar quem está a trabalhar

    for task in schedule:
        # 1. Recompensa por Prioridade (O que já tinhas)
        score += task.cve.final_priority_score
        
        # 2. Bónus por chegar a PROD (Incentiva o pipeline)
        if task.server.environment == "PROD":
            score += 50
            pipelines_completos.add(f"{task.server.chain_id}_{task.cve.id}")
            
        # 3. NOVO BÓNUS: MENTORIA (Equipa Mista)
        # Se a equipa tiver mais de um elemento e incluir um Junior + (Mid ou Senior)
        if len(task.workers) > 1:
            levels = [w.level for w in task.workers]
            for w in task.workers: workers_used.add(w.id) # Registar uso
            if "Junior" in levels and ("Senior" in levels or "Mid" in levels):
                score += 30 # Incentivo para colocar Juniores a aprender com experientes
        else:
            # Caso tarefa de 1 pessoa, registar uso também
            for w in task.workers: workers_used.add(w.id)

        # --- NOVO: CÁLCULO DE CUSTO DA TAREFA ---
        duration = task.end_time - task.start_time
        for w in task.workers:
            # Somamos o custo de cada técnico alocado a esta tarefa
            hourly_rate = LEVEL_HOURLY_RATE.get(w.level, 0)
            total_cost += hourly_rate * duration
            
    # 4. Recompensa extra por fechar o ciclo (DEV+UAT+PROD)
    score += len(pipelines_completos) * 100

    # --- PENALIZAÇÃO POR CUSTO FINANCEIRO ---
    # Subtraímos uma parte do custo ao score final.
    score -= (total_cost / 100.0)
    
    # --- NOVO: PENALIZAÇÃO POR TÉCNICOS OCIOSOS ---
    # Se temos 10 técnicos e só usamos 5, a empresa está a perder dinheiro.
    # Isto força o AG a tentar incluir a Ana Silva, o Ricardo, etc.
    TOTAL_STAFF_COUNT = 10 
    missing_workers = TOTAL_STAFF_COUNT - len(workers_used)
    score -= (missing_workers * 100) # Penalização pesada (-100 por cada técnico ignorado)
        
    return score


def decode_chromosome(chromosome: List[int], tasks: List[Tuple], workers: List[Worker], max_hours: int) -> List[PatchTask]:
    """
    Transforma a 'ordem' (gene) num calendário real.
    """
    schedule = []
    busy_workers: Set[str] = set()
    busy_servers: Set[str] = set()
    pipeline_success: Dict[Tuple[str, str, str], int] = {}

    # NOVO: Dicionário para controlar o limite de fadiga (12h/dia)
    worker_daily_load: Dict[Tuple[str, int], float] = {}
    
    # NOVO: Dicionário para controlar o limite semanal (40h ou 48h)
    # Chave: (ID do técnico, Índice da semana) | Valor: Horas acumuladas
    worker_weekly_load: Dict[Tuple[str, int], float] = {}

    # O AG diz-nos em que ordem devemos tentar agendar as tarefas
    ordered_tasks = [tasks[i] for i in chromosome]

    for cve, server, software in ordered_tasks:
        duration = get_patch_duration(cve.severity)
        min_start_hour = 0
        can_proceed = True
        
        # --- Lógica de Dependência (Igual ao que tinhas) ---
        env, chain = server.environment, server.chain_id
        if env == "UAT":
            if (chain, cve.id, "DEV") in pipeline_success:
                min_start_hour = pipeline_success[(chain, cve.id, "DEV")]
            else: can_proceed = False 
        elif env == "PROD":
            if (chain, cve.id, "UAT") in pipeline_success:
                min_start_hour = pipeline_success[(chain, cve.id, "UAT")]
            else: can_proceed = False

        if not can_proceed: continue

        # --- Procura de vaga no calendário (Até max_hours) ---
        for absolute_hour in range(min_start_hour, max_hours):
            current_day = absolute_hour // 24
            current_week = absolute_hour // 168 # 168h = 1 semana

            # A. Check Servidor
            if not is_server_available(server, absolute_hour, duration): continue
            
            if any(f"{server.id}_{h}" in busy_servers for h in range(absolute_hour, absolute_hour + duration)):
                continue

            # B. Check Staff com Filtro de Nível, Fadiga Diária e Limite Semanal
            available_team = []
            for w in workers:
                if server.id not in w.authorized_server_ids: continue
                if not is_worker_available(w, absolute_hour, duration): continue

                required_lvl = "Mid" if server.environment == "PROD" else "Junior"
                if not can_worker_handle_level(w.level, required_lvl):
                    continue 
                
                # --- CORREÇÃO AQUI: Limite Diário Diferenciado ---
                limit_day = 12 if w.is_on_call else 8  # 12h para prevenção, 8h para normais
                hours_done_today = worker_daily_load.get((w.id, current_day), 0)
                if hours_done_today + duration > limit_day:
                    continue

                # NOVA REGRA: Limite Semanal (48h se On-Call, 40h se Normal)
                limit_week = 48 if w.is_on_call else 40
                hours_done_week = worker_weekly_load.get((w.id, current_week), 0)
                if hours_done_week + duration > limit_week:
                    continue # Excedeu o limite de horas da semana

                if not any(f"{w.id}_{h}" in busy_workers for h in range(absolute_hour, absolute_hour + duration)):
                    available_team.append(w)
            
            # C. Agendar com Filtro de Liderança de Equipa
            if len(available_team) >= cve.operators_required:
                potential_chosen = available_team[:cve.operators_required]
                
                from .logic import LEVEL_RANK
                has_lead = any(LEVEL_RANK.get(w.level, 0) >= 2 for w in potential_chosen)
                
                if has_lead or server.environment != "PROD":
                    end_time = absolute_hour + duration
                    
                    for h in range(absolute_hour, end_time):
                        busy_servers.add(f"{server.id}_{h}")
                    
                    for w in potential_chosen:
                        for h in range(absolute_hour, end_time):
                            busy_workers.add(f"{w.id}_{h}")
                        
                        # Atualizar acumuladores Diário e Semanal
                        worker_daily_load[(w.id, current_day)] = worker_daily_load.get((w.id, current_day), 0) + duration
                        worker_weekly_load[(w.id, current_week)] = worker_weekly_load.get((w.id, current_week), 0) + duration

                    schedule.append(PatchTask(cve, server, software, potential_chosen, absolute_hour, end_time))
                    pipeline_success[(chain, cve.id, env)] = end_time
                    break

    return schedule

def create_genetic_schedule(tasks, workers, max_hours, pop_size=20, generations=50):
    """
    Função Mestra que coordena a evolução.
    """
    num_tasks = len(tasks)
    if num_tasks == 0: return [], []

    logs = []
    population = [random.sample(range(num_tasks), num_tasks) for _ in range(pop_size)]
    best_schedule = []
    best_fitness = -float('inf') # Iniciamos com infinito negativo para suportar penalizações

    msg_start = f"-> A iniciar evolução genética ({generations} gerações)..."
    print(msg_start)
    logs.append(msg_start)

    for gen in range(generations):
        results = []
        for chromo in population:
            current_schedule = decode_chromosome(chromo, tasks, workers, max_hours)
            fit = calculate_fitness(current_schedule, num_tasks)
            results.append((fit, chromo, current_schedule))
            
            if fit > best_fitness:
                best_fitness = fit
                best_schedule = current_schedule
        
        # --- LÓGICA DE EVOLUÇÃO MELHORADA ---
        # Ordenamos os resultados (maior fitness primeiro)
        results.sort(key=lambda x: x[0], reverse=True)
        
        # ELITISMO: Mantemos os 10 melhores (em vez de 5) para preservar boas estratégias
        new_population = [r[1] for r in results[:10]]
        
        while len(new_population) < pop_size:
            # DIVERSIDADE: 20% de chance de gerar um "indivíduo explorador" (totalmente aleatório)
            # Isto ajuda a encontrar técnicos ignorados e novas semanas no calendário
            if random.random() < 0.2:
                new_population.append(random.sample(range(num_tasks), num_tasks))
            else:
                # Mutação clássica por troca (Swap Mutation) para refinar os bons pais
                parent = random.choice(results[:15])[1]
                child = parent[:]
                idx1, idx2 = random.sample(range(num_tasks), 2)
                child[idx1], child[idx2] = child[idx2], child[idx1]
                new_population.append(child)
            
        population = new_population

        gen_msg = f"   Geração {gen:02d}: Melhor Fitness = {best_fitness:.2f}"
        print(gen_msg)
        logs.append(gen_msg)

    return best_schedule, logs