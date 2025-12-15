# Ficheiro: src/optimizer.py
import random
import numpy as np
from . import config

# Mapeamento para converter índice numérico (0-6) em nome do dia para display
DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sab", 6: "Dom"}

def create_individual(num_patches):
    """
    Cria um genoma/indivíduo inicial aleatório.
    
    Representação: Uma lista de inteiros onde:
    - Índice da lista = ID do Patch
    - Valor = Hora de início absoluta na semana (0 a 167)
    - Valor -1 = Patch não agendado
    """
    return [random.randint(-1, config.HORIZON_HOURS - 1) for _ in range(num_patches)]

def get_day_and_hour(absolute_hour):
    """
    Converte uma hora absoluta (ex: 26) em Dia e Hora (ex: Dia 1/Terça, 02h).
    Útil para verificar janelas de manutenção que dependem do dia da semana.
    """
    day = (absolute_hour // 24) % 7
    hour_of_day = absolute_hour % 24
    return day, hour_of_day

def is_operator_available(op, start_abs, duration, day_of_week):
    """
    Verifica se um operador específico pode trabalhar num dado horário.
    Valida:
    1. Se trabalha naquele dia da semana (Simulação baseada no nome).
    2. Se o horário do patch cabe dentro do seu turno diário.
    """
    op_name = op.id.lower()
    is_weekend = (day_of_week >= 5) # 5=Sáb, 6=Dom
    
    # --- Validação Mock de Dias de Trabalho ---
    # Num sistema real, o Operador teria uma lista de dias_folga.
    # Aqui, usamos o nome para simular (ex: "weekend" só trabalha Sáb/Dom)
    if "weekend" in op_name and not is_weekend:
        return False 
    if "day" in op_name and is_weekend:
        return False 
        
    # --- Validação de Turno (Horas) ---
    start_hour_day = start_abs % 24
    end_hour_day = start_hour_day + duration
    
    shift_start, shift_end = op.shift
    
    # O patch tem de começar e acabar DENTRO do turno do técnico
    if start_hour_day >= shift_start and end_hour_day <= shift_end:
        return True
    return False

def calculate_fitness(schedule, servers, patches, operators):
    """
    Função Objetivo (Fitness Function).
    Avalia a qualidade de um plano de agendamento.
    
    Lógica: Score Base (Recompensa) - Penalizações (Erros/Violações).
    Quanto maior o valor, melhor o plano.
    """
    score = 0.0
    penalty = 0.0
    
    # Mapa para controlar colisões de horário dos técnicos
    # Dict: ID_Operador -> Conjunto de horas ocupadas
    op_schedule_map = {op.id: set() for op in operators}
    
    # Dicionário auxiliar para acesso rápido aos servidores por ID
    server_map = {s.id: s for s in servers}

    for i, start_time in enumerate(schedule):
        patch = patches[i]
        server = server_map[patch.server_id]

        # --- A. Regras de Negócio (Thresholds de Risco) ---
        if start_time == -1:
            # Se não agendou patch CRÍTICO (>0.7), penalidade massiva.
            if patch.risk_score > 0.7:
                penalty += 5000 * server.criticality 
            # Se não agendou patch BAIXO RISCO (<0.2), ganha pontos (poupança).
            elif patch.risk_score < 0.2:
                score += 50 
            continue # Passa para o próximo patch

        end_time = start_time + patch.estimated_time
        
        # --- B. Limite do Horizonte Temporal ---
        # Garante que o patch não acaba depois do fim da semana (hora 168)
        if end_time > config.HORIZON_HOURS:
            penalty += 1000
            continue

        # --- C. Janela de Manutenção, RTO e Custo ---
        current_day, current_h = get_day_and_hour(start_time)
        
        valid_window_found = False
        rto_breach = False

        # Procura se existe ALGUMA janela válida no servidor para este dia/hora
        for w_day, w_start, w_end in server.maintenance_windows:
            if current_day == w_day: # Dia corresponde?
                window_duration = w_end - w_start
                
                # 1. Validação RTO (Recovery Time Objective)
                # O patch cabe fisicamente na janela disponível?
                if patch.estimated_time > window_duration:
                    rto_breach = True
                    break 

                # 2. Validação de Encaixe
                # O horário proposto cai dentro dos limites da janela?
                patch_end_h = current_h + patch.estimated_time
                if current_h >= w_start and patch_end_h <= w_end:
                    valid_window_found = True
                    
                    # 3. Cálculo Financeiro
                    # Penaliza agendamentos em servidores com downtime caro
                    cost = patch.estimated_time * server.downtime_cost
                    penalty += (cost / 10.0) # /10 para normalizar a escala do score
                    break
        
        # Aplicação das penalidades de janela
        if rto_breach:
            penalty += 20000 # Penalidade MÁXIMA (Impossível fisicamente)
        elif not valid_window_found:
            penalty += config.PENALTY_WINDOW # Agendou fora da hora permitida
        
        # --- D. Alocação de Staff (Skills + Turno + Disponibilidade) ---
        needed_skill = patch.affected_os
        assigned_op = None
        
        # Filtra quem tem a skill necessária (ex: Linux)
        candidates = [op for op in operators if needed_skill in op.skills]
        
        for op in candidates:
            # Verifica se está no turno certo e dia certo
            if is_operator_available(op, start_time, patch.estimated_time, current_day):
                # Verifica colisão: ele já está ocupado nestas horas?
                collision = False
                for t in range(start_time, end_time):
                    if t in op_schedule_map[op.id]:
                        collision = True
                        break
                
                if not collision:
                    # Sucesso! Aloca o operador e marca as horas como ocupadas
                    assigned_op = op
                    for t in range(start_time, end_time):
                        op_schedule_map[op.id].add(t)
                    break # Já encontrámos um, para de procurar
        
        if assigned_op is None:
            penalty += config.PENALTY_STAFF # Ninguém disponível
        
        # --- E. Recompensa Final (Score) ---
        # Prioriza Risco Alto em Servidores Críticos resolvidos cedo.
        urgency = (patch.risk_score * server.criticality * 50)
        time_bonus = (config.HORIZON_HOURS - start_time) / 10
        score += urgency + time_bonus

    # O fitness nunca deve ser negativo
    return max(0.0, score - penalty)

def crossover(parent1, parent2):
    """Operador Genético: Troca informações entre dois pais (Single Point Crossover)."""
    point = random.randint(1, len(parent1) - 1)
    return parent1[:point] + parent2[point:], parent2[:point] + parent1[point:]

def mutate(individual):
    """
    Versão Agressiva:
    - Maior probabilidade de mutação.
    - Probabilidade alta de ADIAR (-1) para resolver conflitos.
    """
    for i in range(len(individual)):
        # 20% de chance de mudar cada gene (era 10%)
        if random.random() < 0.2:
            
            # Decide o que fazer:
            # 30% de chance de ADIAR o patch (meter -1)
            # Isto ajuda a limpar o calendário quando está cheio de erros
            if random.random() < 0.3:
                individual[i] = -1
            else:
                # Caso contrário, tenta uma nova hora aleatória
                individual[i] = random.randint(-1, config.HORIZON_HOURS - 1)
                
    return individual

def run_genetic_algorithm(servers, patches, operators):
    """
    Executa o ciclo completo de evolução da população.
    Usa Elitismo para garantir que a melhor solução nunca se perde.
    """
    POP_SIZE = 200        # Tamanho da população
    GENERATIONS = 150     # Número de iterações
    ELITISM_COUNT = 10     # Quantos "melhores" passam intactos para a próxima geração

    # 1. População Inicial
    population = [create_individual(len(patches)) for _ in range(POP_SIZE)]
    print(f"Otimizando semana (168h) para {len(patches)} patches...")

    for gen in range(GENERATIONS):
        # 2. Avaliação (Fitness)
        scores = [calculate_fitness(ind, servers, patches, operators) for ind in population]
        
        # Ordena do melhor para o pior
        ranked = sorted(zip(population, scores), key=lambda x: x[1], reverse=True)
        
        # Log de progresso a cada 20 gerações
        if gen % 20 == 0:
            print(f" Geração {gen}: Melhor Score = {ranked[0][1]:.2f}")

        # 3. Seleção e Elitismo
        # Os top X passam direto (Elitismo)
        new_population = [ranked[i][0] for i in range(ELITISM_COUNT)]
        
        # O resto é criado via reprodução dos melhores 50%
        top_half = [x[0] for x in ranked[:POP_SIZE//2]]

        while len(new_population) < POP_SIZE:
            p1 = random.choice(top_half)
            p2 = random.choice(top_half)
            c1, c2 = crossover(p1, p2)
            new_population.append(mutate(c1))
            if len(new_population) < POP_SIZE: new_population.append(mutate(c2))
        
        population = new_population

    # Retorna o melhor indivíduo da última geração
    final_scores = [calculate_fitness(ind, servers, patches, operators) for ind in population]
    best_idx = np.argmax(final_scores)
    return population[best_idx]