"""
Módulo de Algoritmo Genético para Otimização de Patch Scheduling

Implementa um GA para encontrar o melhor agendamento de patches considerando:
- Restrições de janelas de manutenção
- Disponibilidade de workers
- Prioridades de CVEs
- Dependências entre ambientes (DEV -> TEST -> PROD)
- Feriados e ausências
"""

import random
import copy
import logging
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from datetime import date, timedelta
from collections import defaultdict

from .domain import Server, CVE, Software, Worker, PatchTask
from .logic import is_server_available, is_worker_available
from .availability import AvailabilityManager, PlanningPeriod

logger = logging.getLogger(__name__)


@dataclass
class PatchAssignment:
    """Representa uma atribuição de patch a um slot temporal."""
    cve_id: str
    server_id: str
    software_id: str
    day: int  # Dia da semana (0-6) ou dia absoluto
    hour: int  # Hora de início
    worker_ids: List[str]
    duration: int
    
    def __hash__(self):
        return hash((self.cve_id, self.server_id, self.day, self.hour))


@dataclass
class Chromosome:
    """
    Cromossoma que representa uma solução de agendamento.
    
    Cada gene é uma PatchAssignment com:
    - Qual CVE/servidor/software
    - Quando (dia, hora)
    - Quem (workers atribuídos)
    """
    genes: List[PatchAssignment]
    fitness: float = 0.0
    
    def __len__(self):
        return len(self.genes)
    
    def copy(self) -> 'Chromosome':
        return Chromosome(
            genes=[copy.copy(g) for g in self.genes],
            fitness=self.fitness
        )


@dataclass
class GAConfig:
    """Configuração do algoritmo genético."""
    population_size: int = 50
    generations: int = 100
    crossover_rate: float = 0.8
    mutation_rate: float = 0.15
    elite_size: int = 5
    tournament_size: int = 3
    max_daily_hours: int = 8
    planning_weeks: int = 2


class GeneticScheduler:
    """
    Scheduler baseado em Algoritmo Genético.
    
    Otimiza o agendamento de patches considerando múltiplas restrições
    e objetivos.
    """
    
    def __init__(
        self,
        servers: List[Server],
        workers: List[Worker],
        cves: List[CVE],
        tasks: List[Tuple[CVE, Server, Software]],
        config: GAConfig = None,
        availability_manager: AvailabilityManager = None,
        start_date: date = None
    ):
        self.servers = {s.id: s for s in servers}
        self.workers = {w.id: w for w in workers}
        self.cves = {c.id: c for c in cves}
        self.tasks = tasks
        self.config = config or GAConfig()
        self.availability_manager = availability_manager
        self.start_date = start_date or date.today()
        
        # Cache de janelas de manutenção por servidor
        self._server_windows = self._build_server_windows()
        
        # Cache de turnos por worker
        self._worker_shifts = self._build_worker_shifts()
        
        # Total de horas no horizonte de planeamento
        self.total_hours = 168 * self.config.planning_weeks
        
        # Estatísticas
        self.best_fitness_history: List[float] = []
        self.avg_fitness_history: List[float] = []
    
    def _build_server_windows(self) -> Dict[str, List[Tuple[int, int, int]]]:
        """Constrói cache de janelas de manutenção."""
        windows = {}
        for server_id, server in self.servers.items():
            windows[server_id] = server.downtime_windows
        return windows
    
    def _build_worker_shifts(self) -> Dict[str, List[Tuple[int, int, int]]]:
        """Constrói cache de turnos dos workers."""
        shifts = {}
        for worker_id, worker in self.workers.items():
            shifts[worker_id] = worker.weekly_shifts
        return shifts
    
    def _is_valid_slot(
        self,
        server_id: str,
        day: int,
        hour: int,
        duration: int,
        occupied_slots: Dict[str, List[Tuple[int, int]]]
    ) -> bool:
        """Verifica se um slot está disponível para um servidor."""
        server = self.servers.get(server_id)
        if not server:
            return False
        
        # Verificar janela de manutenção
        day_of_week = day % 7
        in_window = False
        for win_day, win_start, win_end in server.downtime_windows:
            if win_day == day_of_week and win_start <= hour < win_end:
                if hour + duration <= win_end:
                    in_window = True
                    break
        
        if not in_window:
            return False
        
        # Verificar se não há conflito com outras tarefas
        absolute_start = day * 24 + hour
        absolute_end = absolute_start + duration
        
        for start, end in occupied_slots.get(server_id, []):
            if not (absolute_end <= start or absolute_start >= end):
                return False
        
        return True
    
    def _get_available_workers(
        self,
        day: int,
        hour: int,
        duration: int,
        required: int,
        server_id: str,
        occupied_workers: Dict[str, List[Tuple[int, int]]],
        worker_daily_hours: Dict[str, Dict[int, int]]
    ) -> List[str]:
        """Encontra workers disponíveis para um slot."""
        available = []
        day_of_week = day % 7
        absolute_start = day * 24 + hour
        absolute_end = absolute_start + duration
        
        # Calcular data real para verificar feriados/férias
        check_date = self.start_date + timedelta(days=day)
        
        for worker_id, worker in self.workers.items():
            # Verificar turno
            in_shift = False
            for shift_day, shift_start, shift_end in worker.weekly_shifts:
                if shift_day == day_of_week and shift_start <= hour < shift_end:
                    if hour + duration <= shift_end:
                        in_shift = True
                        break
            
            if not in_shift:
                continue
            
            # Verificar permissão de acesso ao servidor
            if not worker.can_access_server(server_id):
                continue
            
            # Verificar férias/feriados
            if self.availability_manager:
                if not self.availability_manager.is_worker_available(worker_id, check_date):
                    continue
            
            # Verificar conflitos
            is_free = True
            for start, end in occupied_workers.get(worker_id, []):
                if not (absolute_end <= start or absolute_start >= end):
                    is_free = False
                    break
            
            if not is_free:
                continue
            
            # Verificar limite diário
            current_hours = worker_daily_hours.get(worker_id, {}).get(day, 0)
            if current_hours + duration > self.config.max_daily_hours:
                continue
            
            available.append(worker_id)
            
            if len(available) >= required:
                break
        
        return available
    
    def _create_random_chromosome(self) -> Chromosome:
        """Cria um cromossoma aleatório válido."""
        genes = []
        server_occupied: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        worker_occupied: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        worker_daily_hours: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
        
        # Embaralhar tarefas para variedade
        shuffled_tasks = list(self.tasks)
        random.shuffle(shuffled_tasks)
        
        for cve, server, software in shuffled_tasks:
            # Tentar encontrar um slot válido
            scheduled = False
            
            # Tentar slots aleatórios
            attempts = 0
            max_attempts = 50
            
            while not scheduled and attempts < max_attempts:
                attempts += 1
                
                # Escolher dia e hora aleatórios
                day = random.randint(0, self.config.planning_weeks * 7 - 1)
                
                # Encontrar horas válidas na janela de manutenção
                day_of_week = day % 7
                valid_hours = []
                for win_day, win_start, win_end in server.downtime_windows:
                    if win_day == day_of_week:
                        for h in range(win_start, win_end - cve.estimated_fix_time + 1):
                            valid_hours.append(h)
                
                if not valid_hours:
                    continue
                
                hour = random.choice(valid_hours)
                
                # Verificar slot
                if not self._is_valid_slot(
                    server.id, day, hour, cve.estimated_fix_time, server_occupied
                ):
                    continue
                
                # Encontrar workers
                workers = self._get_available_workers(
                    day, hour, cve.estimated_fix_time,
                    cve.operators_required, server.id,
                    worker_occupied, worker_daily_hours
                )
                
                if len(workers) >= cve.operators_required:
                    # Criar gene
                    chosen_workers = workers[:cve.operators_required]
                    gene = PatchAssignment(
                        cve_id=cve.id,
                        server_id=server.id,
                        software_id=software.id,
                        day=day,
                        hour=hour,
                        worker_ids=chosen_workers,
                        duration=cve.estimated_fix_time
                    )
                    genes.append(gene)
                    
                    # Marcar recursos como ocupados
                    absolute_start = day * 24 + hour
                    absolute_end = absolute_start + cve.estimated_fix_time
                    
                    server_occupied[server.id].append((absolute_start, absolute_end))
                    for w in chosen_workers:
                        worker_occupied[w].append((absolute_start, absolute_end))
                        worker_daily_hours[w][day] += cve.estimated_fix_time
                    
                    scheduled = True
        
        return Chromosome(genes=genes)
    
    def _calculate_fitness(self, chromosome: Chromosome) -> float:
        """
        Calcula o fitness de um cromossoma.
        
        Considera:
        - Número de tarefas agendadas (mais é melhor)
        - Prioridade das CVEs agendadas
        - Respeito às dependências DEV -> TEST -> PROD
        - Distribuição de carga entre workers
        - Utilização eficiente das janelas
        """
        if not chromosome.genes:
            return 0.0
        
        fitness = 0.0
        
        # 1. Bonus por tarefa agendada (peso alto)
        tasks_scheduled = len(chromosome.genes)
        max_tasks = len(self.tasks)
        coverage_score = (tasks_scheduled / max_tasks) * 100 if max_tasks > 0 else 0
        fitness += coverage_score * 2  # Peso 2
        
        # 2. Soma das prioridades das CVEs agendadas
        priority_sum = 0.0
        for gene in chromosome.genes:
            cve = self.cves.get(gene.cve_id)
            if cve:
                priority_sum += cve.final_priority_score
        
        # Normalizar (assumindo prioridade máxima ~10)
        max_priority = max_tasks * 10 if max_tasks > 0 else 1
        priority_score = (priority_sum / max_priority) * 50
        fitness += priority_score
        
        # 3. Penalização por violação de dependências
        env_order = {"DEV": 0, "TEST": 1, "PROD": 2}
        dep_violations = 0
        
        # Agrupar por CVE e dependency_group
        cve_schedules: Dict[str, Dict[str, int]] = defaultdict(dict)  # cve_id -> {env -> day}
        
        for gene in chromosome.genes:
            server = self.servers.get(gene.server_id)
            if server and server.dependency_group:
                key = f"{gene.cve_id}_{server.dependency_group}"
                cve_schedules[key][server.environment] = gene.day
        
        for key, env_days in cve_schedules.items():
            envs_scheduled = list(env_days.keys())
            for i in range(len(envs_scheduled)):
                for j in range(i + 1, len(envs_scheduled)):
                    env1, env2 = envs_scheduled[i], envs_scheduled[j]
                    order1, order2 = env_order.get(env1, 0), env_order.get(env2, 0)
                    day1, day2 = env_days[env1], env_days[env2]
                    
                    # Se env1 deve vir antes de env2, mas está agendado depois
                    if order1 < order2 and day1 > day2:
                        dep_violations += 1
                    elif order2 < order1 and day2 > day1:
                        dep_violations += 1
        
        fitness -= dep_violations * 10  # Penalização forte
        
        # 4. Distribuição de carga (desvio padrão baixo é melhor)
        worker_hours: Dict[str, int] = defaultdict(int)
        for gene in chromosome.genes:
            for w in gene.worker_ids:
                worker_hours[w] += gene.duration
        
        if worker_hours:
            avg_hours = sum(worker_hours.values()) / len(worker_hours)
            variance = sum((h - avg_hours) ** 2 for h in worker_hours.values()) / len(worker_hours)
            std_dev = variance ** 0.5
            balance_score = max(0, 10 - std_dev)
            fitness += balance_score
        
        # 5. Bonus por agendar CVEs críticas cedo
        early_critical_bonus = 0.0
        for gene in chromosome.genes:
            cve = self.cves.get(gene.cve_id)
            if cve and cve.severity in ["Critical", "High"]:
                # Quanto mais cedo, maior o bonus
                days_from_start = gene.day
                max_days = self.config.planning_weeks * 7
                early_factor = 1 - (days_from_start / max_days)
                early_critical_bonus += early_factor * 5
        
        fitness += early_critical_bonus
        
        return max(0, fitness)
    
    def _tournament_selection(self, population: List[Chromosome]) -> Chromosome:
        """Seleciona um cromossoma via torneio."""
        tournament = random.sample(population, min(self.config.tournament_size, len(population)))
        return max(tournament, key=lambda c: c.fitness)
    
    def _crossover(self, parent1: Chromosome, parent2: Chromosome) -> Tuple[Chromosome, Chromosome]:
        """Realiza crossover entre dois pais."""
        if random.random() > self.config.crossover_rate:
            return parent1.copy(), parent2.copy()
        
        # One-point crossover
        if len(parent1.genes) == 0 or len(parent2.genes) == 0:
            return parent1.copy(), parent2.copy()
        
        point = random.randint(1, max(1, min(len(parent1.genes), len(parent2.genes)) - 1))
        
        child1_genes = parent1.genes[:point] + parent2.genes[point:]
        child2_genes = parent2.genes[:point] + parent1.genes[point:]
        
        # Remover duplicatas (mesmo CVE+servidor)
        def deduplicate(genes):
            seen = set()
            unique = []
            for g in genes:
                key = (g.cve_id, g.server_id)
                if key not in seen:
                    seen.add(key)
                    unique.append(g)
            return unique
        
        return Chromosome(genes=deduplicate(child1_genes)), Chromosome(genes=deduplicate(child2_genes))
    
    def _mutate(self, chromosome: Chromosome) -> Chromosome:
        """Aplica mutação a um cromossoma."""
        if random.random() > self.config.mutation_rate:
            return chromosome
        
        mutated = chromosome.copy()
        
        if not mutated.genes:
            return mutated
        
        # Escolher tipo de mutação
        mutation_type = random.choice(["shift_time", "swap", "change_worker"])
        
        if mutation_type == "shift_time" and mutated.genes:
            # Mudar horário de uma tarefa
            idx = random.randint(0, len(mutated.genes) - 1)
            gene = mutated.genes[idx]
            
            # Tentar novo horário
            server = self.servers.get(gene.server_id)
            if server:
                day_of_week = gene.day % 7
                for win_day, win_start, win_end in server.downtime_windows:
                    if win_day == day_of_week:
                        new_hour = random.randint(win_start, max(win_start, win_end - gene.duration))
                        gene.hour = new_hour
                        break
        
        elif mutation_type == "swap" and len(mutated.genes) >= 2:
            # Trocar horários entre duas tarefas
            idx1, idx2 = random.sample(range(len(mutated.genes)), 2)
            mutated.genes[idx1].day, mutated.genes[idx2].day = mutated.genes[idx2].day, mutated.genes[idx1].day
            mutated.genes[idx1].hour, mutated.genes[idx2].hour = mutated.genes[idx2].hour, mutated.genes[idx1].hour
        
        elif mutation_type == "change_worker" and mutated.genes:
            # Tentar trocar workers de uma tarefa
            idx = random.randint(0, len(mutated.genes) - 1)
            gene = mutated.genes[idx]
            
            # Encontrar workers alternativos (simplificado)
            all_workers = list(self.workers.keys())
            random.shuffle(all_workers)
            
            cve = self.cves.get(gene.cve_id)
            if cve and len(all_workers) >= cve.operators_required:
                gene.worker_ids = all_workers[:cve.operators_required]
        
        return mutated
    
    def _repair_chromosome(self, chromosome: Chromosome) -> Chromosome:
        """Repara um cromossoma removendo conflitos."""
        if not chromosome.genes:
            return chromosome
        
        repaired = Chromosome(genes=[])
        server_occupied: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        worker_occupied: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
        
        for gene in chromosome.genes:
            absolute_start = gene.day * 24 + gene.hour
            absolute_end = absolute_start + gene.duration
            
            # Verificar conflito de servidor
            server_conflict = False
            for start, end in server_occupied.get(gene.server_id, []):
                if not (absolute_end <= start or absolute_start >= end):
                    server_conflict = True
                    break
            
            if server_conflict:
                continue
            
            # Verificar conflito de workers
            worker_conflict = False
            for w in gene.worker_ids:
                for start, end in worker_occupied.get(w, []):
                    if not (absolute_end <= start or absolute_start >= end):
                        worker_conflict = True
                        break
                if worker_conflict:
                    break
            
            if worker_conflict:
                continue
            
            # Gene válido - adicionar
            repaired.genes.append(gene)
            server_occupied[gene.server_id].append((absolute_start, absolute_end))
            for w in gene.worker_ids:
                worker_occupied[w].append((absolute_start, absolute_end))
        
        return repaired
    
    def run(self, verbose: bool = False) -> Tuple[Chromosome, List[PatchTask]]:
        """
        Executa o algoritmo genético.
        
        Returns:
            Tuple com o melhor cromossoma e lista de PatchTasks
        """
        if verbose:
            print(f"🧬 Iniciando Algoritmo Genético")
            print(f"   População: {self.config.population_size}")
            print(f"   Gerações: {self.config.generations}")
            print(f"   Tarefas a agendar: {len(self.tasks)}")
        
        # Criar população inicial
        population = [self._create_random_chromosome() for _ in range(self.config.population_size)]
        
        # Calcular fitness inicial
        for chrom in population:
            chrom.fitness = self._calculate_fitness(chrom)
        
        best_ever = max(population, key=lambda c: c.fitness)
        
        for gen in range(self.config.generations):
            # Ordenar por fitness
            population.sort(key=lambda c: c.fitness, reverse=True)
            
            # Preservar elite
            new_population = population[:self.config.elite_size]
            
            # Gerar resto da população
            while len(new_population) < self.config.population_size:
                # Seleção
                parent1 = self._tournament_selection(population)
                parent2 = self._tournament_selection(population)
                
                # Crossover
                child1, child2 = self._crossover(parent1, parent2)
                
                # Mutação
                child1 = self._mutate(child1)
                child2 = self._mutate(child2)
                
                # Reparar
                child1 = self._repair_chromosome(child1)
                child2 = self._repair_chromosome(child2)
                
                # Calcular fitness
                child1.fitness = self._calculate_fitness(child1)
                child2.fitness = self._calculate_fitness(child2)
                
                new_population.extend([child1, child2])
            
            population = new_population[:self.config.population_size]
            
            # Atualizar melhor
            gen_best = max(population, key=lambda c: c.fitness)
            if gen_best.fitness > best_ever.fitness:
                best_ever = gen_best.copy()
            
            # Estatísticas
            avg_fitness = sum(c.fitness for c in population) / len(population)
            self.best_fitness_history.append(best_ever.fitness)
            self.avg_fitness_history.append(avg_fitness)
            
            if verbose and gen % 10 == 0:
                print(f"   Geração {gen}: Best={best_ever.fitness:.2f}, Avg={avg_fitness:.2f}, Tasks={len(best_ever.genes)}")
        
        # Converter para PatchTasks
        patch_tasks = self._chromosome_to_tasks(best_ever)
        
        if verbose:
            print(f"✅ GA Concluído: {len(patch_tasks)} tarefas agendadas")
        
        return best_ever, patch_tasks
    
    def _chromosome_to_tasks(self, chromosome: Chromosome) -> List[PatchTask]:
        """Converte cromossoma para lista de PatchTasks."""
        tasks = []
        
        for gene in chromosome.genes:
            cve = self.cves.get(gene.cve_id)
            server = self.servers.get(gene.server_id)
            
            if not cve or not server:
                continue
            
            # Encontrar software
            software = None
            for sw in server.installed_software:
                if sw.id == gene.software_id:
                    software = sw
                    break
            
            if not software:
                continue
            
            # Encontrar workers
            workers = [self.workers[w] for w in gene.worker_ids if w in self.workers]
            
            if len(workers) < cve.operators_required:
                continue
            
            absolute_start = gene.day * 24 + gene.hour
            
            task = PatchTask(
                cve=cve,
                server=server,
                software=software,
                start_time=absolute_start,
                end_time=absolute_start + gene.duration,
                workers=workers
            )
            tasks.append(task)
        
        # Ordenar por hora de início
        tasks.sort(key=lambda t: t.start_time)
        
        return tasks


def run_genetic_scheduler(
    servers: List[Server],
    workers: List[Worker],
    cves: List[CVE],
    tasks: List[Tuple[CVE, Server, Software]],
    availability_manager: AvailabilityManager = None,
    start_date: date = None,
    population_size: int = 50,
    generations: int = 100,
    verbose: bool = False
) -> Tuple[List[PatchTask], Dict]:
    """
    Função de conveniência para executar o scheduler genético.
    
    Returns:
        Tuple com lista de PatchTasks e dicionário de métricas
    """
    config = GAConfig(
        population_size=population_size,
        generations=generations
    )
    
    scheduler = GeneticScheduler(
        servers=servers,
        workers=workers,
        cves=cves,
        tasks=tasks,
        config=config,
        availability_manager=availability_manager,
        start_date=start_date
    )
    
    best_chromosome, patch_tasks = scheduler.run(verbose=verbose)
    
    metrics = {
        "total_tasks": len(tasks),
        "scheduled_tasks": len(patch_tasks),
        "success_rate": (len(patch_tasks) / len(tasks) * 100) if tasks else 0,
        "best_fitness": best_chromosome.fitness,
        "fitness_history": scheduler.best_fitness_history,
        "avg_fitness_history": scheduler.avg_fitness_history
    }
    
    return patch_tasks, metrics
