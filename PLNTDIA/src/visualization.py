"""
Módulo de Visualização do Algoritmo Genético

Gera gráficos relevantes para análise do planeamento de patches:
- Evolução do fitness ao longo das gerações
- Distribuição de tarefas por severidade
- Utilização de recursos (workers e servidores)
- Cronograma visual do planeamento
- Análise de convergência do algoritmo
"""

import os
import logging
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from datetime import date, timedelta

try:
    import matplotlib
    matplotlib.use('Agg')  # Backend não-interativo para evitar problemas
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.ticker import MaxNLocator
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    plt = None

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    np = None

from .domain import PatchTask, CVE, Server, Worker

logger = logging.getLogger(__name__)

# Cores para severidades
SEVERITY_COLORS = {
    'Critical': '#DC3545',  # Vermelho
    'High': '#FD7E14',      # Laranja
    'Medium': '#FFC107',    # Amarelo
    'Low': '#28A745',       # Verde
}

# Cores para ambientes
ENV_COLORS = {
    'DEV': '#17A2B8',   # Azul claro
    'TEST': '#6C757D',  # Cinza
    'PROD': '#DC3545',  # Vermelho
}

# Nomes dos dias
DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}


class GeneticAlgorithmVisualizer:
    """
    Classe para visualização do algoritmo genético de planeamento.
    
    Gera gráficos durante e após a execução do algoritmo.
    """
    
    def __init__(self, output_dir: str = "graficos"):
        """
        Inicializa o visualizador.
        
        Args:
            output_dir: Diretório para guardar os gráficos
        """
        self.output_dir = output_dir
        self.fitness_history: List[float] = []
        self.best_fitness_history: List[float] = []
        self.diversity_history: List[float] = []
        self.generation_stats: List[Dict] = []
        
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("Matplotlib não disponível. Gráficos não serão gerados.")
            return
        
        # Criar diretório se não existir
        os.makedirs(output_dir, exist_ok=True)
        
        # Configurar estilo
        plt.style.use('seaborn-v0_8-whitegrid')
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12
    
    def record_generation(self, generation: int, fitness_values: List[float], 
                          best_fitness: float, diversity: float = 0.0):
        """
        Regista estatísticas de uma geração.
        
        Args:
            generation: Número da geração
            fitness_values: Lista de fitness de todos os indivíduos
            best_fitness: Melhor fitness da geração
            diversity: Medida de diversidade da população
        """
        if not NUMPY_AVAILABLE:
            avg_fitness = sum(fitness_values) / len(fitness_values) if fitness_values else 0
        else:
            avg_fitness = np.mean(fitness_values) if fitness_values else 0
        
        self.fitness_history.append(avg_fitness)
        self.best_fitness_history.append(best_fitness)
        self.diversity_history.append(diversity)
        
        self.generation_stats.append({
            'generation': generation,
            'avg_fitness': avg_fitness,
            'best_fitness': best_fitness,
            'diversity': diversity,
            'min_fitness': min(fitness_values) if fitness_values else 0,
            'max_fitness': max(fitness_values) if fitness_values else 0
        })
    
    def plot_fitness_evolution(self, filename: str = "fitness_evolution.png") -> Optional[str]:
        """
        Gráfico de evolução do fitness ao longo das gerações.
        
        Args:
            filename: Nome do ficheiro de saída
            
        Returns:
            Caminho do ficheiro gerado ou None se falhar
        """
        if not MATPLOTLIB_AVAILABLE or not self.fitness_history:
            return None
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        generations = range(1, len(self.fitness_history) + 1)
        
        # Linha do fitness médio
        ax.plot(generations, self.fitness_history, 'b-', 
                label='Fitness Médio', linewidth=2, alpha=0.7)
        
        # Linha do melhor fitness
        ax.plot(generations, self.best_fitness_history, 'g-', 
                label='Melhor Fitness', linewidth=2)
        
        # Área de variação
        if self.generation_stats:
            min_vals = [s['min_fitness'] for s in self.generation_stats]
            max_vals = [s['max_fitness'] for s in self.generation_stats]
            ax.fill_between(generations, min_vals, max_vals, 
                           alpha=0.2, color='blue', label='Variação')
        
        ax.set_xlabel('Geração')
        ax.set_ylabel('Fitness')
        ax.set_title('Evolução do Fitness do Algoritmo Genético')
        ax.legend(loc='lower right')
        ax.xaxis.set_major_locator(MaxNLocator(integer=True))
        ax.grid(True, alpha=0.3)
        
        # Adicionar anotação com melhor valor
        best_gen = self.best_fitness_history.index(max(self.best_fitness_history)) + 1
        best_val = max(self.best_fitness_history)
        ax.annotate(f'Melhor: {best_val:.2f}',
                   xy=(best_gen, best_val),
                   xytext=(best_gen + len(generations)*0.1, best_val * 0.95),
                   arrowprops=dict(arrowstyle='->', color='green'),
                   fontsize=10)
        
        filepath = os.path.join(self.output_dir, filename)
        plt.tight_layout()
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Gráfico de evolução do fitness guardado em: {filepath}")
        return filepath
    
    def plot_convergence(self, filename: str = "convergence.png") -> Optional[str]:
        """
        Gráfico de análise de convergência do algoritmo.
        
        Args:
            filename: Nome do ficheiro de saída
            
        Returns:
            Caminho do ficheiro gerado ou None se falhar
        """
        if not MATPLOTLIB_AVAILABLE or len(self.fitness_history) < 2:
            return None
        
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        generations = range(1, len(self.fitness_history) + 1)
        
        # 1. Taxa de melhoria
        ax1 = axes[0, 0]
        improvements = [0] + [self.best_fitness_history[i] - self.best_fitness_history[i-1] 
                             for i in range(1, len(self.best_fitness_history))]
        ax1.bar(generations, improvements, color='steelblue', alpha=0.7)
        ax1.set_xlabel('Geração')
        ax1.set_ylabel('Melhoria no Fitness')
        ax1.set_title('Taxa de Melhoria por Geração')
        ax1.axhline(y=0, color='r', linestyle='--', alpha=0.5)
        
        # 2. Distância do ótimo (normalizado)
        ax2 = axes[0, 1]
        max_fitness = max(self.best_fitness_history)
        distance = [(max_fitness - f) / max_fitness * 100 if max_fitness > 0 else 0 
                   for f in self.best_fitness_history]
        ax2.plot(generations, distance, 'r-', linewidth=2)
        ax2.fill_between(generations, distance, alpha=0.3, color='red')
        ax2.set_xlabel('Geração')
        ax2.set_ylabel('Distância do Ótimo (%)')
        ax2.set_title('Convergência para o Ótimo')
        ax2.set_ylim(bottom=0)
        
        # 3. Diversidade vs Fitness
        ax3 = axes[1, 0]
        if self.diversity_history and any(d > 0 for d in self.diversity_history):
            ax3.plot(generations, self.diversity_history, 'purple', 
                    linewidth=2, label='Diversidade')
            ax3_twin = ax3.twinx()
            ax3_twin.plot(generations, self.best_fitness_history, 'g-', 
                         linewidth=2, label='Best Fitness')
            ax3.set_xlabel('Geração')
            ax3.set_ylabel('Diversidade', color='purple')
            ax3_twin.set_ylabel('Fitness', color='green')
            ax3.set_title('Diversidade vs Fitness')
        else:
            # Se não houver dados de diversidade, mostrar distribuição de fitness
            ax3.hist(self.fitness_history, bins=20, color='steelblue', 
                    alpha=0.7, edgecolor='black')
            ax3.set_xlabel('Fitness')
            ax3.set_ylabel('Frequência')
            ax3.set_title('Distribuição do Fitness Médio')
        
        # 4. Fitness acumulado
        ax4 = axes[1, 1]
        cumulative = []
        running_best = float('-inf')
        for f in self.best_fitness_history:
            running_best = max(running_best, f)
            cumulative.append(running_best)
        ax4.plot(generations, cumulative, 'g-', linewidth=2)
        ax4.fill_between(generations, cumulative, alpha=0.3, color='green')
        ax4.set_xlabel('Geração')
        ax4.set_ylabel('Melhor Fitness Acumulado')
        ax4.set_title('Evolução do Melhor Fitness Encontrado')
        
        plt.suptitle('Análise de Convergência do Algoritmo Genético', fontsize=16)
        plt.tight_layout()
        
        filepath = os.path.join(self.output_dir, filename)
        plt.savefig(filepath, dpi=150, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Gráfico de convergência guardado em: {filepath}")
        return filepath


def plot_schedule_overview(schedule: List[PatchTask], 
                           output_dir: str = "graficos",
                           filename: str = "schedule_overview.png") -> Optional[str]:
    """
    Gráfico panorâmico do planeamento.
    
    Mostra:
    - Distribuição de tarefas por severidade
    - Distribuição por ambiente
    - Utilização ao longo da semana
    - Top servidores com mais patches
    
    Args:
        schedule: Lista de PatchTask agendadas
        output_dir: Diretório de saída
        filename: Nome do ficheiro
        
    Returns:
        Caminho do ficheiro gerado ou None se falhar
    """
    if not MATPLOTLIB_AVAILABLE or not schedule:
        return None
    
    os.makedirs(output_dir, exist_ok=True)
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Distribuição por Severidade (Pie Chart)
    ax1 = axes[0, 0]
    severity_counts = defaultdict(int)
    for task in schedule:
        severity_counts[task.cve.severity] += 1
    
    if severity_counts:
        labels = list(severity_counts.keys())
        sizes = list(severity_counts.values())
        colors = [SEVERITY_COLORS.get(s, '#888888') for s in labels]
        
        wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=colors,
                                           autopct='%1.1f%%', startangle=90,
                                           explode=[0.05 if s == 'Critical' else 0 for s in labels])
        ax1.set_title('Distribuição por Severidade')
    
    # 2. Distribuição por Ambiente (Bar Chart)
    ax2 = axes[0, 1]
    env_counts = defaultdict(int)
    for task in schedule:
        env = task.server.environment
        env_counts[env] += 1
    
    if env_counts:
        envs = list(env_counts.keys())
        counts = list(env_counts.values())
        colors = [ENV_COLORS.get(e, '#888888') for e in envs]
        
        bars = ax2.bar(envs, counts, color=colors, edgecolor='black', alpha=0.8)
        ax2.set_xlabel('Ambiente')
        ax2.set_ylabel('Número de Patches')
        ax2.set_title('Patches por Ambiente')
        
        # Adicionar valores nas barras
        for bar, count in zip(bars, counts):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(count), ha='center', va='bottom', fontsize=11)
    
    # 3. Utilização ao Longo da Semana (Area Chart)
    ax3 = axes[1, 0]
    hours_by_day = defaultdict(int)
    for task in schedule:
        day = task.day
        hours_by_day[day] += task.duration
    
    days = range(7)
    hours = [hours_by_day.get(d, 0) for d in days]
    day_names = [DAYS_MAP[d] for d in days]
    
    ax3.fill_between(days, hours, alpha=0.4, color='steelblue')
    ax3.plot(days, hours, 'o-', color='steelblue', linewidth=2, markersize=8)
    ax3.set_xticks(days)
    ax3.set_xticklabels(day_names)
    ax3.set_xlabel('Dia da Semana')
    ax3.set_ylabel('Horas de Trabalho')
    ax3.set_title('Carga de Trabalho por Dia')
    ax3.set_ylim(bottom=0)
    
    # 4. Top 10 Servidores (Horizontal Bar)
    ax4 = axes[1, 1]
    server_counts = defaultdict(int)
    for task in schedule:
        server_counts[task.server.id] += 1
    
    if server_counts:
        # Top 10 servidores
        top_servers = sorted(server_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        servers = [s[0] for s in top_servers]
        counts = [s[1] for s in top_servers]
        
        colors = []
        for s in servers:
            if 'PROD' in s:
                colors.append(ENV_COLORS['PROD'])
            elif 'TEST' in s:
                colors.append(ENV_COLORS['TEST'])
            else:
                colors.append(ENV_COLORS['DEV'])
        
        y_pos = range(len(servers))
        ax4.barh(y_pos, counts, color=colors, alpha=0.8, edgecolor='black')
        ax4.set_yticks(y_pos)
        ax4.set_yticklabels(servers)
        ax4.set_xlabel('Número de Patches')
        ax4.set_title('Top 10 Servidores com Mais Patches')
        ax4.invert_yaxis()
    
    plt.suptitle('Visão Geral do Planeamento de Patches', fontsize=16)
    plt.tight_layout()
    
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Gráfico panorâmico guardado em: {filepath}")
    return filepath


def plot_worker_utilization(schedule: List[PatchTask],
                            workers: List[Worker],
                            output_dir: str = "graficos",
                            filename: str = "worker_utilization.png") -> Optional[str]:
    """
    Gráfico de utilização dos workers.
    
    Args:
        schedule: Lista de PatchTask agendadas
        workers: Lista de todos os workers
        output_dir: Diretório de saída
        filename: Nome do ficheiro
        
    Returns:
        Caminho do ficheiro gerado ou None se falhar
    """
    if not MATPLOTLIB_AVAILABLE or not schedule:
        return None
    
    os.makedirs(output_dir, exist_ok=True)
    
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    
    # Calcular horas por worker
    worker_hours = defaultdict(int)
    worker_tasks = defaultdict(int)
    
    for task in schedule:
        for worker in task.workers:
            worker_hours[worker.id] += task.duration
            worker_tasks[worker.id] += 1
    
    # 1. Horas de Trabalho por Worker
    ax1 = axes[0]
    
    worker_names = []
    hours = []
    colors = []
    
    level_colors = {'Senior': '#28A745', 'Mid': '#FFC107', 'Junior': '#17A2B8'}
    
    for w in workers:
        name = w.name if w.name else w.id
        worker_names.append(f"{name}\n({w.level})")
        hours.append(worker_hours.get(w.id, 0))
        colors.append(level_colors.get(w.level, '#888888'))
    
    bars = ax1.bar(range(len(worker_names)), hours, color=colors, edgecolor='black', alpha=0.8)
    ax1.set_xticks(range(len(worker_names)))
    ax1.set_xticklabels(worker_names, rotation=45, ha='right')
    ax1.set_xlabel('Técnico')
    ax1.set_ylabel('Horas de Trabalho')
    ax1.set_title('Carga de Trabalho por Técnico')
    
    # Adicionar legenda
    legend_patches = [mpatches.Patch(color=c, label=l) 
                     for l, c in level_colors.items()]
    ax1.legend(handles=legend_patches, loc='upper right')
    
    # 2. Número de Tarefas por Worker
    ax2 = axes[1]
    
    tasks = [worker_tasks.get(w.id, 0) for w in workers]
    
    bars = ax2.bar(range(len(worker_names)), tasks, color=colors, edgecolor='black', alpha=0.8)
    ax2.set_xticks(range(len(worker_names)))
    ax2.set_xticklabels(worker_names, rotation=45, ha='right')
    ax2.set_xlabel('Técnico')
    ax2.set_ylabel('Número de Tarefas')
    ax2.set_title('Tarefas Atribuídas por Técnico')
    
    # Adicionar valores nas barras
    for ax, values in [(ax1, hours), (ax2, tasks)]:
        for bar, val in zip(ax.patches, values):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                       str(int(val)), ha='center', va='bottom', fontsize=9)
    
    plt.suptitle('Utilização da Equipa Técnica', fontsize=14)
    plt.tight_layout()
    
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Gráfico de utilização de workers guardado em: {filepath}")
    return filepath


def plot_timeline(schedule: List[PatchTask],
                  output_dir: str = "graficos",
                  filename: str = "timeline.png",
                  max_tasks: int = 30) -> Optional[str]:
    """
    Gráfico de timeline (Gantt) do planeamento.
    
    Args:
        schedule: Lista de PatchTask agendadas
        output_dir: Diretório de saída
        filename: Nome do ficheiro
        max_tasks: Máximo de tarefas a mostrar
        
    Returns:
        Caminho do ficheiro gerado ou None se falhar
    """
    if not MATPLOTLIB_AVAILABLE or not schedule:
        return None
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Ordenar por hora de início
    sorted_schedule = sorted(schedule, key=lambda x: x.start_time)[:max_tasks]
    
    fig, ax = plt.subplots(figsize=(16, max(8, len(sorted_schedule) * 0.4)))
    
    y_ticks = []
    y_labels = []
    
    for i, task in enumerate(sorted_schedule):
        y = len(sorted_schedule) - i - 1
        
        # Cor baseada na severidade
        color = SEVERITY_COLORS.get(task.cve.severity, '#888888')
        
        # Barra da tarefa
        ax.barh(y, task.duration, left=task.start_time, 
                color=color, edgecolor='black', alpha=0.8, height=0.6)
        
        # Texto dentro da barra
        text_x = task.start_time + task.duration / 2
        ax.text(text_x, y, f"{task.cve.id[:12]}...", 
                ha='center', va='center', fontsize=8, color='white', fontweight='bold')
        
        y_ticks.append(y)
        y_labels.append(f"{task.server.id}")
    
    ax.set_yticks(y_ticks)
    ax.set_yticklabels(y_labels)
    ax.set_xlabel('Hora (absoluta desde início do planeamento)')
    ax.set_ylabel('Servidor')
    ax.set_title(f'Timeline de Patches (Top {len(sorted_schedule)} Tarefas)')
    
    # Adicionar linhas verticais para dias
    for day in range(8):
        ax.axvline(x=day * 24, color='gray', linestyle='--', alpha=0.3)
        if day < 7:
            ax.text(day * 24 + 12, len(sorted_schedule) + 0.5, 
                   DAYS_MAP[day], ha='center', fontsize=10)
    
    # Legenda
    legend_patches = [mpatches.Patch(color=c, label=s) 
                     for s, c in SEVERITY_COLORS.items()]
    ax.legend(handles=legend_patches, loc='upper right', title='Severidade')
    
    ax.set_xlim(left=0)
    ax.set_ylim(-0.5, len(sorted_schedule) + 1)
    
    plt.tight_layout()
    
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Gráfico de timeline guardado em: {filepath}")
    return filepath


def plot_cve_analysis(cves: List[CVE],
                      output_dir: str = "graficos",
                      filename: str = "cve_analysis.png") -> Optional[str]:
    """
    Gráfico de análise dos CVEs.
    
    Args:
        cves: Lista de CVEs
        output_dir: Diretório de saída
        filename: Nome do ficheiro
        
    Returns:
        Caminho do ficheiro gerado ou None se falhar
    """
    if not MATPLOTLIB_AVAILABLE or not cves:
        return None
    
    os.makedirs(output_dir, exist_ok=True)
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # 1. Distribuição de Severidade
    ax1 = axes[0, 0]
    severity_counts = defaultdict(int)
    for cve in cves:
        severity_counts[cve.severity] += 1
    
    labels = list(severity_counts.keys())
    sizes = list(severity_counts.values())
    colors = [SEVERITY_COLORS.get(s, '#888888') for s in labels]
    
    ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax1.set_title('Distribuição de CVEs por Severidade')
    
    # 2. Distribuição de EPSS Score
    ax2 = axes[0, 1]
    epss_scores = [cve.epss_score for cve in cves if cve.epss_score > 0]
    
    if epss_scores:
        ax2.hist(epss_scores, bins=20, color='steelblue', edgecolor='black', alpha=0.7)
        ax2.axvline(x=0.5, color='red', linestyle='--', label='Alto Risco (0.5)')
        ax2.set_xlabel('EPSS Score')
        ax2.set_ylabel('Frequência')
        ax2.set_title('Distribuição de EPSS Score')
        ax2.legend()
    
    # 3. Tempo Estimado de Fix
    ax3 = axes[1, 0]
    fix_times = [cve.estimated_fix_time for cve in cves]
    
    if fix_times:
        unique_times = sorted(set(fix_times))
        counts = [fix_times.count(t) for t in unique_times]
        
        ax3.bar(unique_times, counts, color='teal', edgecolor='black', alpha=0.7)
        ax3.set_xlabel('Tempo Estimado (horas)')
        ax3.set_ylabel('Número de CVEs')
        ax3.set_title('Distribuição de Tempo de Fix')
    
    # 4. Prioridade Final (se calculada)
    ax4 = axes[1, 1]
    priorities = [cve.final_priority_score for cve in cves if cve.final_priority_score > 0]
    
    if priorities:
        ax4.hist(priorities, bins=20, color='purple', edgecolor='black', alpha=0.7)
        ax4.set_xlabel('Score de Prioridade')
        ax4.set_ylabel('Frequência')
        ax4.set_title('Distribuição de Prioridade Final')
    else:
        # Se não houver prioridades, mostrar risk levels
        risk_counts = defaultdict(int)
        for cve in cves:
            risk_counts[cve.risk_level] += 1
        
        risks = list(risk_counts.keys())
        counts = list(risk_counts.values())
        ax4.bar(risks, counts, color='purple', edgecolor='black', alpha=0.7)
        ax4.set_xlabel('Nível de Risco')
        ax4.set_ylabel('Número de CVEs')
        ax4.set_title('Distribuição de Nível de Risco')
    
    plt.suptitle('Análise de CVEs', fontsize=16)
    plt.tight_layout()
    
    filepath = os.path.join(output_dir, filename)
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Gráfico de análise de CVEs guardado em: {filepath}")
    return filepath


def generate_all_charts(schedule: List[PatchTask],
                        cves: List[CVE],
                        workers: List[Worker],
                        metrics,
                        visualizer: Optional[GeneticAlgorithmVisualizer] = None,
                        output_dir: str = "graficos") -> List[str]:
    """
    Gera todos os gráficos disponíveis.
    
    Args:
        schedule: Lista de tarefas agendadas
        cves: Lista de CVEs
        workers: Lista de workers
        metrics: Métricas do agendamento
        visualizer: Visualizador do AG (opcional, para gráficos de fitness)
        output_dir: Diretório de saída
        
    Returns:
        Lista de caminhos dos ficheiros gerados
    """
    if not MATPLOTLIB_AVAILABLE:
        logger.warning("Matplotlib não disponível. Instale com: pip install matplotlib")
        return []
    
    generated_files = []
    
    # 1. Gráficos do algoritmo genético (se disponível)
    if visualizer:
        fitness_file = visualizer.plot_fitness_evolution()
        if fitness_file:
            generated_files.append(fitness_file)
        
        convergence_file = visualizer.plot_convergence()
        if convergence_file:
            generated_files.append(convergence_file)
    
    # 2. Visão geral do planeamento
    overview_file = plot_schedule_overview(schedule, output_dir)
    if overview_file:
        generated_files.append(overview_file)
    
    # 3. Utilização de workers
    worker_file = plot_worker_utilization(schedule, workers, output_dir)
    if worker_file:
        generated_files.append(worker_file)
    
    # 4. Timeline
    timeline_file = plot_timeline(schedule, output_dir)
    if timeline_file:
        generated_files.append(timeline_file)
    
    # 5. Análise de CVEs
    cve_file = plot_cve_analysis(cves, output_dir)
    if cve_file:
        generated_files.append(cve_file)
    
    return generated_files


def print_charts_summary(generated_files: List[str]):
    """
    Imprime resumo dos gráficos gerados.
    
    Args:
        generated_files: Lista de caminhos dos ficheiros gerados
    """
    if not generated_files:
        print("\n⚠️  Nenhum gráfico foi gerado.")
        print("   Instale matplotlib: pip install matplotlib")
        return
    
    print("\n" + "=" * 50)
    print("📊 GRÁFICOS GERADOS")
    print("=" * 50)
    
    for filepath in generated_files:
        filename = os.path.basename(filepath)
        print(f"   ✅ {filename}")
    
    print(f"\n   📁 Diretório: {os.path.dirname(generated_files[0])}")
    print("=" * 50)
