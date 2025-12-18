#!/usr/bin/env python3
"""
PLNTDIA - Sistema de Planeamento de Patches

Este módulo é o ponto de entrada principal do sistema.
Executa o pipeline completo: carregamento de dados -> análise -> agendamento -> relatório.

Utiliza dados reais dos ficheiros CSV:
- servers.csv: Lista de servidores
- server_applications.csv: Software instalado
- server_windows.csv: Janelas de manutenção
- team.csv: Equipa técnica
- team_vacations.csv: Férias e ausências da equipa

Suporta também:
- Dataset real de CVEs (merged_cve_data.csv)
- Tracking de patches aplicados
- Período de planeamento configurável
"""

# Ficheiro: main.py
import logging
import argparse
import sys
import os
from datetime import datetime, date
from typing import List, Tuple, Optional

from src.repository import (
    load_data_from_csv,
    generate_cves_for_infrastructure,
    save_scenario_to_json
)
from src.logic import find_affected_servers, calculate_priority
from src.planner import create_simple_schedule, create_schedule_with_metrics
from src.domain import CVE, Server, Software
from src.cve_loader import load_cves_from_dataset
from src.patch_tracker import PatchTracker, filter_unapplied_cves
from src.availability import (
    AvailabilityManager, 
    PlanningPeriod, 
    load_vacations, 
    create_planning_period
)
from src.dependency_manager import DependencyManager, PatchStatus
import re


# Configuração de Logging
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configura o sistema de logging."""
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('plntdia.log', encoding='utf-8')
        ]
    )
    return logging.getLogger(__name__)


# Mapeamento para ficar bonito no print
DAYS_MAP = {0: "Seg", 1: "Ter", 2: "Qua", 3: "Qui", 4: "Sex", 5: "Sáb", 6: "Dom"}


def parse_period_to_days(period: str) -> int:
    """
    Converte um período temporal em número de dias.
    
    Exemplos:
        "1 semana" -> 7
        "2 semanas" -> 14
        "1 mês" -> 30
        "3 meses" -> 90
        "1 ano" -> 365
        
    Args:
        period: String com o período (ex: "2 semanas", "1 mês")
        
    Returns:
        Número de dias correspondente
        
    Raises:
        ValueError: Se o formato não for reconhecido
    """
    period = period.lower().strip()
    
    # Padrão: número + unidade
    match = re.match(r'(\d+)\s*(semana|semanas|week|weeks|mês|mes|meses|month|months|ano|anos|year|years|dia|dias|day|days)', period)
    
    if not match:
        raise ValueError(f"Formato de período não reconhecido: '{period}'. Use formatos como '1 semana', '2 meses', '1 ano'")
    
    num = int(match.group(1))
    unit = match.group(2)
    
    # Mapeamento de unidades para dias
    if unit in ('semana', 'semanas', 'week', 'weeks'):
        return num * 7
    elif unit in ('mês', 'mes', 'meses', 'month', 'months'):
        return num * 30
    elif unit in ('ano', 'anos', 'year', 'years'):
        return num * 365
    elif unit in ('dia', 'dias', 'day', 'days'):
        return num
    else:
        raise ValueError(f"Unidade de tempo não reconhecida: '{unit}'")


def parse_args():
    """Parse argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description='PLNTDIA - Sistema de Planeamento de Patches (dados CSV)'
    )
    
    # === Grupo: Fonte de CVEs ===
    cve_group = parser.add_argument_group('Fonte de CVEs')
    cve_source = cve_group.add_mutually_exclusive_group()
    cve_source.add_argument(
        '-c', '--cves', 
        type=int, 
        default=50,
        help='Número de CVEs sintéticos a gerar (default: 50)'
    )
    cve_source.add_argument(
        '--dataset',
        type=str,
        metavar='PATH',
        help='Usar CVEs reais do dataset (ex: dataset/merged_cve_data.csv)'
    )
    
    # === Grupo: Filtros de Data (para dataset real) ===
    date_group = parser.add_argument_group('Filtros de Data (requer --dataset)')
    date_group.add_argument(
        '--days',
        type=int,
        default=None,
        help='CVEs dos últimos N dias (default: 30 se nenhum filtro especificado)'
    )
    date_group.add_argument(
        '--period',
        type=str,
        metavar='PERÍODO',
        help='Período temporal: "1 semana", "2 semanas", "1 mês", "3 meses", etc.'
    )
    date_group.add_argument(
        '--month',
        type=str,
        metavar='MM ou YYYY-MM',
        help='CVEs de um mês específico (ex: 12 ou 2025-01)'
    )
    date_group.add_argument(
        '--year',
        type=int,
        help='Ano para o filtro de mês (default: ano atual)'
    )
    date_group.add_argument(
        '--min-severity',
        type=str,
        choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
        default='LOW',
        help='Severidade mínima dos CVEs (default: LOW)'
    )
    
    # === Grupo: Tracking de Patches ===
    tracking_group = parser.add_argument_group('Tracking de Patches')
    tracking_group.add_argument(
        '--track-patches',
        action='store_true',
        help='Registar patches agendados no histórico'
    )
    tracking_group.add_argument(
        '--patch-history',
        type=str,
        default=None,
        help='Ficheiro de histórico de patches (default: data/applied_patches.csv)'
    )
    tracking_group.add_argument(
        '--skip-applied',
        action='store_true',
        help='Ignorar CVEs já aplicados aos servidores'
    )
    tracking_group.add_argument(
        '--patch-report',
        type=str,
        metavar='PATH',
        help='Gerar relatório de patches aplicados'
    )
    
    # === Grupo: Disponibilidade da Equipa ===
    avail_group = parser.add_argument_group('Disponibilidade da Equipa')
    avail_group.add_argument(
        '--vacations',
        type=str,
        metavar='PATH',
        help='Ficheiro CSV de férias/ausências (default: csv/team_vacations.csv)'
    )
    avail_group.add_argument(
        '--ignore-vacations',
        action='store_true',
        help='Ignorar férias/ausências no planeamento'
    )
    avail_group.add_argument(
        '--start-date',
        type=str,
        metavar='YYYY-MM-DD',
        help='Data de início do planeamento (default: hoje)'
    )
    avail_group.add_argument(
        '--show-availability',
        action='store_true',
        help='Mostrar resumo de disponibilidade da equipa'
    )
    
    # === Grupo: Dependências DEV → TEST → PROD ===
    dep_group = parser.add_argument_group('Dependências de Pipeline')
    dep_group.add_argument(
        '--enforce-dependencies',
        action='store_true',
        help='Bloquear patches em PROD se não foram testados em TEST'
    )
    dep_group.add_argument(
        '--show-pipeline',
        action='store_true',
        help='Mostrar estado do pipeline de deployment'
    )
    
    # === Grupo: Configuração Geral ===
    parser.add_argument(
        '--csv-path', 
        type=str, 
        default=None,
        help='Caminho para a pasta CSV (default: ./csv)'
    )
    parser.add_argument(
        '--seed', 
        type=int, 
        default=42,
        help='Seed para reprodutibilidade (default: 42)'
    )
    parser.add_argument(
        '-o', '--output', 
        type=str, 
        default='relatorio_analise.txt',
        help='Ficheiro de output (default: relatorio_analise.txt)'
    )
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true',
        help='Modo verbose com mais detalhes'
    )
    parser.add_argument(
        '--save-scenario', 
        type=str,
        help='Salvar cenário gerado em ficheiro JSON'
    )
    parser.add_argument(
        '--max-display', 
        type=int, 
        default=20,
        help='Máximo de tarefas a mostrar no relatório (default: 20)'
    )
    return parser.parse_args()


def identify_tasks(
    cves: List[CVE], 
    servers: List[Server],
    logger: logging.Logger
) -> List[Tuple[CVE, Server, Software]]:
    """
    Identifica todas as tarefas válidas (CVE + Server + Software).
    
    Aplica:
    - Matching de software vulnerável
    - Cálculo de prioridade
    - Filtro de RTO
    """
    tasks_to_plan = []
    discarded_rto = 0
    
    logger.info("A calcular prioridades e verificar RTO...")
    
    for cve in cves:
        targets = find_affected_servers(cve, servers)
        
        if not targets:
            continue

        for server, software in targets:
            # Calcular prioridade
            cve.final_priority_score = calculate_priority(cve, software)
            
            # Filtro RTO (Regra Rígida)
            if cve.estimated_fix_time <= server.rto_hours:
                tasks_to_plan.append((cve, server, software))
            else:
                discarded_rto += 1
                logger.debug(
                    f"Descartado: {cve.id} excede RTO do {server.id} "
                    f"({cve.estimated_fix_time}h > {server.rto_hours}h)"
                )
    
    logger.info(f"Tarefas válidas: {len(tasks_to_plan)}, Descartadas (RTO): {discarded_rto}")
    return tasks_to_plan


def generate_report(
    schedule, 
    metrics, 
    tasks_to_plan,
    filename: str,
    max_display: int,
    servers: List[Server],
    cves: List[CVE],
    workers,
    csv_path: str,
    cve_source: str = "sintético",
    cve_stats: dict = None,
    tracker = None
):
    """Gera o relatório final em ficheiro."""
    
    with open(filename, "w", encoding="utf-8") as f:
        
        def log(texto=""):
            print(texto)
            f.write(texto + "\n")

        log("=" * 60)
        log("         PLNTDIA - Relatório de Planeamento")
        log(f"         Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        log("=" * 60)
        
        log("\n=== 1. DADOS CARREGADOS (CSV) ===")
        log(f"📂 Fonte dados: {csv_path or 'csv/'}")
        log(f"🖥️  Servidores: {len(servers)}")
        
        # Contar por tipo
        prod_count = len([s for s in servers if "PROD" in s.id])
        uat_count = len([s for s in servers if "UAT" in s.id])
        dev_count = len([s for s in servers if "DEV" in s.id])
        log(f"    - PROD: {prod_count} | UAT: {uat_count} | DEV: {dev_count}")
        
        log(f"🔒 CVEs:       {len(cves)} ({cve_source})")
        
        # Se usar dataset real, mostrar estatísticas
        if cve_stats:
            log(f"    - Período: {cve_stats.get('period', 'N/A')}")
            log(f"    - Total no ficheiro: {cve_stats.get('total_file', 'N/A'):,}")
            log(f"    - Total no período: {cve_stats.get('total_period', 'N/A'):,}")
            log(f"    - Match infraestrutura: {cve_stats.get('matched', 'N/A'):,}")
        
        log(f"👷 Equipa:     {len(workers)} técnicos")
        
        # Detalhes da equipa
        senior_count = len([w for w in workers if w.level == "Senior"])
        mid_count = len([w for w in workers if w.level == "Mid"])
        junior_count = len([w for w in workers if w.level == "Junior"])
        log(f"    - Senior: {senior_count} | Mid: {mid_count} | Junior: {junior_count}")
        
        log(f"✅ Tarefas válidas identificadas: {len(tasks_to_plan)}")
        
        # Estatísticas de patches se disponível
        if tracker:
            stats = tracker.get_statistics()
            if stats['total'] > 0:
                log(f"\n📋 Histórico de Patches:")
                log(f"    - Total registados: {stats['total']}")
                log(f"    - Com sucesso: {stats['success']}")
                log(f"    - Agendados: {stats['scheduled']}")
                log(f"    - Servidores únicos: {stats['servers_patched']}")

        log("\n=== 2. RESULTADO DO AGENDAMENTO ===")
        log(f"✅ Agendadas:     {metrics.scheduled_tasks}")
        log(f"⚠️  Falhadas:      {metrics.failed_tasks}")
        log(f"📈 Taxa de Sucesso: {metrics.success_rate:.1f}%")
        
        log("\n=== 3. UTILIZAÇÃO DE RECURSOS ===")
        
        log("\n👷 Técnicos:")
        for worker_id, util in sorted(metrics.worker_utilization.items(), key=lambda x: -x[1]):
            # Encontrar nome do técnico
            worker = next((w for w in workers if w.id == worker_id), None)
            worker_name = worker.name if worker and worker.name else worker_id
            bar = "█" * int(util / 5) + "░" * (20 - int(util / 5))
            log(f"   {worker_name:20} [{bar}] {util:5.1f}%")
        
        avg_worker_util = sum(metrics.worker_utilization.values()) / len(metrics.worker_utilization) if metrics.worker_utilization else 0
        log(f"\n   Média de utilização: {avg_worker_util:.1f}%")
        
        log("\n🖥️  Servidores (top 10):")
        sorted_servers = sorted(metrics.server_utilization.items(), key=lambda x: -x[1])[:10]
        for server_id, util in sorted_servers:
            bar = "█" * int(util / 5) + "░" * (20 - int(util / 5))
            log(f"   {server_id:20} [{bar}] {util:5.1f}%")

        log(f"\n=== 4. PLANO FINAL (Primeiras {max_display} Tarefas) ===")
        
        # Ordenar cronologicamente
        sorted_schedule = sorted(schedule, key=lambda x: x.start_time)
        
        for i, task in enumerate(sorted_schedule[:max_display]):
            # Formatação de dia e hora
            day_name = DAYS_MAP[task.day]
            start_h = task.hour
            end_h = task.end_time % 24
            
            # Formatar nomes da equipa (usar nome se disponível)
            team_names = []
            for w in task.workers:
                name = w.name if w.name else w.id
                team_names.append(f"{name} ({w.level})")
            team_str = ", ".join(team_names)
            
            # Ícone baseado na severidade
            sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(task.cve.severity, "⚪")
            
            log(f"\n🗓️  [{day_name} {start_h:02d}h-{end_h:02d}h] {task.cve.id}")
            log(f"    {sev_icon} Severidade: {task.cve.severity} | EPSS: {task.cve.epss_score:.2f} | Risco: {task.cve.risk_level}")
            log(f"    🖥️  Servidor: {task.server.id}")
            log(f"    📦 Software: {task.software.id} v{task.software.version} (Criticidade: {task.software.criticality})")
            log(f"    👷 Equipa:   {team_str}")
            log(f"    ⏱️  Duração:  {task.duration}h | Prioridade: {task.cve.final_priority_score:.2f}")
            log("-" * 50)

        if len(schedule) > max_display:
            log(f"\n... e mais {len(schedule) - max_display} tarefas não mostradas")

        log("\n" + "=" * 60)
        log("                    FIM DO RELATÓRIO")
        log("=" * 60)


def main():
    """Função principal do sistema."""
    args = parse_args()
    logger = setup_logging(args.verbose)
    
    logger.info("=== PLNTDIA - Início da Execução ===")
    
    # Inicializar tracker de patches se necessário
    tracker = None
    if args.track_patches or args.skip_applied or args.patch_report:
        tracker = PatchTracker(args.patch_history)
        logger.info(f"Tracker de patches inicializado: {len(tracker.history.patches)} patches no histórico")
    
    # Se pedido apenas relatório de patches, gerar e sair
    if args.patch_report and not args.dataset and args.cves == 50:
        if tracker:
            report = tracker.generate_report(args.patch_report)
            print(report)
            print(f"\n✅ Relatório de patches guardado em '{args.patch_report}'")
        else:
            print("❌ Use --track-patches ou --patch-history para especificar o histórico")
        return
    
    try:
        # 0. Configurar período de planeamento e disponibilidade
        # Parse da data de início
        start_date = None
        if args.start_date:
            try:
                start_date = datetime.strptime(args.start_date, '%Y-%m-%d').date()
            except ValueError:
                logger.warning(f"Data inválida: {args.start_date}, usando hoje")
                start_date = date.today()
        else:
            start_date = date.today()
        
        # Determinar número de dias do período
        planning_days = 7  # default: 1 semana
        period_desc = "1 semana"
        
        if args.period:
            planning_days = parse_period_to_days(args.period)
            period_desc = args.period
        elif args.days:
            planning_days = args.days
            period_desc = f"{args.days} dias"
        
        # Criar período de planeamento
        planning_period = create_planning_period(days=planning_days, start_date=start_date)
        logger.info(f"Período de planeamento: {planning_period.start_date} a {planning_period.end_date} ({period_desc})")
        
        # Carregar disponibilidade/férias e feriados
        availability_manager = None
        if not args.ignore_vacations:
            vacations_path = args.vacations
            csv_base = args.csv_path or 'csv'
            
            if not vacations_path:
                vacations_path = os.path.join(csv_base, 'team_vacations.csv')
            
            # Caminho para ficheiro de feriados
            holidays_path = os.path.join(csv_base, 'holidays.csv')
            
            if os.path.exists(vacations_path) or os.path.exists(holidays_path):
                availability_manager = AvailabilityManager(
                    vacations_file=vacations_path if os.path.exists(vacations_path) else None,
                    holidays_file=holidays_path if os.path.exists(holidays_path) else None
                )
                if os.path.exists(vacations_path):
                    logger.info(f"Carregadas {len(availability_manager.absences)} ausências de {vacations_path}")
                if os.path.exists(holidays_path):
                    logger.info(f"Carregados {len(availability_manager.holidays)} feriados de {holidays_path}")
            else:
                logger.info("Ficheiros de férias/feriados não encontrados, continuando sem restrições")
        
        # Mostrar resumo de disponibilidade se pedido
        if args.show_availability and availability_manager:
            summary = availability_manager.get_availability_summary(planning_period)
            print("\n" + "=" * 50)
            print("📅 RESUMO DE DISPONIBILIDADE DA EQUIPA")
            print("=" * 50)
            print(f"Período: {summary['period']}")
            print(f"Total de dias: {summary['total_days']}")
            print(f"Workers com ausências: {summary['workers_with_absences']}")
            if summary['days_off_by_worker']:
                print("\nDias de ausência por worker:")
                for worker_id, days in summary['days_off_by_worker'].items():
                    print(f"  {worker_id}: {days} dias")
            if summary.get('holidays_in_period'):
                print(f"\n🎉 Feriados no período: {summary['holiday_count']}")
                for holiday in summary['holidays_in_period']:
                    print(f"  {holiday.date}: {holiday.name}")
            elif availability_manager.holidays:
                print(f"\n🎉 Feriados carregados: {len(availability_manager.holidays)} (nenhum no período)")
            print("=" * 50 + "\n")
        
        # 1. Carregar dados dos ficheiros CSV
        logger.info(f"A carregar dados dos ficheiros CSV...")
        servers, workers = load_data_from_csv(args.csv_path)
        
        logger.info(f"Carregados: {len(servers)} servidores, {len(workers)} técnicos")
        
        # 2. Obter CVEs (dataset real ou sintéticos)
        cve_source = "sintético"
        cve_stats = {}
        
        if args.dataset:
            # Usar dataset real
            if not os.path.exists(args.dataset):
                raise FileNotFoundError(f"Dataset não encontrado: {args.dataset}")
            
            logger.info(f"A carregar CVEs do dataset: {args.dataset}")
            result = load_cves_from_dataset(
                dataset_path=args.dataset,
                servers=servers,
                days=planning_days,
                month=args.month,
                year=args.year,
                min_severity=args.min_severity
            )
            cves = result.cves
            cve_source = "dataset real"
            cve_stats = {
                'total_file': result.total_in_file,
                'total_period': result.total_in_period,
                'matched': result.matched_to_infrastructure,
                'period': f"{result.period_start.date()} a {result.period_end.date()}",
                'period_desc': period_desc
            }
            logger.info(f"CVEs carregados: {len(cves)} (período: {cve_stats['period']})")
        else:
            # Gerar CVEs sintéticos
            logger.info(f"A gerar {args.cves} CVEs sintéticos para a infraestrutura...")
            cves = generate_cves_for_infrastructure(servers, args.cves, args.seed)
        
        # 2b. Filtrar CVEs já aplicados (se pedido)
        if args.skip_applied and tracker:
            original_count = len(cves)
            cves = filter_unapplied_cves(cves, servers, tracker)
            skipped = original_count - len(cves)
            logger.info(f"CVEs filtrados: {skipped} já aplicados, {len(cves)} pendentes")
        
        # 2c. Filtrar workers indisponíveis por férias
        available_workers = workers
        if availability_manager:
            # Identificar workers com ausências no período
            workers_with_absences = set()
            for worker in workers:
                absences = availability_manager.get_worker_absences_in_period(worker.id, planning_period)
                if absences:
                    total_days = sum(a.duration_days for a in absences)
                    workers_with_absences.add(worker.id)
                    logger.info(f"Worker {worker.id} tem {total_days} dias de ausência no período")
            
            if workers_with_absences:
                logger.info(f"Workers com ausências no período: {', '.join(workers_with_absences)}")
        
        # Salvar cenário se pedido
        if args.save_scenario:
            save_scenario_to_json(servers, cves, workers, args.save_scenario)
            logger.info(f"Cenário salvo em {args.save_scenario}")
        
        # 3. Identificar tarefas
        tasks_to_plan = identify_tasks(cves, servers, logger)
        
        if not tasks_to_plan:
            logger.warning("Nenhuma tarefa válida encontrada!")
            return
        
        # 3b. Aplicar restrições de dependências DEV → TEST → PROD
        dep_manager = None
        if args.enforce_dependencies:
            dep_manager = DependencyManager(servers)
            
            # Separar tarefas por ambiente
            dev_tasks = [(c, s, sw) for c, s, sw in tasks_to_plan if s.environment == "DEV"]
            test_tasks = [(c, s, sw) for c, s, sw in tasks_to_plan if s.environment == "TEST"]
            prod_tasks = [(c, s, sw) for c, s, sw in tasks_to_plan if s.environment == "PROD"]
            
            # Identificar quais CVEs podem ir para PROD
            blocked_prod = []
            allowed_prod = []
            
            for cve, server, sw in prod_tasks:
                can_apply, reason = dep_manager.can_apply_patch(cve, server, check_test_success=True)
                if can_apply:
                    allowed_prod.append((cve, server, sw))
                else:
                    blocked_prod.append((cve, server, sw, reason))
                    logger.warning(f"Bloqueado: {cve.id} para {server.id} - {reason}")
            
            # Reconstruir lista de tarefas (DEV + TEST + PROD permitidos)
            tasks_to_plan = dev_tasks + test_tasks + allowed_prod
            
            logger.info(
                f"Dependências aplicadas: {len(dev_tasks)} DEV, {len(test_tasks)} TEST, "
                f"{len(allowed_prod)} PROD permitidos, {len(blocked_prod)} PROD bloqueados"
            )
            
            if blocked_prod and args.verbose:
                print("\n⚠️  TAREFAS BLOQUEADAS POR DEPENDÊNCIA:")
                for cve, server, sw, reason in blocked_prod[:10]:
                    print(f"   - {cve.id} → {server.id}: {reason}")
                if len(blocked_prod) > 10:
                    print(f"   ... e mais {len(blocked_prod) - 10} tarefas bloqueadas")
        
        # Mostrar estado do pipeline se pedido
        if args.show_pipeline:
            if dep_manager is None:
                dep_manager = DependencyManager(servers)
            
            summary = dep_manager.get_pipeline_summary()
            print("\n" + "=" * 50)
            print("🔄 ESTADO DO PIPELINE DEV → TEST → PROD")
            print("=" * 50)
            print(f"Grupos de dependência: {summary['total_groups']}")
            print(f"Registos de patches: {summary['total_records']}")
            print(f"Patches bloqueados para PROD: {summary['blocked_count']}")
            
            if summary['blocked_by_group']:
                print("\nBloqueados por grupo:")
                for group, cves in summary['blocked_by_group'].items():
                    print(f"  {group}: {len(cves)} CVEs bloqueados")
            print("=" * 50 + "\n")
        
        # 4. Executar agendamento com métricas
        logger.info("A executar agendamento...")
        logger.info(f"Horizonte de planeamento: {planning_period.total_days} dias ({planning_period.weeks} semanas)")
        
        # Passar informação de disponibilidade ao scheduler
        schedule, metrics = create_schedule_with_metrics(
            tasks_to_plan, 
            workers,
            planning_weeks=planning_period.weeks,
            availability_manager=availability_manager
        )
        
        logger.info(f"Agendamento concluído: {metrics}")
        
        # 5. Registar patches agendados (se pedido)
        if args.track_patches and tracker and schedule:
            # O schedule já contém objetos com cve e server
            scheduled_tasks = []
            for item in schedule:
                if hasattr(item, 'cve') and hasattr(item, 'server'):
                    scheduled_tasks.append(item)
            
            if scheduled_tasks:
                tracker.record_scheduled_tasks(scheduled_tasks)
                logger.info(f"Registadas {len(scheduled_tasks)} tarefas no histórico de patches")
        
        # 6. Gerar relatório
        generate_report(
            schedule, 
            metrics, 
            tasks_to_plan,
            args.output,
            args.max_display,
            servers,
            cves,
            workers,
            args.csv_path,
            cve_source=cve_source,
            cve_stats=cve_stats,
            tracker=tracker
        )
        
        print(f"\n✅ [SUCESSO] Relatório gerado em '{args.output}'")
        print(f"📊 Log detalhado em 'plntdia.log'")
        
        # Gerar relatório de patches se pedido
        if args.patch_report and tracker:
            report = tracker.generate_report(args.patch_report)
            print(f"📋 Relatório de patches em '{args.patch_report}'")
        
    except FileNotFoundError as e:
        logger.error(f"Ficheiro não encontrado: {e}")
        print(f"\n❌ [ERRO] Ficheiro não encontrado: {e}")
        print("   Certifique-se que os ficheiros necessários existem:")
        print("   - Pasta 'csv/' com servers.csv, server_applications.csv, etc.")
        print("   - Ou dataset especificado com --dataset")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Erro durante execução: {e}")
        print(f"\n❌ [ERRO] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()