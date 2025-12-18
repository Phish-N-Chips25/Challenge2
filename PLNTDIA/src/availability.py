"""
Módulo de Gestão de Disponibilidade da Equipa

Este módulo gere:
- Férias e ausências planeadas
- Período de planeamento (horizonte temporal)
- Verificação de disponibilidade em datas específicas
"""

import csv
import os
import logging
from datetime import datetime, timedelta, date
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Holiday:
    """Representa um feriado nacional/regional."""
    date: date
    name: str
    holiday_type: str  # feriado_nacional, feriado_facultativo, feriado_municipal
    
    def __hash__(self):
        return hash(self.date)
    
    def __eq__(self, other):
        if isinstance(other, Holiday):
            return self.date == other.date
        return False


@dataclass
class Absence:
    """Representa uma ausência (férias, formação, etc.)."""
    worker_id: str
    start_date: date
    end_date: date
    absence_type: str  # ferias, formacao, doenca, outro
    notes: str = ""
    
    def includes_date(self, check_date: date) -> bool:
        """Verifica se uma data está dentro do período de ausência."""
        return self.start_date <= check_date <= self.end_date
    
    def overlaps_period(self, period_start: date, period_end: date) -> bool:
        """Verifica se há sobreposição com um período."""
        return not (self.end_date < period_start or self.start_date > period_end)
    
    @property
    def duration_days(self) -> int:
        """Duração da ausência em dias."""
        return (self.end_date - self.start_date).days + 1


@dataclass
class PlanningPeriod:
    """Define o período de planeamento."""
    start_date: date
    end_date: date
    total_days: int
    weeks: int
    
    @classmethod
    def from_days(cls, days: int, start_from: date = None) -> 'PlanningPeriod':
        """Cria período a partir de número de dias."""
        if start_from is None:
            start_from = date.today()
        end = start_from + timedelta(days=days - 1)
        return cls(
            start_date=start_from,
            end_date=end,
            total_days=days,
            weeks=(days + 6) // 7
        )
    
    def get_week_dates(self, week_num: int) -> Tuple[date, date]:
        """Retorna início e fim de uma semana específica do período."""
        week_start = self.start_date + timedelta(days=week_num * 7)
        week_end = min(week_start + timedelta(days=6), self.end_date)
        return week_start, week_end
    
    def date_to_absolute_hour(self, target_date: date, hour: int) -> int:
        """Converte uma data e hora para hora absoluta no período."""
        days_from_start = (target_date - self.start_date).days
        return days_from_start * 24 + hour


class AvailabilityManager:
    """
    Gestor de disponibilidade da equipa.
    
    Combina turnos semanais com férias/ausências e feriados para determinar
    disponibilidade real num período de planeamento.
    """
    
    def __init__(self, vacations_file: str = None, holidays_file: str = None):
        """
        Inicializa o gestor.
        
        Args:
            vacations_file: Caminho para ficheiro CSV de férias
            holidays_file: Caminho para ficheiro CSV de feriados
        """
        self.absences: List[Absence] = []
        self.absences_by_worker: Dict[str, List[Absence]] = {}
        self.holidays: Dict[date, Holiday] = {}
        
        if vacations_file and os.path.exists(vacations_file):
            self._load_absences(vacations_file)
        
        if holidays_file and os.path.exists(holidays_file):
            self._load_holidays(holidays_file)
    
    def _load_holidays(self, filepath: str) -> None:
        """Carrega feriados do ficheiro CSV."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        holiday_date = datetime.strptime(row['date'], '%Y-%m-%d').date()
                        holiday = Holiday(
                            date=holiday_date,
                            name=row['name'],
                            holiday_type=row.get('type', 'feriado_nacional')
                        )
                        self.holidays[holiday_date] = holiday
                    except (ValueError, KeyError) as e:
                        logger.warning(f"Erro ao processar feriado: {e}")
                        continue
            
            logger.info(f"Carregados {len(self.holidays)} feriados de {filepath}")
            
        except Exception as e:
            logger.error(f"Erro ao carregar ficheiro de feriados: {e}")
    
    def is_holiday(self, check_date: date) -> bool:
        """Verifica se uma data é feriado."""
        return check_date in self.holidays
    
    def get_holiday(self, check_date: date) -> Optional[Holiday]:
        """Retorna o feriado de uma data, se existir."""
        return self.holidays.get(check_date)
    
    def _load_absences(self, filepath: str) -> None:
        """Carrega ausências do ficheiro CSV."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        absence = Absence(
                            worker_id=row['worker_id'],
                            start_date=datetime.strptime(row['start_date'], '%Y-%m-%d').date(),
                            end_date=datetime.strptime(row['end_date'], '%Y-%m-%d').date(),
                            absence_type=row.get('type', 'ferias'),
                            notes=row.get('notes', '')
                        )
                        self.absences.append(absence)
                        
                        if absence.worker_id not in self.absences_by_worker:
                            self.absences_by_worker[absence.worker_id] = []
                        self.absences_by_worker[absence.worker_id].append(absence)
                        
                    except (ValueError, KeyError) as e:
                        logger.warning(f"Erro ao processar ausência: {e}")
                        continue
            
            logger.info(f"Carregadas {len(self.absences)} ausências de {filepath}")
            
        except Exception as e:
            logger.error(f"Erro ao carregar ficheiro de férias: {e}")
    
    def add_absence(self, absence: Absence) -> None:
        """Adiciona uma ausência manualmente."""
        self.absences.append(absence)
        if absence.worker_id not in self.absences_by_worker:
            self.absences_by_worker[absence.worker_id] = []
        self.absences_by_worker[absence.worker_id].append(absence)
    
    def add_holiday(self, holiday: Holiday) -> None:
        """Adiciona um feriado manualmente."""
        self.holidays[holiday.date] = holiday
    
    def is_worker_available(self, worker_id: str, check_date: date) -> bool:
        """
        Verifica se um worker está disponível numa data.
        
        Args:
            worker_id: ID do trabalhador
            check_date: Data a verificar
            
        Returns:
            True se disponível, False se tem ausência ou é feriado
        """
        # Verificar se é feriado (ninguém trabalha)
        if self.is_holiday(check_date):
            return False
        
        # Verificar ausências individuais
        worker_absences = self.absences_by_worker.get(worker_id, [])
        return not any(a.includes_date(check_date) for a in worker_absences)
    
    def get_unavailable_workers(self, check_date: date) -> Set[str]:
        """Retorna conjunto de workers indisponíveis numa data."""
        unavailable = set()
        for absence in self.absences:
            if absence.includes_date(check_date):
                unavailable.add(absence.worker_id)
        return unavailable
    
    def get_available_workers(self, worker_ids: List[str], check_date: date) -> List[str]:
        """Filtra lista de workers mantendo apenas os disponíveis."""
        # Se é feriado, ninguém está disponível
        if self.is_holiday(check_date):
            return []
        
        unavailable = self.get_unavailable_workers(check_date)
        return [w for w in worker_ids if w not in unavailable]
    
    def get_worker_absences_in_period(
        self, 
        worker_id: str, 
        period: PlanningPeriod
    ) -> List[Absence]:
        """Retorna ausências de um worker num período."""
        worker_absences = self.absences_by_worker.get(worker_id, [])
        return [a for a in worker_absences 
                if a.overlaps_period(period.start_date, period.end_date)]
    
    def get_holidays_in_period(self, period: PlanningPeriod) -> List[Holiday]:
        """Retorna feriados que caem dentro do período de planeamento."""
        return [
            h for h_date, h in sorted(self.holidays.items())
            if period.start_date <= h_date <= period.end_date
        ]
    
    def get_availability_summary(self, period: PlanningPeriod) -> Dict:
        """
        Gera resumo de disponibilidade para o período.
        
        Returns:
            Dicionário com estatísticas de disponibilidade
        """
        # Contar dias de ausência por worker
        days_off = {}
        for worker_id, absences in self.absences_by_worker.items():
            total = 0
            for absence in absences:
                if absence.overlaps_period(period.start_date, period.end_date):
                    # Contar apenas dias dentro do período
                    start = max(absence.start_date, period.start_date)
                    end = min(absence.end_date, period.end_date)
                    total += (end - start).days + 1
            if total > 0:
                days_off[worker_id] = total
        
        # Dias com menos recursos
        daily_unavailable = {}
        current = period.start_date
        while current <= period.end_date:
            unavailable = self.get_unavailable_workers(current)
            if unavailable:
                daily_unavailable[current.isoformat()] = list(unavailable)
            current += timedelta(days=1)
        
        # Feriados no período
        holidays_in_period = self.get_holidays_in_period(period)
        
        return {
            'period': f"{period.start_date} a {period.end_date}",
            'total_days': period.total_days,
            'workers_with_absences': len(days_off),
            'days_off_by_worker': days_off,
            'daily_unavailability': daily_unavailable,
            'holidays_in_period': holidays_in_period,
            'holiday_count': len(holidays_in_period)
        }
    
    def get_effective_shifts(
        self,
        worker_id: str,
        base_shifts: List[Tuple[int, int, int]],
        period: PlanningPeriod
    ) -> Dict[date, List[Tuple[int, int]]]:
        """
        Calcula turnos efetivos considerando ausências.
        
        Args:
            worker_id: ID do trabalhador
            base_shifts: Turnos semanais base [(dia_semana, hora_inicio, hora_fim), ...]
            period: Período de planeamento
            
        Returns:
            Dicionário {data: [(hora_inicio, hora_fim), ...]}
        """
        effective = {}
        current = period.start_date
        
        while current <= period.end_date:
            if self.is_worker_available(worker_id, current):
                # Worker disponível - aplicar turnos base
                weekday = current.weekday()
                day_shifts = [(start, end) for day, start, end in base_shifts if day == weekday]
                if day_shifts:
                    effective[current] = day_shifts
            # Se não disponível, não adiciona turnos para esse dia
            current += timedelta(days=1)
        
        return effective


def load_vacations(csv_path: str = None) -> AvailabilityManager:
    """
    Carrega férias do ficheiro CSV padrão ou especificado.
    
    Args:
        csv_path: Caminho base dos CSVs (default: csv/)
        
    Returns:
        AvailabilityManager configurado
    """
    if csv_path is None:
        csv_path = os.path.join(os.path.dirname(__file__), '..', 'csv')
    
    vacations_file = os.path.join(csv_path, 'team_vacations.csv')
    
    return AvailabilityManager(vacations_file if os.path.exists(vacations_file) else None)


def create_planning_period(
    days: int = None,
    period_str: str = None,
    start_date: date = None
) -> PlanningPeriod:
    """
    Cria um período de planeamento.
    
    Args:
        days: Número de dias (tem prioridade se especificado)
        period_str: String de período ("1 semana", "2 meses", etc.)
        start_date: Data de início (default: hoje)
        
    Returns:
        PlanningPeriod configurado
    """
    import re
    
    if start_date is None:
        start_date = date.today()
    
    # Se dias especificado diretamente, usar
    if days:
        return PlanningPeriod.from_days(days, start_date)
    
    # Parse do período string
    if period_str:
        period_str = period_str.lower().strip()
        match = re.match(
            r'(\d+)\s*(semana|semanas|week|weeks|mês|mes|meses|month|months|ano|anos|year|years|dia|dias|day|days)',
            period_str
        )
        
        if match:
            num = int(match.group(1))
            unit = match.group(2)
            
            if unit in ('semana', 'semanas', 'week', 'weeks'):
                days = num * 7
            elif unit in ('mês', 'mes', 'meses', 'month', 'months'):
                days = num * 30
            elif unit in ('ano', 'anos', 'year', 'years'):
                days = num * 365
            else:
                days = num
            
            return PlanningPeriod.from_days(days, start_date)
    
    # Default: 1 semana
    return PlanningPeriod.from_days(7, start_date)
