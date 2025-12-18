from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


# --- ENUMS PARA TYPE SAFETY ---
class Severity(Enum):
    """Níveis de severidade CVSS."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    
    @property
    def score(self) -> float:
        """Retorna o score numérico associado à severidade."""
        scores = {"Low": 2.0, "Medium": 5.0, "High": 8.0, "Critical": 10.0}
        return scores[self.value]
    
    @classmethod
    def from_string(cls, value: str) -> 'Severity':
        """Cria Severity a partir de string, com fallback para LOW."""
        for sev in cls:
            if sev.value.lower() == value.lower():
                return sev
        logger.warning(f"Severidade desconhecida '{value}', usando LOW")
        return cls.LOW


# --- 1. SOFTWARE (A nova camada intermédia) ---
@dataclass
class Software:
    """Representa um software instalado num servidor."""
    id: str                 # Ex: "Apache_HTTP_Server"
    version: str            # Ex: "2.4.50"
    criticality: float      # 1.0 (Baixo) a 10.0 (Crítico) - Impacto se este software falhar

    def __post_init__(self):
        """Validação após inicialização."""
        if not 0.0 <= self.criticality <= 10.0:
            raise ValueError(f"Criticality deve estar entre 0.0 e 10.0, recebido: {self.criticality}")
        if not self.id or not self.id.strip():
            raise ValueError("Software ID não pode ser vazio")

    def __repr__(self):
        return f"{self.id} v{self.version} (Crit: {self.criticality})"

# --- 2. SERVIDOR ---
@dataclass
class Server:
    """Representa um servidor na infraestrutura."""
    id: str
    os_name: str            # Ex: "Ubuntu"
    os_version: str         # Ex: "20.04"
    rto_hours: int          # Recovery Time Objective (Ex: 4 horas max de paragem)
    
    # Lista de janelas: (DiaSemana, HoraInicio, HoraFim)
    # 0=Segunda ... 6=Domingo
    downtime_windows: List[Tuple[int, int, int]]
    
    # O que está instalado neste servidor
    installed_software: List[Software] = field(default_factory=list)
    
    # Novos campos para pipeline DEV -> TEST -> PROD
    environment: str = "PROD"           # DEV, TEST, ou PROD
    application_group: str = ""         # Ex: "WebPortal", "ERP", "Database"
    dependency_group: str = ""          # Ex: "GRP_WebPortal" - liga DEV/TEST/PROD do mesmo grupo

    def __post_init__(self):
        """Validação após inicialização."""
        if self.rto_hours <= 0:
            raise ValueError(f"RTO deve ser positivo, recebido: {self.rto_hours}")
        if not self.id or not self.id.strip():
            raise ValueError("Server ID não pode ser vazio")
        # Validar janelas de downtime
        for day, start, end in self.downtime_windows:
            if not (0 <= day <= 6):
                raise ValueError(f"Dia da semana inválido: {day}")
            if not (0 <= start < end <= 24):
                raise ValueError(f"Janela inválida: {start}-{end}")
        # Validar environment
        if self.environment not in ["DEV", "TEST", "PROD", ""]:
            logger.warning(f"Environment desconhecido '{self.environment}', assumindo PROD")
            self.environment = "PROD"

    def add_software(self, sw: Software):
        """Adiciona software ao servidor."""
        if sw not in self.installed_software:
            self.installed_software.append(sw)
    
    def has_software(self, software_id: str, version: str) -> bool:
        """Verifica se o servidor tem um software específico."""
        return any(s.id == software_id and s.version == version 
                   for s in self.installed_software)
    
    @property
    def is_production(self) -> bool:
        """Verifica se é um servidor de produção."""
        return self.environment == "PROD"
    
    @property
    def is_test(self) -> bool:
        """Verifica se é um servidor de teste."""
        return self.environment == "TEST"
    
    @property
    def is_dev(self) -> bool:
        """Verifica se é um servidor de desenvolvimento."""
        return self.environment == "DEV"

# --- 3. CVE / PATCH ---
@dataclass
class CVE:
    """Representa uma vulnerabilidade (CVE) e o patch associado."""
    id: str                 # Ex: "CVE-2024-1234"
    severity: str           # "Low", "Medium", "High", "Critical" (CVSS qualitativo)
    epss_score: float       # Output do ML: Probabilidade de exploração (0.0 a 1.0)
    
    # Ligação ao Software
    affected_software_id: str      # Ex: "Apache_HTTP_Server"
    affected_software_version: str # Ex: "2.4.50" (Simplificado, num real seria um range)
    
    # Restrições de Patching
    estimated_fix_time: int # Duração em horas
    operators_required: int # Nº de pessoas
    
    # Propriedade calculada posteriormente (Prioridade Final)
    final_priority_score: float = 0.0

    def __post_init__(self):
        """Validação após inicialização."""
        if not 0.0 <= self.epss_score <= 1.0:
            raise ValueError(f"EPSS score deve estar entre 0.0 e 1.0, recebido: {self.epss_score}")
        if self.estimated_fix_time <= 0:
            raise ValueError(f"Tempo de fix deve ser positivo, recebido: {self.estimated_fix_time}")
        if self.operators_required <= 0:
            raise ValueError(f"Operadores requeridos deve ser positivo, recebido: {self.operators_required}")

    @property
    def severity_enum(self) -> Severity:
        """Retorna a severidade como Enum."""
        return Severity.from_string(self.severity)
    
    @property
    def severity_score(self) -> float:
        """Retorna o score numérico da severidade."""
        return self.severity_enum.score
    
    @property
    def risk_level(self) -> str:
        """Classificação de risco baseada em EPSS."""
        if self.epss_score >= 0.7:
            return "ALTO"
        elif self.epss_score >= 0.3:
            return "MÉDIO"
        return "BAIXO"
    

# --- 4. OPERÁRIO ---
@dataclass
class Worker:
    """Representa um técnico/operário."""
    id: str
    name: str = ""
    level: str = "Junior"  # Junior, Mid, Senior
    skills: List[str] = field(default_factory=list)  # Ex: ["Patch Management", "SQL Server"]
    weekly_shifts: List[Tuple[int, int, int]] = field(default_factory=list)
    
    # Lista de IDs dos servidores onde este técnico PODE tocar
    # Ex: ["Srv_Production", "Srv_Backup"]
    authorized_server_ids: List[str] = field(default_factory=list)
    
    # Máximo de horas por dia (requisito do documento)
    max_daily_hours: int = 8
    
    # On-call (disponível para emergências)
    on_call: bool = False

    def __post_init__(self):
        """Validação após inicialização."""
        if not self.id or not self.id.strip():
            raise ValueError("Worker ID não pode ser vazio")
        # Validar turnos (se existirem)
        for shift in self.weekly_shifts:
            if len(shift) == 3:
                day, start, end = shift
                if not (0 <= day <= 6):
                    raise ValueError(f"Dia da semana inválido no turno: {day}")
                if not (0 <= start < end <= 24):
                    raise ValueError(f"Turno inválido: {start}-{end}")

    def can_access_server(self, server_id: str) -> bool:
        """Verifica se o worker tem autorização para o servidor."""
        # Se não há restrições, pode aceder a tudo
        if not self.authorized_server_ids:
            return True
        return server_id in self.authorized_server_ids
    
    def has_skill(self, skill: str) -> bool:
        """Verifica se o worker tem uma skill específica."""
        return any(skill.lower() in s.lower() for s in self.skills)


# --- 5. O OBJETO FINAL (O Plano) ---
@dataclass
class PatchTask:
    """Representa uma tarefa de patching agendada."""
    cve: CVE
    server: Server
    software: Software
    workers: List['Worker']    
    start_time: int     # Hora absoluta na simulação (0 a 168)
    end_time: int
    
    @property
    def duration(self) -> int:
        """Duração da tarefa em horas."""
        return self.end_time - self.start_time
    
    @property
    def day(self) -> int:
        """Dia da semana (0=Segunda, 6=Domingo)."""
        return (self.start_time // 24) % 7
    
    @property
    def hour(self) -> int:
        """Hora do dia (0-23)."""
        return self.start_time % 24
    
    def __repr__(self):
        workers_str = ", ".join(w.id for w in self.workers)
        return f"PatchTask({self.cve.id} @ {self.server.id}, {self.start_time}h-{self.end_time}h, Team: [{workers_str}])"