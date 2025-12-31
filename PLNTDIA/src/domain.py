from dataclasses import dataclass, field
from typing import List, Tuple, Optional

# --- 1. SOFTWARE (A nova camada intermédia) ---
@dataclass
class Software:
    id: str                 # Ex: "Apache_HTTP_Server"
    version: str            # Ex: "2.4.50"
    criticality: float      # 1.0 (Baixo) a 10.0 (Crítico) - Impacto se este software falhar

    def __repr__(self):
        return f"{self.id} v{self.version} (Crit: {self.criticality})"

# --- 2. SERVIDOR ---
@dataclass
class Server:
    id: str
    os_name: str
    os_version: str
    rto_hours: int
    downtime_windows: List[Tuple[int, int, int]] = field(default_factory=list)
    installed_software: List[Software] = field(default_factory=list)

    @property
    def environment(self):
        return self.id.split('_')[1] # Extrai DEV, UAT ou PROD

    @property
    def chain_id(self):
        return self.id.split('_')[2] # Extrai o número 001, 002...

    @property
    def env_rank(self):
        # Define a ordem lógica
        return {"DEV": 1, "UAT": 2, "PROD": 3}.get(self.environment, 99)

# --- 3. CVE / PATCH ---
@dataclass
class CVE:
    id: str                 # Ex: "CVE-2024-1234"
    severity: str           # "Low", "Medium", "High", "Critical" (CVSS qualitativo)
    epss_score: float       # Output do ML: Probabilidade de exploração (0.0 a 1.0)
    
    # Ligação ao Software
    affected_software_id: str      # Ex: "Apache_HTTP_Server"
    affected_software_version: str # Ex: "2.4.50" (Simplificado, num real seria um range)
    
    # Restrições de Patching
    operators_required: int # Nº de pessoas
    
    # Propriedade calculada posteriormente (Prioridade Final)
    final_priority_score: float = 0.0
    

# --- 4. OPERÁRIO ---
@dataclass
class Worker:
    id: str
    name: str # Adicionámos o nome para ficar bonito no relatório
    level: str # 'Junior', 'Mid', 'Senior'
    skills: List[str] = field(default_factory=list) # Novidade
    weekly_shifts: List[Tuple[int, int, int]] = field(default_factory=list)
    # Este campo continua a ser crucial para o algoritmo saber onde ele pode tocar.
    # Mas agora será preenchido automaticamente pelo código!
    authorized_server_ids: List[str] = field(default_factory=list)
    is_on_call: bool = False # NOVO: Define se pode fazer 12h/dia e noites/FDS



    def __repr__(self):
        # Útil para o Debug que fizemos antes
        status = "ON-CALL" if self.is_on_call else "NORMAL"
        return f"{self.name} ({self.level}) [{status}]"


# --- 5. O OBJETO FINAL (O Plano) ---
@dataclass
class PatchTask:
    """Representa uma linha do output final desejado"""
    cve: CVE
    server: Server
    software: Software
    workers: List[Worker]    
    start_time: int  # Agora pode ir de 0 até 8760 (1 ano em horas)
    end_time: int
    # [NOVO] Flag para identificar se esta tarefa violou a janela de manutenção (Soft RTO)
    # Se True, significa que o patch demora mais tempo do que a janela permite,
    # mas foi agendado na mesma (requer aprovação humana).
    rto_violation: bool = False


@dataclass
class FailedTask:
    """Representa uma tarefa que NÃO foi possível agendar"""
    cve: CVE
    server: Server
    reason: str # Ex: "Dependência de DEV não satisfeita" ou "Sem vaga na agenda"