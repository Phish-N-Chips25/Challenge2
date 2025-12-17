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
    os_name: str            # Ex: "Ubuntu"
    os_version: str         # Ex: "20.04"
    rto_hours: int          # Recovery Time Objective (Ex: 4 horas max de paragem)
    
    # Lista de janelas: (DiaSemana, HoraInicio, HoraFim)
    # 0=Segunda ... 6=Domingo
    downtime_windows: List[Tuple[int, int, int]]
    
    # O que está instalado neste servidor
    installed_software: List[Software] = field(default_factory=list)

    def add_software(self, sw: Software):
        self.installed_software.append(sw)

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
    estimated_fix_time: int # Duração em horas
    operators_required: int # Nº de pessoas
    
    # Propriedade calculada posteriormente (Prioridade Final)
    final_priority_score: float = 0.0
    

# --- 4. OPERÁRIO ---
@dataclass
class Worker:
    id: str
    weekly_shifts: List[Tuple[int, int, int]] = field(default_factory=list)
    
    # NOVO CAMPO: Lista de IDs dos servidores onde este técnico PODE tocar
    # Ex: ["Srv_Production", "Srv_Backup"]
    authorized_server_ids: List[str] = field(default_factory=list)


# --- 5. O OBJETO FINAL (O Plano) ---
@dataclass
class PatchTask:
    """Representa uma linha do output final desejado"""
    cve: CVE
    server: Server
    software: Software
    workers: List[Worker]    
    start_time: int     # Hora absoluta na simulação (0 a 168)
    end_time: int