# Ficheiro: src/entities.py
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class Server:
    """
    Representa um servidor na infraestrutura.
    """
    id: str
    os: str
    criticality: float     # Importância para o negócio (ex: 1.0 a 10.0)
    
    # Lista de janelas de manutenção permitidas.
    # Formato da Tupla: (Dia_da_Semana, Hora_Inicio, Hora_Fim)
    # Onde: 0=Segunda, ..., 6=Domingo. As horas são 0-24.
    maintenance_windows: List[Tuple[int, int, int]] 
    
    downtime_cost: float   # Custo financeiro por hora de paragem (ex: €/h)

@dataclass
class Patch:
    """
    Representa uma vulnerabilidade (CVE) que precisa de correção.
    """
    id: str
    risk_score: float      # Score EPSS ou similar (0.0 a 1.0)
    severity: str          # Texto descritivo (Low, Medium, High, Critical)
    estimated_time: int    # Duração estimada da aplicação do patch em horas
    affected_os: str       # Sistema operativo alvo (tem de bater certo com o Server)
    operators_needed: int  # Quantidade de técnicos necessários
    server_id: str         # ID do servidor onde será aplicado

@dataclass
class Operator:
    """
    Representa um técnico/operário disponível para aplicar patches.
    """
    id: str
    skills: List[str]      # Lista de OS que sabe gerir (ex: ["Linux", "Windows"])
    shift: Tuple[int, int] # Turno de trabalho diário (Hora_Inicio, Hora_Fim)