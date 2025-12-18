"""
Módulo de Gestão de Dependências DEV → TEST → PROD

Este módulo implementa a lógica de pipeline de deployment:
- Patches devem ser primeiro aplicados em DEV
- Depois em TEST
- Só após sucesso em TEST podem ir para PROD

Se um patch falha em TEST, não pode ser aplicado em PROD para
o mesmo dependency_group até ser resolvido.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .domain import Server, CVE, PatchTask

logger = logging.getLogger(__name__)


class PatchStatus(Enum):
    """Estado de um patch num ambiente."""
    PENDING = "pending"         # Ainda não aplicado
    SCHEDULED = "scheduled"     # Agendado para aplicação
    IN_PROGRESS = "in_progress" # A ser aplicado
    SUCCESS = "success"         # Aplicado com sucesso
    FAILED = "failed"           # Falhou na aplicação
    BLOCKED = "blocked"         # Bloqueado por dependência


@dataclass
class PatchDeploymentRecord:
    """Registo de um patch num ambiente específico."""
    cve_id: str
    software_id: str
    software_version: str
    dependency_group: str
    environment: str            # DEV, TEST, PROD
    status: PatchStatus
    scheduled_time: Optional[datetime] = None
    completed_time: Optional[datetime] = None
    worker_ids: List[str] = field(default_factory=list)
    server_id: str = ""
    failure_reason: str = ""


class DependencyManager:
    """
    Gestor de dependências para pipeline DEV → TEST → PROD.
    
    Regras:
    1. Um patch pode ser aplicado em DEV a qualquer momento
    2. Um patch só pode ir para TEST após sucesso em DEV (do mesmo dependency_group)
    3. Um patch só pode ir para PROD após sucesso em TEST (do mesmo dependency_group)
    4. Se um patch FALHA em TEST, é bloqueado para PROD até resolução
    """
    
    def __init__(self, servers: List[Server]):
        """
        Inicializa o gestor com a lista de servidores.
        
        Args:
            servers: Lista de servidores da infraestrutura
        """
        self.servers = servers
        self.servers_by_id: Dict[str, Server] = {s.id: s for s in servers}
        
        # Mapear servidores por dependency_group e environment
        self.groups: Dict[str, Dict[str, List[Server]]] = {}
        for srv in servers:
            if srv.dependency_group:
                if srv.dependency_group not in self.groups:
                    self.groups[srv.dependency_group] = {"DEV": [], "TEST": [], "PROD": []}
                if srv.environment in self.groups[srv.dependency_group]:
                    self.groups[srv.dependency_group][srv.environment].append(srv)
        
        # Histórico de patches por (cve_id, dependency_group, environment)
        self.patch_records: Dict[Tuple[str, str, str], PatchDeploymentRecord] = {}
        
        # CVEs bloqueados para PROD por dependency_group
        self.blocked_cves: Dict[str, Set[str]] = {}  # dependency_group -> set(cve_ids)
        
        logger.info(f"DependencyManager inicializado com {len(self.groups)} grupos de dependência")
        for group, envs in self.groups.items():
            logger.debug(f"  {group}: DEV={len(envs['DEV'])}, TEST={len(envs['TEST'])}, PROD={len(envs['PROD'])}")
    
    def get_server_environment(self, server_id: str) -> str:
        """Obtém o environment de um servidor."""
        srv = self.servers_by_id.get(server_id)
        if srv:
            return srv.environment
        # Fallback para parser do ID
        if "PROD" in server_id:
            return "PROD"
        elif "TEST" in server_id:
            return "TEST"
        elif "DEV" in server_id:
            return "DEV"
        return "PROD"  # Default mais restritivo
    
    def get_server_dependency_group(self, server_id: str) -> str:
        """Obtém o dependency_group de um servidor."""
        srv = self.servers_by_id.get(server_id)
        return srv.dependency_group if srv else ""
    
    def can_apply_patch(
        self,
        cve: CVE,
        server: Server,
        check_test_success: bool = True
    ) -> Tuple[bool, str]:
        """
        Verifica se um patch pode ser aplicado num servidor.
        
        Args:
            cve: CVE/patch a aplicar
            server: Servidor destino
            check_test_success: Se True, requer sucesso em TEST para PROD
            
        Returns:
            Tupla (pode_aplicar, razão)
        """
        env = server.environment
        dep_group = server.dependency_group
        
        # DEV pode sempre receber patches
        if env == "DEV":
            return True, "DEV aceita patches sem restrições"
        
        # TEST requer sucesso em DEV (opcional, mas bom para rastreamento)
        if env == "TEST":
            dev_key = (cve.id, dep_group, "DEV")
            dev_record = self.patch_records.get(dev_key)
            
            if dev_record and dev_record.status == PatchStatus.FAILED:
                return False, f"Patch {cve.id} falhou em DEV para grupo {dep_group}"
            
            # Permitir TEST mesmo sem DEV (para flexibilidade)
            return True, "TEST pode receber patch"
        
        # PROD requer sucesso em TEST
        if env == "PROD" and check_test_success:
            # Verificar se está bloqueado
            if dep_group in self.blocked_cves:
                if cve.id in self.blocked_cves[dep_group]:
                    return False, f"Patch {cve.id} bloqueado para PROD (falhou em TEST para grupo {dep_group})"
            
            # Verificar se há sucesso em TEST
            test_key = (cve.id, dep_group, "TEST")
            test_record = self.patch_records.get(test_key)
            
            if test_record:
                if test_record.status == PatchStatus.FAILED:
                    return False, f"Patch {cve.id} falhou em TEST para grupo {dep_group}"
                elif test_record.status == PatchStatus.SUCCESS:
                    return True, f"Patch {cve.id} aprovado em TEST para grupo {dep_group}"
            
            # Se não há registo em TEST, bloquear por padrão
            return False, f"Patch {cve.id} ainda não foi testado em TEST para grupo {dep_group}"
        
        return True, "Patch permitido"
    
    def record_patch_scheduled(
        self,
        cve: CVE,
        server: Server,
        scheduled_time: datetime,
        worker_ids: List[str]
    ):
        """Regista que um patch foi agendado."""
        key = (cve.id, server.dependency_group, server.environment)
        
        record = PatchDeploymentRecord(
            cve_id=cve.id,
            software_id=cve.affected_software_id,
            software_version=cve.affected_software_version,
            dependency_group=server.dependency_group,
            environment=server.environment,
            status=PatchStatus.SCHEDULED,
            scheduled_time=scheduled_time,
            worker_ids=worker_ids,
            server_id=server.id
        )
        
        self.patch_records[key] = record
        logger.debug(f"Patch {cve.id} agendado para {server.id} ({server.environment})")
    
    def record_patch_success(
        self,
        cve_id: str,
        server: Server,
        completed_time: datetime = None
    ):
        """Regista sucesso na aplicação de um patch."""
        key = (cve_id, server.dependency_group, server.environment)
        
        if key in self.patch_records:
            self.patch_records[key].status = PatchStatus.SUCCESS
            self.patch_records[key].completed_time = completed_time or datetime.now()
        else:
            # Criar registo se não existir
            self.patch_records[key] = PatchDeploymentRecord(
                cve_id=cve_id,
                software_id="",
                software_version="",
                dependency_group=server.dependency_group,
                environment=server.environment,
                status=PatchStatus.SUCCESS,
                completed_time=completed_time or datetime.now(),
                server_id=server.id
            )
        
        # Remover do bloqueio se estava bloqueado
        if server.dependency_group in self.blocked_cves:
            self.blocked_cves[server.dependency_group].discard(cve_id)
        
        logger.info(f"Patch {cve_id} aplicado com SUCESSO em {server.id} ({server.environment})")
    
    def record_patch_failure(
        self,
        cve_id: str,
        server: Server,
        failure_reason: str = "",
        completed_time: datetime = None
    ):
        """Regista falha na aplicação de um patch."""
        key = (cve_id, server.dependency_group, server.environment)
        
        if key in self.patch_records:
            self.patch_records[key].status = PatchStatus.FAILED
            self.patch_records[key].completed_time = completed_time or datetime.now()
            self.patch_records[key].failure_reason = failure_reason
        else:
            self.patch_records[key] = PatchDeploymentRecord(
                cve_id=cve_id,
                software_id="",
                software_version="",
                dependency_group=server.dependency_group,
                environment=server.environment,
                status=PatchStatus.FAILED,
                completed_time=completed_time or datetime.now(),
                server_id=server.id,
                failure_reason=failure_reason
            )
        
        # Se falhou em TEST, bloquear para PROD
        if server.environment == "TEST":
            if server.dependency_group not in self.blocked_cves:
                self.blocked_cves[server.dependency_group] = set()
            self.blocked_cves[server.dependency_group].add(cve_id)
            logger.warning(
                f"Patch {cve_id} FALHOU em TEST para grupo {server.dependency_group}. "
                f"Bloqueado para PROD até resolução."
            )
        
        logger.info(f"Patch {cve_id} FALHOU em {server.id} ({server.environment}): {failure_reason}")
    
    def unblock_patch(self, cve_id: str, dependency_group: str):
        """Remove o bloqueio de um patch para PROD (após correção manual)."""
        if dependency_group in self.blocked_cves:
            self.blocked_cves[dependency_group].discard(cve_id)
            logger.info(f"Patch {cve_id} desbloqueado para PROD no grupo {dependency_group}")
    
    def get_blocked_patches(self, dependency_group: str = None) -> Dict[str, Set[str]]:
        """Obtém CVEs bloqueados, opcionalmente filtrados por grupo."""
        if dependency_group:
            return {dependency_group: self.blocked_cves.get(dependency_group, set())}
        return dict(self.blocked_cves)
    
    def get_deployment_status(self, cve_id: str, dependency_group: str) -> Dict[str, PatchStatus]:
        """Obtém o estado do patch em cada ambiente para um grupo."""
        status = {}
        for env in ["DEV", "TEST", "PROD"]:
            key = (cve_id, dependency_group, env)
            record = self.patch_records.get(key)
            status[env] = record.status if record else PatchStatus.PENDING
        return status
    
    def filter_tasks_by_dependency(
        self,
        tasks: List[PatchTask],
        check_test_success: bool = True
    ) -> Tuple[List[PatchTask], List[Tuple[PatchTask, str]]]:
        """
        Filtra tarefas de patch baseado nas dependências.
        
        Args:
            tasks: Lista de tarefas a filtrar
            check_test_success: Se True, requer sucesso em TEST para PROD
            
        Returns:
            Tupla (tarefas_permitidas, tarefas_bloqueadas_com_razão)
        """
        allowed = []
        blocked = []
        
        for task in tasks:
            server = self.servers_by_id.get(task.server_id)
            if not server:
                allowed.append(task)  # Servidor desconhecido, permitir
                continue
            
            # Criar CVE mock para verificação
            cve = CVE(
                id=task.cve_id,
                severity="Medium",
                epss_score=0.5,
                affected_software_id=task.software_id,
                affected_software_version=task.software_version,
                estimated_fix_time=task.duration_hours,
                operators_required=1
            )
            
            can_apply, reason = self.can_apply_patch(cve, server, check_test_success)
            
            if can_apply:
                allowed.append(task)
            else:
                blocked.append((task, reason))
        
        return allowed, blocked
    
    def get_pipeline_summary(self) -> Dict:
        """Gera resumo do estado do pipeline de deployment."""
        summary = {
            "total_groups": len(self.groups),
            "total_records": len(self.patch_records),
            "blocked_count": sum(len(cves) for cves in self.blocked_cves.values()),
            "by_environment": {
                "DEV": {"success": 0, "failed": 0, "scheduled": 0, "pending": 0},
                "TEST": {"success": 0, "failed": 0, "scheduled": 0, "pending": 0},
                "PROD": {"success": 0, "failed": 0, "scheduled": 0, "pending": 0}
            },
            "blocked_by_group": dict(self.blocked_cves)
        }
        
        for key, record in self.patch_records.items():
            env = record.environment
            if env in summary["by_environment"]:
                if record.status == PatchStatus.SUCCESS:
                    summary["by_environment"][env]["success"] += 1
                elif record.status == PatchStatus.FAILED:
                    summary["by_environment"][env]["failed"] += 1
                elif record.status == PatchStatus.SCHEDULED:
                    summary["by_environment"][env]["scheduled"] += 1
                else:
                    summary["by_environment"][env]["pending"] += 1
        
        return summary
