"""
Módulo para tracking de patches aplicados aos servidores.

Este módulo permite:
- Registar patches aplicados com sucesso
- Consultar histórico de patches por servidor/CVE/data
- Verificar se um CVE já foi aplicado a um servidor
- Gerar relatórios de patches aplicados
"""

import csv
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path

from .domain import CVE, Server, PatchTask

logger = logging.getLogger(__name__)


@dataclass
class AppliedPatch:
    """Representa um patch aplicado a um servidor."""
    cve_id: str
    server_id: str
    software_id: str
    software_version: str
    severity: str
    applied_date: str
    applied_by: str  # worker_id
    window_start: str
    window_end: str
    duration_hours: float
    status: str = "SUCCESS"  # SUCCESS, FAILED, ROLLBACK
    notes: str = ""
    
    def to_dict(self) -> Dict:
        """Converte para dicionário."""
        return asdict(self)


@dataclass
class PatchHistory:
    """Histórico completo de patches."""
    patches: List[AppliedPatch] = field(default_factory=list)
    
    def add_patch(self, patch: AppliedPatch) -> None:
        """Adiciona um patch ao histórico."""
        self.patches.append(patch)
    
    def get_patches_by_server(self, server_id: str) -> List[AppliedPatch]:
        """Retorna patches aplicados a um servidor."""
        return [p for p in self.patches if p.server_id == server_id]
    
    def get_patches_by_cve(self, cve_id: str) -> List[AppliedPatch]:
        """Retorna patches para um CVE específico."""
        return [p for p in self.patches if p.cve_id == cve_id]
    
    def get_patches_by_date_range(self, start: datetime, end: datetime) -> List[AppliedPatch]:
        """Retorna patches aplicados num período."""
        result = []
        for p in self.patches:
            try:
                patch_date = datetime.strptime(p.applied_date[:10], '%Y-%m-%d')
                if start <= patch_date <= end:
                    result.append(p)
            except ValueError:
                continue
        return result
    
    def is_cve_applied_to_server(self, cve_id: str, server_id: str) -> bool:
        """Verifica se um CVE já foi aplicado ou agendado para um servidor."""
        return any(p.cve_id == cve_id and p.server_id == server_id and p.status in ["SUCCESS", "SCHEDULED"]
                   for p in self.patches)
    
    def get_pending_cves_for_server(self, server_id: str, all_cves: List[str]) -> List[str]:
        """Retorna CVEs ainda não aplicados a um servidor."""
        applied = {p.cve_id for p in self.patches 
                   if p.server_id == server_id and p.status == "SUCCESS"}
        return [cve for cve in all_cves if cve not in applied]


class PatchTracker:
    """
    Gestor de histórico de patches aplicados.
    
    Guarda e carrega histórico de patches em formato CSV.
    """
    
    CSV_HEADERS = [
        'cve_id', 'server_id', 'software_id', 'software_version',
        'severity', 'applied_date', 'applied_by', 'window_start',
        'window_end', 'duration_hours', 'status', 'notes'
    ]
    
    def __init__(self, history_file: str = None):
        """
        Inicializa o tracker.
        
        Args:
            history_file: Caminho para o ficheiro de histórico CSV.
                         Se None, usa data/applied_patches.csv
        """
        if history_file is None:
            # Default: data/applied_patches.csv na pasta do projeto
            base_dir = Path(__file__).parent.parent
            history_file = str(base_dir / 'data' / 'applied_patches.csv')
        
        self.history_file = history_file
        self.history = PatchHistory()
        
        # Carregar histórico existente
        if os.path.exists(self.history_file):
            self._load_history()
        else:
            logger.info(f"Histórico de patches não existe, será criado: {self.history_file}")
    
    def _load_history(self) -> None:
        """Carrega histórico do ficheiro CSV."""
        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    patch = AppliedPatch(
                        cve_id=row['cve_id'],
                        server_id=row['server_id'],
                        software_id=row['software_id'],
                        software_version=row.get('software_version', ''),
                        severity=row.get('severity', 'MEDIUM'),
                        applied_date=row['applied_date'],
                        applied_by=row.get('applied_by', ''),
                        window_start=row.get('window_start', ''),
                        window_end=row.get('window_end', ''),
                        duration_hours=float(row.get('duration_hours', 0)),
                        status=row.get('status', 'SUCCESS'),
                        notes=row.get('notes', '')
                    )
                    self.history.add_patch(patch)
            logger.info(f"Carregados {len(self.history.patches)} patches do histórico")
        except Exception as e:
            logger.error(f"Erro ao carregar histórico: {e}")
            raise
    
    def _save_history(self) -> None:
        """Guarda histórico completo no ficheiro CSV."""
        # Criar diretório se não existir
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        
        with open(self.history_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.CSV_HEADERS)
            writer.writeheader()
            for patch in self.history.patches:
                writer.writerow(patch.to_dict())
        
        logger.info(f"Guardados {len(self.history.patches)} patches no histórico")
    
    def _append_patch(self, patch: AppliedPatch) -> None:
        """Adiciona um patch ao ficheiro (append mode)."""
        file_exists = os.path.exists(self.history_file)
        
        # Criar diretório se não existir
        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        
        with open(self.history_file, 'a', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.CSV_HEADERS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(patch.to_dict())
    
    def record_patch(
        self,
        cve: CVE,
        server: Server,
        worker_id: str,
        window_start: datetime,
        window_end: datetime,
        status: str = "SUCCESS",
        notes: str = ""
    ) -> AppliedPatch:
        """
        Regista um patch aplicado.
        
        Args:
            cve: O CVE aplicado
            server: O servidor onde foi aplicado
            worker_id: ID do trabalhador que aplicou
            window_start: Início da janela de manutenção
            window_end: Fim da janela de manutenção
            status: Estado (SUCCESS, FAILED, ROLLBACK)
            notes: Notas adicionais
            
        Returns:
            O AppliedPatch criado
        """
        # Encontrar o software no servidor que corresponde ao CVE
        software_id = ""
        software_version = ""
        for software in server.software:
            if software.software_id == cve.software_id:
                software_id = software.software_id
                software_version = software.version
                break
        
        # Se não encontrou, usar o do CVE
        if not software_id:
            software_id = cve.software_id
            software_version = ""
        
        patch = AppliedPatch(
            cve_id=cve.cve_id,
            server_id=server.server_id,
            software_id=software_id,
            software_version=software_version,
            severity=cve.severity,
            applied_date=datetime.now().isoformat(),
            applied_by=worker_id,
            window_start=window_start.isoformat(),
            window_end=window_end.isoformat(),
            duration_hours=cve.time_to_patch,
            status=status,
            notes=notes
        )
        
        self.history.add_patch(patch)
        self._append_patch(patch)
        
        logger.info(f"Registado patch: {cve.cve_id} -> {server.server_id} por {worker_id}")
        
        return patch
    
    def record_scheduled_tasks(
        self,
        scheduled_tasks: List[PatchTask],
        execution_date: datetime = None
    ) -> List[AppliedPatch]:
        """
        Regista múltiplas tarefas agendadas como patches aplicados.
        
        Args:
            scheduled_tasks: Lista de PatchTask agendadas com sucesso
            execution_date: Data de execução (default: agora)
            
        Returns:
            Lista de AppliedPatch criados
        """
        if execution_date is None:
            execution_date = datetime.now()
        
        patches = []
        for task in scheduled_tasks:
            # Obter worker responsável (primeiro da lista)
            worker_id = task.workers[0].id if task.workers else ""
            
            # Calcular timestamps baseados no start_time/end_time
            # start_time é hora absoluta (0-168 para semana)
            day = task.day
            start_hour = task.hour
            end_hour = task.end_time % 24
            
            # Criar data relativa à data de execução
            base_date = execution_date.replace(hour=0, minute=0, second=0, microsecond=0)
            from datetime import timedelta
            window_start = base_date + timedelta(days=day, hours=start_hour)
            window_end = base_date + timedelta(days=day, hours=end_hour)
            
            patch = AppliedPatch(
                cve_id=task.cve.id,
                server_id=task.server.id,
                software_id=task.software.id,
                software_version=task.software.version,
                severity=task.cve.severity,
                applied_date=execution_date.isoformat(),
                applied_by=worker_id,
                window_start=window_start.isoformat(),
                window_end=window_end.isoformat(),
                duration_hours=task.duration,
                status="SCHEDULED",
                notes=f"Agendado: {task}"
            )
            
            self.history.add_patch(patch)
            patches.append(patch)
        
        # Guardar tudo de uma vez
        self._save_history()
        
        logger.info(f"Registadas {len(patches)} tarefas agendadas")
        
        return patches
    
    def mark_as_applied(self, cve_id: str, server_id: str, notes: str = "") -> bool:
        """
        Marca um patch agendado como aplicado.
        
        Args:
            cve_id: ID do CVE
            server_id: ID do servidor
            notes: Notas adicionais
            
        Returns:
            True se encontrou e atualizou, False caso contrário
        """
        for patch in self.history.patches:
            if patch.cve_id == cve_id and patch.server_id == server_id and patch.status == "SCHEDULED":
                patch.status = "SUCCESS"
                patch.applied_date = datetime.now().isoformat()
                if notes:
                    patch.notes = notes
                self._save_history()
                logger.info(f"Patch marcado como aplicado: {cve_id} -> {server_id}")
                return True
        return False
    
    def mark_as_failed(self, cve_id: str, server_id: str, notes: str = "") -> bool:
        """
        Marca um patch como falhado.
        
        Args:
            cve_id: ID do CVE
            server_id: ID do servidor
            notes: Notas sobre a falha
            
        Returns:
            True se encontrou e atualizou, False caso contrário
        """
        for patch in self.history.patches:
            if patch.cve_id == cve_id and patch.server_id == server_id and patch.status in ["SCHEDULED", "SUCCESS"]:
                patch.status = "FAILED"
                patch.applied_date = datetime.now().isoformat()
                if notes:
                    patch.notes = notes
                self._save_history()
                logger.info(f"Patch marcado como falhado: {cve_id} -> {server_id}")
                return True
        return False
    
    def _get_server_software_version(self, server: Server, software_id: str) -> str:
        """Obtém a versão de um software num servidor."""
        for software in server.software:
            if software.software_id == software_id:
                return software.version
        return ""
    
    def is_already_patched(self, cve_id: str, server_id: str) -> bool:
        """Verifica se um CVE já foi aplicado a um servidor."""
        return self.history.is_cve_applied_to_server(cve_id, server_id)
    
    def get_pending_for_server(self, server_id: str, all_cve_ids: List[str]) -> List[str]:
        """Retorna CVEs ainda não aplicados a um servidor."""
        return self.history.get_pending_cves_for_server(server_id, all_cve_ids)
    
    def get_statistics(self) -> Dict:
        """
        Retorna estatísticas do histórico de patches.
        
        Returns:
            Dicionário com estatísticas
        """
        if not self.history.patches:
            return {
                'total': 0,
                'success': 0,
                'failed': 0,
                'scheduled': 0,
                'servers_patched': 0,
                'unique_cves': 0,
                'by_severity': {}
            }
        
        total = len(self.history.patches)
        success = sum(1 for p in self.history.patches if p.status == "SUCCESS")
        failed = sum(1 for p in self.history.patches if p.status == "FAILED")
        scheduled = sum(1 for p in self.history.patches if p.status == "SCHEDULED")
        
        servers = set(p.server_id for p in self.history.patches)
        cves = set(p.cve_id for p in self.history.patches)
        
        by_severity = {}
        for p in self.history.patches:
            sev = p.severity or 'UNKNOWN'
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return {
            'total': total,
            'success': success,
            'failed': failed,
            'scheduled': scheduled,
            'rollback': total - success - failed - scheduled,
            'servers_patched': len(servers),
            'unique_cves': len(cves),
            'by_severity': by_severity
        }
    
    def generate_report(self, output_file: str = None) -> str:
        """
        Gera um relatório em texto do histórico de patches.
        
        Args:
            output_file: Ficheiro de saída (opcional)
            
        Returns:
            Relatório em formato texto
        """
        stats = self.get_statistics()
        
        lines = [
            "=" * 60,
            "RELATÓRIO DE PATCHES APLICADOS",
            "=" * 60,
            f"Data do relatório: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "RESUMO GERAL",
            "-" * 40,
            f"Total de patches:     {stats['total']}",
            f"  - Com sucesso:      {stats['success']}",
            f"  - Agendados:        {stats['scheduled']}",
            f"  - Falhados:         {stats['failed']}",
            f"  - Rollback:         {stats['rollback']}",
            f"Servidores afetados:  {stats['servers_patched']}",
            f"CVEs únicos:          {stats['unique_cves']}",
            "",
            "POR SEVERIDADE",
            "-" * 40,
        ]
        
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = stats['by_severity'].get(sev, 0)
            lines.append(f"  {sev:12}: {count}")
        
        if self.history.patches:
            lines.extend([
                "",
                "ÚLTIMOS 10 PATCHES",
                "-" * 40,
            ])
            
            recent = sorted(self.history.patches, 
                           key=lambda p: p.applied_date, 
                           reverse=True)[:10]
            
            for p in recent:
                date = p.applied_date[:10] if p.applied_date else "N/A"
                lines.append(f"  {date} | {p.cve_id:15} | {p.server_id:12} | {p.status}")
        
        lines.append("")
        lines.append("=" * 60)
        
        report = "\n".join(lines)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Relatório guardado em: {output_file}")
        
        return report


def filter_unapplied_cves(
    cves: List[CVE],
    servers: List[Server],
    tracker: PatchTracker
) -> List[CVE]:
    """
    Filtra CVEs que ainda não foram aplicados a todos os servidores afetados.
    
    Args:
        cves: Lista de CVEs
        servers: Lista de servidores
        tracker: PatchTracker com histórico
        
    Returns:
        Lista de CVEs que ainda precisam ser aplicados
    """
    unapplied = []
    
    for cve in cves:
        # Usar o atributo correto: affected_software_id
        cve_software_id = getattr(cve, 'affected_software_id', None) or getattr(cve, 'software_id', None)
        cve_id = getattr(cve, 'id', None) or getattr(cve, 'cve_id', None)
        
        if not cve_software_id or not cve_id:
            continue
        
        # Encontrar servidores afetados por este CVE
        # Server pode ter 'installed_software' ou 'software'
        affected_servers = []
        for s in servers:
            server_software = getattr(s, 'installed_software', None) or getattr(s, 'software', [])
            if any(sw.id == cve_software_id for sw in server_software):
                affected_servers.append(s)
        
        # Verificar se foi aplicado a todos
        needs_patching = False
        for server in affected_servers:
            server_id = getattr(server, 'id', None) or getattr(server, 'server_id', None)
            if server_id and not tracker.is_already_patched(cve_id, server_id):
                needs_patching = True
                break
        
        if needs_patching:
            unapplied.append(cve)
    
    return unapplied
