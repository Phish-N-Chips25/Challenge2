"""
Módulo para carregar CVEs reais do dataset merged_cve_data.csv

Este módulo permite:
- Filtrar CVEs dos últimos N dias ou de um mês específico
- Fazer match com o software instalado na infraestrutura
- Converter para objetos CVE do domínio
"""

import csv
import sys
import os
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass

from .domain import CVE, Server, Software

logger = logging.getLogger(__name__)

# Aumentar limite de campo CSV (alguns campos têm listas longas)
csv.field_size_limit(sys.maxsize)

# Mapeamento de software do dataset para IDs do nosso sistema
SOFTWARE_MAPPING = {
    # Microsoft SQL Server
    'sql server': 'SQL Server',
    'microsoft sql': 'SQL Server',
    'mssql': 'SQL Server',
    
    # MySQL
    'mysql': 'MySQL Server',
    'mysql server': 'MySQL Server',
    
    # Oracle Database
    'oracle database': 'Oracle Database',
    'oracle db': 'Oracle Database',
    'oracle_database': 'Oracle Database',
    
    # PostgreSQL
    'postgresql': 'PostgreSQL',
    'postgres': 'PostgreSQL',
    
    # Active Directory
    'active directory': 'Active Directory',
    'ad ds': 'Active Directory',
    'ldap': 'Active Directory',
    
    # Exchange
    'exchange server': 'Exchange',
    'microsoft exchange': 'Exchange',
    'exchange': 'Exchange',
    
    # IIS
    'internet information services': 'IIS',
    'iis': 'IIS',
    
    # SharePoint
    'sharepoint': 'SharePoint',
    'microsoft sharepoint': 'SharePoint',
    
    # Windows Server (genérico)
    'windows server': 'Windows Server',
    'windows': 'Windows Server',
    
    # Java
    'java': 'Java',
    'jdk': 'Java',
    'jre': 'Java',
    'openjdk': 'Java',
    
    # WebLogic
    'weblogic': 'WebLogic Server',
    'weblogic server': 'WebLogic Server',
    'oracle weblogic': 'WebLogic Server',
    
    # Apache Tomcat
    'tomcat': 'Apache Tomcat',
    'apache tomcat': 'Apache Tomcat',
    
    # Nginx
    'nginx': 'Nginx',
    
    # Node.js
    'node.js': 'Node.js',
    'nodejs': 'Node.js',
    'node': 'Node.js',
    
    # Redis
    'redis': 'Redis',
    
    # Elasticsearch
    'elasticsearch': 'Elasticsearch',
    'elastic': 'Elasticsearch',
    
    # .NET
    '.net framework': '.NET Framework',
    '.net': '.NET Framework',
    'dotnet': '.NET Framework',
    'asp.net': 'ASP.NET Core',
    
    # Python
    'python': 'Python',
    
    # Grafana
    'grafana': 'Grafana',
    
    # Prometheus
    'prometheus': 'Prometheus',
    
    # Zabbix
    'zabbix': 'Zabbix',
    
    # Kong
    'kong': 'Kong Gateway',
    'kong gateway': 'Kong Gateway',
    
    # RabbitMQ
    'rabbitmq': 'RabbitMQ',
    
    # Fortinet
    'fortinet': 'Fortinet FortiGate',
    'fortigate': 'Fortinet FortiGate',
    'fortios': 'Fortinet FortiGate',
    
    # CrowdStrike
    'crowdstrike': 'CrowdStrike Falcon',
    'falcon': 'CrowdStrike Falcon',
    
    # Dynamics 365
    'dynamics': 'Dynamics 365',
    'dynamics 365': 'Dynamics 365',
}

# Versões que mapeiam para as nossas versões instaladas
VERSION_MAPPING = {
    'SQL Server': ['2019', '2017', '2016'],
    'Active Directory': ['2016', '2019', '2022'],
    'Exchange': ['2016', '2019'],
    'IIS': ['10.0'],
    'SharePoint': ['2019', '2016'],
    'Windows Server': ['2019', '2022', '2016'],
    'MySQL Server': ['8.0', '5.7'],
    'Oracle Database': ['19c', '18c', '12c'],
    'PostgreSQL': ['15', '14', '13'],
    'Java': ['17', '11', '8'],
    'WebLogic Server': ['14.1', '12.2'],
    'Apache Tomcat': ['10.0', '9.0'],
    'Nginx': ['1.24', '1.22'],
    'Node.js': ['18', '16', '14'],
    'Redis': ['7.0', '6.2'],
    'Elasticsearch': ['8.0', '7.17'],
    '.NET Framework': ['4.8', '4.7'],
    'ASP.NET Core': ['6.0', '7.0'],
    'Python': ['3.11', '3.10', '3.9'],
    'Grafana': ['10.0', '9.0'],
    'Prometheus': ['2.45', '2.40'],
    'Zabbix': ['6.0', '5.4'],
    'Kong Gateway': ['3.0', '2.8'],
    'RabbitMQ': ['3.12', '3.11'],
    'Fortinet FortiGate': ['7.2', '7.0'],
    'CrowdStrike Falcon': ['6.0'],
    'Dynamics 365': ['9.2', '9.1'],
}


@dataclass
class CVELoadResult:
    """Resultado do carregamento de CVEs."""
    total_in_file: int
    total_in_period: int
    matched_to_infrastructure: int
    cves: List[CVE]
    period_start: datetime
    period_end: datetime


def load_cves_from_dataset(
    dataset_path: str,
    servers: List[Server],
    days: int = 30,
    month: Optional[str] = None,
    year: Optional[int] = None,
    min_severity: str = "LOW",
    include_cisa_kev: bool = True
) -> CVELoadResult:
    """
    Carrega CVEs do dataset filtrados por data e relevância.
    
    Args:
        dataset_path: Caminho para o ficheiro merged_cve_data.csv
        servers: Lista de servidores com software instalado
        days: Número de dias para filtrar (default: 30)
        month: Mês específico (ex: "2025-12" ou "12")
        year: Ano específico (default: ano atual)
        min_severity: Severidade mínima (LOW, MEDIUM, HIGH, CRITICAL)
        include_cisa_kev: Incluir sempre CVEs no CISA KEV
        
    Returns:
        CVELoadResult com CVEs filtrados e estatísticas
    """
    # Calcular período de datas
    now = datetime.now()
    
    if month:
        # Filtrar por mês específico
        if year is None:
            year = now.year
        
        # Parsing do mês
        if '-' in str(month):
            parts = str(month).split('-')
            year = int(parts[0])
            month_num = int(parts[1])
        else:
            month_num = int(month)
        
        period_start = datetime(year, month_num, 1)
        # Último dia do mês
        if month_num == 12:
            period_end = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            period_end = datetime(year, month_num + 1, 1) - timedelta(days=1)
        period_end = period_end.replace(hour=23, minute=59, second=59)
    else:
        # Últimos N dias
        period_end = now
        period_start = now - timedelta(days=days)
    
    logger.info(f"A filtrar CVEs de {period_start.date()} a {period_end.date()}")
    
    # Obter software instalado na infraestrutura
    installed_software = _get_installed_software(servers)
    logger.info(f"Software na infraestrutura: {', '.join(installed_software)}")
    
    # Mapeamento de severidade para ordem
    severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_sev_level = severity_order.get(min_severity.upper(), 0)
    
    # Carregar e filtrar CVEs
    cves = []
    total_in_file = 0
    total_in_period = 0
    
    with open(dataset_path, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            total_in_file += 1
            
            # Obter data de publicação
            pub_date_str = row.get('published_date_file1', '') or row.get('published_date_file2', '')
            if not pub_date_str:
                continue
            
            try:
                pub_date = datetime.strptime(pub_date_str[:10], '%Y-%m-%d')
            except ValueError:
                continue
            
            # Filtrar por período
            if not (period_start <= pub_date <= period_end):
                continue
            
            total_in_period += 1
            
            # Obter severidade
            severity = (row.get('base_severity_file1', '') or 
                       row.get('base_severity_file2', '') or 'LOW').upper()
            
            # CISA KEV?
            is_kev = row.get('cisa_kev_file1', '').lower() == 'true' or \
                     row.get('cisa_kev_file2', '').lower() == 'true'
            
            # Filtrar por severidade (a menos que seja KEV)
            if not is_kev:
                sev_level = severity_order.get(severity, 0)
                if sev_level < min_sev_level:
                    continue
            
            # Verificar se o CVE afeta o nosso software
            products = (row.get('impacted_products', '') or '').lower()
            vendor = (row.get('impacted_vendor', '') or '').lower()
            
            matched_software = _match_software(products, vendor, installed_software)
            
            if not matched_software:
                continue
            
            # Criar objeto CVE
            cve = _create_cve_from_row(row, matched_software, pub_date)
            if cve:
                cves.append(cve)
    
    logger.info(f"CVEs carregados: {len(cves)} de {total_in_period} no período ({total_in_file} total)")
    
    return CVELoadResult(
        total_in_file=total_in_file,
        total_in_period=total_in_period,
        matched_to_infrastructure=len(cves),
        cves=cves,
        period_start=period_start,
        period_end=period_end
    )


def _get_installed_software(servers: List[Server]) -> Set[str]:
    """Obtém conjunto de software instalado nos servidores."""
    software_ids = set()
    for server in servers:
        for sw in server.installed_software:
            software_ids.add(sw.id)
    return software_ids


def _match_software(products: str, vendor: str, installed_software: Set[str]) -> Optional[str]:
    """
    Tenta fazer match entre os produtos do CVE e o software instalado.
    
    Returns:
        ID do software se houver match, None caso contrário
    """
    combined = f"{vendor} {products}"
    
    for pattern, software_id in SOFTWARE_MAPPING.items():
        if pattern in combined:
            # Verificar se temos este software instalado
            if software_id in installed_software:
                return software_id
            # Verificar variações (SQL Server vs SQL Server 2019)
            for installed in installed_software:
                if software_id in installed or installed in software_id:
                    return installed
    
    return None


def _create_cve_from_row(row: Dict, software_id: str, pub_date: datetime) -> Optional[CVE]:
    """Cria objeto CVE a partir de uma linha do CSV."""
    try:
        cve_id = row['cve_id']
        
        # Severidade
        severity = (row.get('base_severity_file1', '') or 
                   row.get('base_severity_file2', '') or 'MEDIUM').upper()
        if severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            severity = 'MEDIUM'
        
        # CVSS Score
        cvss_str = row.get('base_score_file1', '') or row.get('base_score_file2', '') or '5.0'
        try:
            cvss_score = float(cvss_str)
        except ValueError:
            cvss_score = 5.0
        
        # EPSS Score
        epss_str = row.get('epss_score', '') or '0.1'
        try:
            epss_score = float(epss_str)
            if epss_score > 1:
                epss_score = epss_score / 100  # Converter de percentagem
        except ValueError:
            epss_score = 0.1
        
        # CISA KEV
        is_kev = row.get('cisa_kev_file1', '').lower() == 'true' or \
                 row.get('cisa_kev_file2', '').lower() == 'true'
        
        # Estimar tempo de fix baseado na severidade
        fix_time_map = {'CRITICAL': 4, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 1}
        fix_time = fix_time_map.get(severity, 2)
        
        # Operadores necessários baseado na severidade
        operators_map = {'CRITICAL': 2, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 1}
        operators = operators_map.get(severity, 1)
        
        # Se é KEV, aumentar urgência
        if is_kev:
            epss_score = max(epss_score, 0.9)  # KEV tem sempre alta probabilidade
        
        # Obter versão do software afetado
        versions = row.get('vulnerable_versions', '') or ''
        # Tentar encontrar versão compatível com a nossa infraestrutura
        version = _find_compatible_version(software_id, versions)
        
        return CVE(
            id=cve_id,
            severity=severity.capitalize(),
            epss_score=epss_score,
            affected_software_id=software_id,
            affected_software_version=version,
            estimated_fix_time=fix_time,
            operators_required=operators
        )
        
    except Exception as e:
        logger.warning(f"Erro ao criar CVE {row.get('cve_id', 'unknown')}: {e}")
        return None


def _find_compatible_version(software_id: str, versions_str: str) -> str:
    """Encontra uma versão compatível com a nossa infraestrutura."""
    our_versions = VERSION_MAPPING.get(software_id, [])
    
    if not our_versions:
        return "all"
    
    # Verificar se alguma das nossas versões está na string de versões
    versions_lower = versions_str.lower()
    for v in our_versions:
        if v in versions_lower:
            return v
    
    # Se não encontrar, assumir que afeta todas
    return our_versions[0] if our_versions else "all"


def get_cve_summary(cves: List[CVE]) -> Dict:
    """Gera resumo estatístico dos CVEs carregados."""
    if not cves:
        return {'total': 0}
    
    from collections import Counter
    
    severities = Counter(cve.severity for cve in cves)
    software = Counter(cve.affected_software_id for cve in cves)
    
    # CVEs de alto risco (EPSS > 0.5 ou severidade Critical/High)
    high_risk = [c for c in cves if c.epss_score > 0.5 or c.severity in ['Critical', 'High']]
    
    return {
        'total': len(cves),
        'by_severity': dict(severities),
        'by_software': dict(software),
        'high_risk_count': len(high_risk),
        'avg_epss': sum(c.epss_score for c in cves) / len(cves),
        'max_epss': max(c.epss_score for c in cves),
    }
