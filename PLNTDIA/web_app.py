"""
PLNTDIA Web API - Flask Backend

Provides REST API endpoints for:
- CVE management and listing
- Server information
- Patch planning generation using Genetic Algorithm
- Calendar data for scheduling
"""

import os
import sys
import json
import logging
import re
from datetime import datetime, date, timedelta
from typing import List, Dict, Tuple, Optional, Any
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.domain import Server, CVE, Software, Worker, PatchTask
from src.repository import load_servers_from_csv, load_workers_from_csv, generate_cves_for_infrastructure
from src.availability import AvailabilityManager, PlanningPeriod
from src.genetic_algorithm import run_genetic_scheduler, GAConfig, GeneticScheduler
from src.logic import calculate_priority
from src.database import get_database, GAExecutionReport
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
CORS(app)

# ============================================================
# VALIDATION & PAGINATION HELPERS
# ============================================================

class ValidationError(Exception):
    """Custom validation error with status code."""
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


def validate_pagination(page: Any, per_page: Any, max_per_page: int = 100) -> Tuple[int, int]:
    """Validate and return pagination parameters."""
    try:
        page = int(page) if page else 1
        per_page = int(per_page) if per_page else 20
    except (ValueError, TypeError):
        raise ValidationError("page and per_page must be integers")
    
    if page < 1:
        raise ValidationError("page must be >= 1")
    if per_page < 1 or per_page > max_per_page:
        raise ValidationError(f"per_page must be between 1 and {max_per_page}")
    
    return page, per_page


def paginate(items: List, page: int, per_page: int) -> Dict:
    """Paginate a list of items."""
    total = len(items)
    total_pages = (total + per_page - 1) // per_page
    start = (page - 1) * per_page
    end = start + per_page
    
    return {
        "items": items[start:end],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }
    }


def validate_severity(severity: str) -> str:
    """Validate CVE severity level."""
    valid = ['critical', 'high', 'medium', 'low']
    if severity and severity.lower() not in valid:
        raise ValidationError(f"Invalid severity. Must be one of: {', '.join(valid)}")
    return severity.lower() if severity else None


def validate_environment(env: str) -> str:
    """Validate server environment."""
    valid = ['dev', 'test', 'prod']
    if env and env.lower() not in valid:
        raise ValidationError(f"Invalid environment. Must be one of: {', '.join(valid)}")
    return env.upper() if env else None


def validate_date(date_str: str, param_name: str = 'date') -> date:
    """Validate and parse date string (YYYY-MM-DD)."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        raise ValidationError(f"{param_name} must be in YYYY-MM-DD format")


def validate_positive_int(value: Any, param_name: str, max_value: int = None) -> int:
    """Validate positive integer parameter."""
    try:
        value = int(value)
    except (ValueError, TypeError):
        raise ValidationError(f"{param_name} must be an integer")
    
    if value < 1:
        raise ValidationError(f"{param_name} must be positive")
    if max_value and value > max_value:
        raise ValidationError(f"{param_name} must be <= {max_value}")
    
    return value


@app.errorhandler(ValidationError)
def handle_validation_error(error):
    """Handle validation errors."""
    return jsonify({"error": error.message}), error.status_code


@app.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request errors."""
    return jsonify({"error": "Bad request"}), 400


@app.errorhandler(404)
def handle_not_found(error):
    """Handle not found errors."""
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def handle_server_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {error}")
    return jsonify({"error": "Internal server error"}), 500


# ============================================================
# DATA CACHE
# ============================================================

# Global data cache
_data_cache = {
    "servers": None,
    "workers": None,
    "cves": None,
    "cve_metadata": {},  # Cache for additional CVE info like published_date
    "availability_manager": None,
    "last_load": None
}


def load_data(force_reload: bool = False) -> Tuple[List[Server], List[Worker], AvailabilityManager]:
    """Load or return cached data."""
    if not force_reload and _data_cache["servers"] is not None:
        return _data_cache["servers"], _data_cache["workers"], _data_cache["availability_manager"]
    
    csv_path = os.path.join(os.path.dirname(__file__), 'csv')
    
    # Load servers and workers
    servers = load_servers_from_csv(csv_path)
    workers = load_workers_from_csv(csv_path, servers)
    
    # Load availability manager
    vacations_path = os.path.join(csv_path, 'team_vacations.csv')
    holidays_path = os.path.join(csv_path, 'holidays.csv')
    
    availability_manager = AvailabilityManager(
        vacations_file=vacations_path if os.path.exists(vacations_path) else None,
        holidays_file=holidays_path if os.path.exists(holidays_path) else None
    )
    
    # Cache data
    _data_cache["servers"] = servers
    _data_cache["workers"] = workers
    _data_cache["availability_manager"] = availability_manager
    _data_cache["last_load"] = datetime.now()
    
    logger.info(f"Data loaded: {len(servers)} servers, {len(workers)} workers")
    
    return servers, workers, availability_manager


def generate_cves(servers: List[Server], count: int = 50) -> List[CVE]:
    """Generate CVEs for the infrastructure."""
    cves = generate_cves_for_infrastructure(servers, count)
    _data_cache["cves"] = cves
    return cves


def load_cves_from_csv(servers: List[Server], max_cves: int = 200) -> List[CVE]:
    """
    Load real CVEs from merged_cve_data.csv and map to installed software.
    
    Args:
        servers: List of servers with installed software
        max_cves: Maximum number of CVEs to load
    
    Returns:
        List of CVE objects that affect the infrastructure
    """
    import csv
    import re
    
    # Map software names to search patterns in CVE data
    SOFTWARE_MAPPINGS = {
        "SQL Server": ["sql server", "microsoft sql", "mssql"],
        "IIS": ["iis", "internet information services"],
        "MySQL Server": ["mysql"],
        ".NET Framework": [".net framework", "dotnet"],
        "ASP.NET Core": ["asp.net", "aspnet"],
        "Active Directory": ["active directory", "ad fs", "adfs"],
        "Exchange": ["exchange server", "microsoft exchange"],
        "SharePoint": ["sharepoint"],
        "Java": ["java se", "java jdk", "java jre", "openjdk"],
        "Oracle Database": ["oracle database", "oracle db"],
        "PostgreSQL": ["postgresql", "postgres"],
        "WebLogic Server": ["weblogic"],
        "Apache Tomcat": ["tomcat", "apache tomcat"],
        "Nginx": ["nginx"],
        "Redis": ["redis"],
        "Elasticsearch": ["elasticsearch", "elastic search"],
        "Node.js": ["node.js", "nodejs"],
        "Python": ["python"],
        "Grafana": ["grafana"],
        "Prometheus": ["prometheus"],
        "RabbitMQ": ["rabbitmq"],
        "Zabbix": ["zabbix"],
        "Kong Gateway": ["kong"],
        "CrowdStrike Falcon": ["crowdstrike"],
        "Fortinet FortiGate": ["fortinet", "fortigate"],
        "Dynamics 365": ["dynamics 365", "dynamics365"],
        "Windows Server": ["windows server"],
    }
    
    # Collect all installed software from servers
    installed_software = {}
    for server in servers:
        for sw in server.installed_software:
            if sw.id not in installed_software:
                installed_software[sw.id] = sw.version
    
    logger.info(f"Software instalado na infraestrutura: {list(installed_software.keys())}")
    
    # Path to merged CVE data
    csv_path = os.path.join(os.path.dirname(__file__), 'dataset', 'merged_cve_data.csv')
    
    if not os.path.exists(csv_path):
        logger.warning(f"CVE dataset not found at {csv_path}, falling back to generated CVEs")
        return generate_cves_for_infrastructure(servers, max_cves)
    
    cves = []
    severity_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "": "Medium"}
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                if len(cves) >= max_cves:
                    break
                
                # Get product info
                impacted_products = row.get('impacted_products', '').lower()
                vulnerable_versions = row.get('vulnerable_versions', '')
                cve_id = row.get('cve_id', '')
                
                if not impacted_products or not cve_id:
                    continue
                
                # Try to match with installed software
                matched_software = None
                matched_version = None
                
                for sw_name, patterns in SOFTWARE_MAPPINGS.items():
                    if sw_name in installed_software:
                        for pattern in patterns:
                            if pattern in impacted_products:
                                matched_software = sw_name
                                matched_version = installed_software[sw_name]
                                break
                    if matched_software:
                        break
                
                if not matched_software:
                    continue
                
                # Parse severity
                severity_str = row.get('base_severity_file1', '') or row.get('base_severity_file2', '')
                severity = severity_map.get(severity_str.upper(), "Medium")
                
                # Parse EPSS score
                try:
                    epss_score = float(row.get('epss_score', 0) or 0)
                except (ValueError, TypeError):
                    epss_score = 0.1
                
                # Parse base score
                try:
                    base_score = float(row.get('base_score_file1', 0) or row.get('base_score_file2', 0) or 5.0)
                except (ValueError, TypeError):
                    base_score = 5.0
                
                # Get published date (try both file1 and file2 columns)
                published_date = row.get('published_date_file1', '') or row.get('published_date_file2', '') or row.get('datePublished', '')
                
                # Calculate estimated fix time based on severity
                fix_time_map = {"Critical": 4, "High": 6, "Medium": 8, "Low": 12}
                estimated_fix_time = fix_time_map.get(severity, 8)
                
                # Ensure EPSS score is within valid range
                epss_score = max(0.0, min(1.0, epss_score))
                
                # Create CVE object (only with valid constructor arguments)
                cve = CVE(
                    id=cve_id,
                    severity=severity,
                    epss_score=epss_score,
                    affected_software_id=matched_software,
                    affected_software_version=matched_version,
                    estimated_fix_time=estimated_fix_time,
                    operators_required=2 if severity in ["Critical", "High"] else 1
                )
                
                # Set calculated priority score
                cve.final_priority_score = base_score * (1 + epss_score) * (1.5 if severity == "Critical" else 1.2 if severity == "High" else 1.0)
                
                # Store metadata (published_date) in cache
                _data_cache["cve_metadata"][cve_id] = {
                    "published_date": published_date,
                    "base_score": base_score
                }
                
                cves.append(cve)
        
        logger.info(f"Loaded {len(cves)} real CVEs from dataset")
        
        # Sort by priority (highest first)
        cves.sort(key=lambda c: c.final_priority_score, reverse=True)
        
        # Ensure we have CVEs of all severities for dashboard
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for cve in cves:
            severity_counts[cve.severity] += 1
        
        logger.info(f"CVEs by severity: {severity_counts}")
        
        _data_cache["cves"] = cves
        return cves
        
    except Exception as e:
        logger.error(f"Error loading CVEs from CSV: {e}")
        return generate_cves_for_infrastructure(servers, max_cves)


def server_to_dict(server: Server) -> Dict:
    """Convert Server to dictionary."""
    return {
        "server_id": server.id,
        "id": server.id,
        "os_name": server.os_name,
        "os_version": server.os_version,
        "rto_hours": server.rto_hours,
        "environment": server.environment,
        "application_group": server.application_group,
        "dependency_group": server.dependency_group,
        "software": [sw.id for sw in server.installed_software],
        "maintenance_window": f"{server.downtime_windows[0][1]}-{server.downtime_windows[0][2]}" if server.downtime_windows else None,
        "downtime_windows": [
            {"day": d, "start": s, "end": e} 
            for d, s, e in server.downtime_windows
        ],
        "installed_software": [
            {"id": sw.id, "version": sw.version, "criticality": sw.criticality}
            for sw in server.installed_software
        ]
    }


def cve_to_dict(cve: CVE) -> Dict:
    """Convert CVE to dictionary."""
    return {
        "cve_id": cve.id,
        "id": cve.id,
        "severity": cve.severity,
        "epss_score": round(cve.epss_score, 3),
        "software": cve.affected_software_id,
        "affected_software_id": cve.affected_software_id,
        "affected_software_version": cve.affected_software_version,
        "patch_duration_hours": cve.estimated_fix_time,
        "estimated_fix_time": cve.estimated_fix_time,
        "operators_required": cve.operators_required,
        "priority": round(cve.final_priority_score, 2),
        "final_priority_score": round(cve.final_priority_score, 2),
        "risk_level": cve.risk_level,
        "severity_score": cve.severity_score
    }


def worker_to_dict(worker: Worker) -> Dict:
    """Convert Worker to dictionary."""
    return {
        "id": worker.id,
        "name": worker.name,
        "level": worker.level,
        "skills": worker.skills,
        "weekly_shifts": [
            {"day": d, "start": s, "end": e}
            for d, s, e in worker.weekly_shifts
        ],
        "authorized_servers": worker.authorized_server_ids,
        "max_daily_hours": worker.max_daily_hours,
        "on_call": worker.on_call
    }


def task_to_dict(task: PatchTask, start_date: date) -> Dict:
    """Convert PatchTask to dictionary with calendar info."""
    day_offset = task.start_time // 24
    hour_of_day = task.start_time % 24
    task_date = start_date + timedelta(days=day_offset)
    
    day_names = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
    day_name = day_names[task_date.weekday()]
    
    return {
        "cve_id": task.cve.id,
        "server_id": task.server.id,
        "software_id": task.software.id,
        "software_version": task.software.version,
        "start_time": task.start_time,
        "end_time": task.end_time,
        "duration": task.end_time - task.start_time,
        "date": task_date.isoformat(),
        "day_name": day_name,
        "hour_start": hour_of_day,
        "hour_end": hour_of_day + (task.end_time - task.start_time),
        "workers": [w.name or w.id for w in task.workers],
        "worker_ids": [w.id for w in task.workers],
        "severity": task.cve.severity,
        "environment": task.server.environment,
        "priority": round(task.cve.final_priority_score, 2)
    }


# ============== API Routes ==============

@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    """Serve favicon."""
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')


@app.route('/api/status')
def api_status():
    """Basic API health check."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "cached_data": _data_cache["last_load"].isoformat() if _data_cache["last_load"] else None
    })


@app.route('/api/health')
def api_health():
    """Comprehensive health check endpoint.
    
    Returns detailed status of all system components.
    """
    health = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "components": {}
    }
    
    # Check data cache
    try:
        servers, workers, availability_manager = load_data()
        health["components"]["data_cache"] = {
            "status": "healthy",
            "servers_count": len(servers),
            "workers_count": len(workers),
            "last_load": _data_cache["last_load"].isoformat() if _data_cache["last_load"] else None
        }
    except Exception as e:
        health["status"] = "degraded"
        health["components"]["data_cache"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # Check CVE data
    try:
        if _data_cache["cves"] is not None:
            health["components"]["cve_data"] = {
                "status": "healthy",
                "cves_count": len(_data_cache["cves"]),
                "source": "cached"
            }
        else:
            health["components"]["cve_data"] = {
                "status": "healthy",
                "cves_count": 0,
                "source": "not_loaded"
            }
    except Exception as e:
        health["components"]["cve_data"] = {
            "status": "unhealthy",
            "error": str(e)
        }
    
    # Check CSV files
    csv_path = os.path.join(os.path.dirname(__file__), 'csv')
    required_files = ['servers.csv', 'team.csv', 'holidays.csv']
    csv_status = "healthy"
    missing_files = []
    
    for f in required_files:
        if not os.path.exists(os.path.join(csv_path, f)):
            csv_status = "degraded"
            missing_files.append(f)
    
    health["components"]["csv_files"] = {
        "status": csv_status,
        "path": csv_path,
        "missing_files": missing_files if missing_files else None
    }
    
    # Check dataset
    dataset_path = os.path.join(os.path.dirname(__file__), 'dataset', 'merged_cve_data.csv')
    if os.path.exists(dataset_path):
        file_size = os.path.getsize(dataset_path)
        health["components"]["cve_dataset"] = {
            "status": "healthy",
            "path": dataset_path,
            "size_mb": round(file_size / (1024 * 1024), 2)
        }
    else:
        health["components"]["cve_dataset"] = {
            "status": "missing",
            "path": dataset_path
        }
    
    # Overall status
    if any(c.get("status") == "unhealthy" for c in health["components"].values()):
        health["status"] = "unhealthy"
    elif any(c.get("status") in ["degraded", "missing"] for c in health["components"].values()):
        health["status"] = "degraded"
    
    status_code = 200 if health["status"] == "healthy" else 503 if health["status"] == "unhealthy" else 200
    
    return jsonify(health), status_code


@app.route('/api/metrics')
def api_metrics():
    """Get system metrics for monitoring.
    
    Returns counts and statistics useful for monitoring dashboards.
    """
    servers, workers, availability_manager = load_data()
    
    if _data_cache["cves"] is None:
        load_cves_from_csv(servers, 200)
    
    cves = _data_cache["cves"] or []
    
    # Calculate severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for cve in cves:
        severity_counts[cve.severity] = severity_counts.get(cve.severity, 0) + 1
    
    # Calculate environment distribution
    env_counts = {"DEV": 0, "TEST": 0, "PROD": 0}
    for server in servers:
        env_counts[server.environment] = env_counts.get(server.environment, 0) + 1
    
    # Calculate worker level distribution
    level_counts = {"Junior": 0, "Mid": 0, "Senior": 0}
    for worker in workers:
        level_counts[worker.level] = level_counts.get(worker.level, 0) + 1
    
    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "totals": {
            "servers": len(servers),
            "cves": len(cves),
            "workers": len(workers),
            "holidays": len(availability_manager.holidays) if availability_manager else 0
        },
        "distributions": {
            "cves_by_severity": severity_counts,
            "servers_by_environment": env_counts,
            "workers_by_level": level_counts
        },
        "cache": {
            "is_loaded": _data_cache["last_load"] is not None,
            "last_load": _data_cache["last_load"].isoformat() if _data_cache["last_load"] else None
        }
    })

@app.route('/api/servers')
def api_servers():
    """Get all servers with pagination and filtering.
    
    Query params:
        - environment: Filter by env (DEV, TEST, PROD)
        - application_group: Filter by app group
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
    """
    servers, _, _ = load_data()
    
    # Validate and filter by environment
    env = request.args.get('environment')
    if env:
        env = validate_environment(env)
        servers = [s for s in servers if s.environment == env]
    
    # Filter by application group
    app_group = request.args.get('application_group')
    if app_group:
        servers = [s for s in servers if s.application_group == app_group]
    
    # Pagination
    page, per_page = validate_pagination(
        request.args.get('page'),
        request.args.get('per_page')
    )
    
    result = paginate([server_to_dict(s) for s in servers], page, per_page)
    
    return jsonify({
        "count": result["pagination"]["total"],
        "servers": result["items"],
        "pagination": result["pagination"]
    })


@app.route('/api/servers/<server_id>')
def api_server_detail(server_id: str):
    """Get server details."""
    servers, _, _ = load_data()
    
    server = next((s for s in servers if s.id == server_id), None)
    if not server:
        return jsonify({"error": "Server not found"}), 404
    
    return jsonify(server_to_dict(server))


@app.route('/api/workers')
def api_workers():
    """Get all workers."""
    _, workers, _ = load_data()
    
    # Filter by level if provided
    level = request.args.get('level')
    if level:
        workers = [w for w in workers if w.level.lower() == level.lower()]
    
    return jsonify({
        "count": len(workers),
        "workers": [worker_to_dict(w) for w in workers]
    })


@app.route('/api/cves')
def api_cves():
    """Get all CVEs from the real dataset with pagination.
    
    Query params:
        - severity: Filter by severity (Critical, High, Medium, Low)
        - software: Filter by software name (partial match)
        - sort: Sort by 'priority', 'severity', or 'epss' (default: priority)
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - count: Max CVEs to load from dataset (default: 200)
    """
    servers, _, _ = load_data()
    
    # Validate count parameter
    count = request.args.get('count', 200)
    if count:
        count = validate_positive_int(count, 'count', max_value=1000)
    
    use_real = request.args.get('real', 'true').lower() == 'true'
    
    # Load real CVEs from CSV or generate
    if _data_cache["cves"] is None:
        if use_real:
            load_cves_from_csv(servers, count)
        else:
            generate_cves(servers, count)
    
    cves = list(_data_cache["cves"])  # Create copy to avoid modifying cache
    
    # Filter by severity if provided
    severity = request.args.get('severity')
    if severity:
        severity = validate_severity(severity)
        cves = [c for c in cves if c.severity.lower() == severity]
    
    # Filter by software if provided
    software = request.args.get('software')
    if software:
        # Sanitize input to prevent injection
        software = re.sub(r'[^\w\s.-]', '', software)
        cves = [c for c in cves if software.lower() in c.affected_software_id.lower()]
    
    # Validate and apply sorting
    sort_by = request.args.get('sort', 'priority')
    valid_sorts = ['priority', 'severity', 'epss', 'cve_id']
    if sort_by not in valid_sorts:
        raise ValidationError(f"Invalid sort. Must be one of: {', '.join(valid_sorts)}")
    
    if sort_by == 'priority':
        cves = sorted(cves, key=lambda c: c.final_priority_score, reverse=True)
    elif sort_by == 'severity':
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        cves = sorted(cves, key=lambda c: severity_order.get(c.severity, 0), reverse=True)
    elif sort_by == 'epss':
        cves = sorted(cves, key=lambda c: c.epss_score, reverse=True)
    elif sort_by == 'cve_id':
        cves = sorted(cves, key=lambda c: c.id)
    
    # Pagination
    page, per_page = validate_pagination(
        request.args.get('page'),
        request.args.get('per_page')
    )
    
    result = paginate([cve_to_dict(c) for c in cves], page, per_page)
    
    return jsonify({
        "count": result["pagination"]["total"],
        "cves": result["items"],
        "pagination": result["pagination"]
    })


@app.route('/api/cves/<cve_id>')
def api_cve_detail(cve_id: str):
    """Get CVE details."""
    if _data_cache["cves"] is None:
        servers, _, _ = load_data()
        generate_cves(servers, 50)
    
    cve = next((c for c in _data_cache["cves"] if c.id == cve_id), None)
    if not cve:
        return jsonify({"error": "CVE not found"}), 404
    
    return jsonify(cve_to_dict(cve))


@app.route('/api/cves/<cve_id>/affected-servers')
def api_cve_affected_servers(cve_id: str):
    """Get servers affected by a CVE.
    
    Supports both:
    - Generated CVEs (in memory cache) - have affected_software_id
    - Database CVEs (from real dataset) - match by vendor/product name
    """
    servers, _, _ = load_data()
    
    # First try to find in generated CVEs cache
    cve = None
    if _data_cache["cves"]:
        cve = next((c for c in _data_cache["cves"] if c.id == cve_id), None)
    
    if cve:
        # Generated CVE - use affected_software_id matching
        affected = []
        for server in servers:
            for sw in server.installed_software:
                if sw.id == cve.affected_software_id:
                    affected.append({
                        "server": server_to_dict(server),
                        "software": {
                            "id": sw.id,
                            "version": sw.version,
                            "criticality": sw.criticality
                        }
                    })
                    break
        
        return jsonify({
            "cve_id": cve_id,
            "count": len(affected),
            "servers": [a["server"] for a in affected],
            "affected_servers": affected
        })
    
    # Try database CVE - match by vendor/product name
    try:
        db = get_database()
        db_cve = db.get_cve_by_id(cve_id)
        
        if not db_cve:
            return jsonify({"error": "CVE not found"}), 404
        
        # Extract vendor and product from database CVE (try multiple field names)
        vendor = (db_cve.get('impacted_vendor') or db_cve.get('vendor') or '').lower()
        product = (db_cve.get('impacted_products') or db_cve.get('product') or '').lower()
        description = (db_cve.get('cwe_description') or '').lower()
        
        # Find affected servers by matching software name
        affected = []
        for server in servers:
            for sw in server.installed_software:
                sw_name = sw.id.lower()
                # Match if software name contains vendor or product name
                if (vendor and vendor in sw_name) or (product and product in sw_name):
                    affected.append({
                        "server": server_to_dict(server),
                        "software": {
                            "id": sw.id,
                            "version": sw.version,
                            "criticality": sw.criticality
                        },
                        "match_type": "vendor_product"
                    })
                    break
        
        # If no matches by vendor/product, try broader matching
        if not affected:
            # Try to match common software patterns
            software_patterns = {
                'microsoft': ['IIS', '.NET Framework', 'ASP.NET Core', 'Exchange', 'Active Directory', 'SQL Server', 'SharePoint'],
                'apache': ['Apache Tomcat'],
                'oracle': ['Oracle Database', 'Java', 'WebLogic Server'],
                'mysql': ['MySQL Server'],
                'postgresql': ['PostgreSQL'],
                'redis': ['Redis'],
                'elasticsearch': ['Elasticsearch'],
                'nginx': ['Nginx'],
                'python': ['Python'],
                'node': ['Node.js'],
                'grafana': ['Grafana'],
                'fortinet': ['Fortinet FortiGate'],
                'crowdstrike': ['CrowdStrike Falcon'],
                'zabbix': ['Zabbix'],
                'kong': ['Kong Gateway'],
                'rabbitmq': ['RabbitMQ'],
                'prometheus': ['Prometheus']
            }
            
            matched_software = set()
            search_terms = [vendor, product, db_cve.get('description', '').lower()[:100]]
            
            for term in search_terms:
                if not term:
                    continue
                for pattern_key, software_list in software_patterns.items():
                    if pattern_key in term:
                        matched_software.update(software_list)
            
            for server in servers:
                for sw in server.installed_software:
                    if sw.id in matched_software:
                        affected.append({
                            "server": server_to_dict(server),
                            "software": {
                                "id": sw.id,
                                "version": sw.version,
                                "criticality": sw.criticality
                            },
                            "match_type": "pattern"
                        })
                        break
        
        return jsonify({
            "cve_id": cve_id,
            "count": len(affected),
            "servers": [a["server"] for a in affected],
            "affected_servers": affected,
            "source": "database",
            "vendor": vendor,
            "product": product
        })
        
    except Exception as e:
        logger.error(f"Error finding affected servers for {cve_id}: {e}")
        return jsonify({"error": f"Error processing CVE: {str(e)}"}), 500


@app.route('/api/holidays')
def api_holidays():
    """Get holidays."""
    _, _, availability_manager = load_data()
    
    holidays = []
    if availability_manager and availability_manager.holidays:
        for h_date, holiday in sorted(availability_manager.holidays.items()):
            holidays.append({
                "date": h_date.isoformat(),
                "name": holiday.name,
                "type": holiday.holiday_type
            })
    
    return jsonify({
        "count": len(holidays),
        "holidays": holidays
    })


@app.route('/api/patches/recommended')
def api_recommended_patches():
    """
    Automatically identify which patches should be applied to each server.
    Returns a structured list of all CVE-Server combinations that need patching.
    """
    servers, _, _ = load_data()
    
    if _data_cache["cves"] is None:
        generate_cves(servers, 50)
    
    cves = _data_cache["cves"]
    
    # Build patch recommendations grouped by server
    by_server = {}
    by_cve = {}
    all_patches = []
    
    for cve in cves:
        for server in servers:
            for sw in server.installed_software:
                if sw.id == cve.affected_software_id:
                    patch_info = {
                        "cve_id": cve.id,
                        "cve_severity": cve.severity,
                        "cve_priority": round(cve.final_priority_score, 2),
                        "cve_epss": round(cve.epss_score, 3),
                        "server_id": server.id,
                        "server_environment": server.environment,
                        "server_app_group": server.application_group,
                        "server_dependency_group": server.dependency_group,
                        "software_id": sw.id,
                        "software_version": sw.version,
                        "estimated_time": cve.estimated_fix_time,
                        "operators_required": cve.operators_required
                    }
                    all_patches.append(patch_info)
                    
                    # Group by server
                    if server.id not in by_server:
                        by_server[server.id] = {
                            "server": server_to_dict(server),
                            "patches": []
                        }
                    by_server[server.id]["patches"].append({
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "priority": round(cve.final_priority_score, 2),
                        "software": sw.id,
                        "time": cve.estimated_fix_time
                    })
                    
                    # Group by CVE
                    if cve.id not in by_cve:
                        by_cve[cve.id] = {
                            "cve": cve_to_dict(cve),
                            "affected_servers": []
                        }
                    by_cve[cve.id]["affected_servers"].append({
                        "server_id": server.id,
                        "environment": server.environment,
                        "app_group": server.application_group
                    })
                    break
    
    # Sort patches by priority
    all_patches.sort(key=lambda p: p["cve_priority"], reverse=True)
    
    # Statistics
    stats = {
        "total_patches": len(all_patches),
        "by_severity": {},
        "by_environment": {},
        "total_time_hours": sum(p["estimated_time"] for p in all_patches)
    }
    
    for p in all_patches:
        stats["by_severity"][p["cve_severity"]] = stats["by_severity"].get(p["cve_severity"], 0) + 1
        stats["by_environment"][p["server_environment"]] = stats["by_environment"].get(p["server_environment"], 0) + 1
    
    return jsonify({
        "all_patches": all_patches,
        "by_server": by_server,
        "by_cve": by_cve,
        "statistics": stats
    })


@app.route('/api/plan/auto', methods=['POST'])
def api_auto_generate_plan():
    """
    Automatically generate a complete patch plan for all identified vulnerabilities.
    Uses the Genetic Algorithm to optimize scheduling.
    """
    data = request.json or {}
    
    servers, workers, availability_manager = load_data()
    
    if _data_cache["cves"] is None:
        generate_cves(servers, 50)
    
    cves = _data_cache["cves"]
    
    # Get parameters
    start_date_str = data.get('start_date')
    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    else:
        start_date = date.today()
    
    days = int(data.get('days', 30))  # Default to 30 days for monthly view
    population_size = int(data.get('population_size', 50))
    generations = int(data.get('generations', 100))
    
    # Filter by severity if provided
    min_severity = data.get('min_severity', 'Low')
    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    min_severity_level = severity_order.get(min_severity, 1)
    
    # Automatically build all tasks
    tasks = []
    for cve in cves:
        if severity_order.get(cve.severity, 0) >= min_severity_level:
            for server in servers:
                for sw in server.installed_software:
                    if sw.id == cve.affected_software_id:
                        tasks.append((cve, server, sw))
    
    if not tasks:
        return jsonify({"error": "No patches to schedule"}), 400
    
    logger.info(f"Auto-scheduling {len(tasks)} tasks with GA")
    
    # Run genetic algorithm
    config = GAConfig(
        population_size=population_size,
        generations=generations,
        planning_weeks=(days + 6) // 7
    )
    
    scheduler = GeneticScheduler(
        servers=servers,
        workers=workers,
        cves=cves,
        tasks=tasks,
        config=config,
        availability_manager=availability_manager,
        start_date=start_date
    )
    
    best_chromosome, patch_tasks = scheduler.run(verbose=True)
    
    # Convert to response with detailed calendar info
    schedule = [task_to_dict(t, start_date) for t in patch_tasks]
    
    # Build monthly calendar structure
    monthly_calendar = build_monthly_calendar(schedule, start_date, days, availability_manager)
    
    # Calculate metrics
    metrics = {
        "total_patches_needed": len(tasks),
        "patches_scheduled": len(patch_tasks),
        "success_rate": round((len(patch_tasks) / len(tasks) * 100) if tasks else 0, 1),
        "best_fitness": round(best_chromosome.fitness, 2),
        "total_hours": sum(t['duration'] for t in schedule),
        "by_environment": {},
        "by_severity": {},
        "by_week": {}
    }
    
    for task in schedule:
        env = task['environment']
        metrics["by_environment"][env] = metrics["by_environment"].get(env, 0) + 1
        
        sev = task['severity']
        metrics["by_severity"][sev] = metrics["by_severity"].get(sev, 0) + 1
        
        # Week number
        task_date = datetime.strptime(task['date'], '%Y-%m-%d').date()
        week_num = (task_date - start_date).days // 7 + 1
        week_key = f"Semana {week_num}"
        metrics["by_week"][week_key] = metrics["by_week"].get(week_key, 0) + 1
    
    return jsonify({
        "success": True,
        "schedule": schedule,
        "monthly_calendar": monthly_calendar,
        "metrics": metrics,
        "config": {
            "start_date": start_date.isoformat(),
            "days": days,
            "population_size": population_size,
            "generations": generations
        }
    })


def build_monthly_calendar(schedule: List[Dict], start_date: date, days: int, availability_manager) -> Dict:
    """Build a monthly calendar structure for shift-planning view."""
    calendar = {
        "start_date": start_date.isoformat(),
        "days": days,
        "weeks": [],
        "by_date": {}
    }
    
    day_names = ["Seg", "Ter", "Qua", "Qui", "Sex", "Sáb", "Dom"]
    month_names = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho",
                   "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]
    
    # Group schedule by date
    schedule_by_date = {}
    for task in schedule:
        task_date = task['date']
        if task_date not in schedule_by_date:
            schedule_by_date[task_date] = []
        schedule_by_date[task_date].append(task)
    
    # Build calendar structure
    current_week = []
    current_date = start_date
    
    # Add padding for first week if not starting on Monday
    first_day_offset = current_date.weekday()
    for i in range(first_day_offset):
        current_week.append(None)
    
    for day_offset in range(days):
        current_date = start_date + timedelta(days=day_offset)
        date_str = current_date.isoformat()
        
        # Check if holiday
        is_holiday = False
        holiday_name = None
        if availability_manager and availability_manager.holidays:
            holiday = availability_manager.holidays.get(current_date)
            if holiday:
                is_holiday = True
                holiday_name = holiday.name
        
        # Get tasks for this day
        day_tasks = schedule_by_date.get(date_str, [])
        
        # Build day info
        day_info = {
            "date": date_str,
            "day": current_date.day,
            "day_name": day_names[current_date.weekday()],
            "month": month_names[current_date.month - 1],
            "is_weekend": current_date.weekday() >= 5,
            "is_holiday": is_holiday,
            "holiday_name": holiday_name,
            "tasks": day_tasks,
            "task_count": len(day_tasks),
            "summary": {
                "servers": list(set(t['server_id'] for t in day_tasks)),
                "cves": list(set(t['cve_id'] for t in day_tasks)),
                "workers": list(set(w for t in day_tasks for w in t.get('workers', []))),
                "environments": list(set(t['environment'] for t in day_tasks)),
                "total_hours": sum(t['duration'] for t in day_tasks)
            }
        }
        
        current_week.append(day_info)
        calendar["by_date"][date_str] = day_info
        
        # Start new week on Monday
        if current_date.weekday() == 6:  # Sunday
            calendar["weeks"].append(current_week)
            current_week = []
    
    # Add remaining days of last week
    if current_week:
        # Pad end of week
        while len(current_week) < 7:
            current_week.append(None)
        calendar["weeks"].append(current_week)
    
    return calendar


@app.route('/api/availability')
def api_availability():
    """Get team availability summary."""
    _, workers, availability_manager = load_data()
    
    start_date_str = request.args.get('start_date')
    days = int(request.args.get('days', 14))
    
    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    else:
        start_date = date.today()
    
    period = PlanningPeriod.from_days(days, start_date)
    
    if availability_manager:
        summary = availability_manager.get_availability_summary(period)
        holidays_in_period = availability_manager.get_holidays_in_period(period)
        
        return jsonify({
            "period": summary['period'],
            "total_days": summary['total_days'],
            "workers_with_absences": summary['workers_with_absences'],
            "days_off_by_worker": summary['days_off_by_worker'],
            "holidays": [
                {"date": h.date.isoformat(), "name": h.name}
                for h in holidays_in_period
            ]
        })
    
    return jsonify({"error": "Availability data not loaded"}), 500


@app.route('/api/plan', methods=['POST'])
def api_generate_plan():
    """
    Generate a patch schedule using Genetic Algorithm.
    Returns detailed execution report.
    
    Request body:
    {
        "selected_patches": [
            {"cve_id": "CVE-2025-1001", "server_ids": ["DEV_WebPortal_01", "TEST_WebPortal_01"]}
        ],
        "start_date": "2026-01-01",
        "days": 14,
        "population_size": 50,
        "generations": 100
    }
    """
    start_time = time.time()
    data = request.json or {}
    
    servers, workers, availability_manager = load_data()
    
    # Get config object if present (from frontend)
    config_data = data.get('config', {})
    
    # Get parameters - check both root level and config object
    start_date_str = data.get('start_date') or config_data.get('start_date')
    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    else:
        start_date = date.today()
    
    days = int(data.get('days') or config_data.get('planning_days') or 14)
    population_size = int(data.get('population_size') or config_data.get('population_size') or 50)
    generations = int(data.get('generations') or config_data.get('generations') or 100)
    
    logger.info(f"Plan config: start_date={start_date}, days={days}, generations={generations}")
    
    # Get or generate CVEs
    if _data_cache["cves"] is None:
        generate_cves(servers, 50)
    
    cves = _data_cache["cves"]
    cves_dict = {c.id: c for c in cves}
    servers_dict = {s.id: s for s in servers}
    
    # Build tasks from selected patches or frontend tasks
    tasks = []
    selected_patches = data.get('selected_patches', [])
    frontend_tasks = data.get('tasks', [])  # Tasks from frontend autoGeneratePlan
    
    if frontend_tasks:
        # Build tasks from frontend format (cve_id, server_id pairs)
        for task_data in frontend_tasks:
            cve_id = task_data.get('cve_id')
            server_id = task_data.get('server_id')
            
            cve = cves_dict.get(cve_id)
            server = servers_dict.get(server_id)
            
            if not cve or not server:
                continue
            
            # Find matching software
            for sw in server.installed_software:
                if sw.id == cve.affected_software_id:
                    tasks.append((cve, server, sw))
                    break
        logger.info(f"Built {len(tasks)} tasks from frontend format")
    elif selected_patches:
        # Build tasks from selection format
        for patch in selected_patches:
            cve_id = patch.get('cve_id')
            server_ids = patch.get('server_ids', [])
            
            cve = cves_dict.get(cve_id)
            if not cve:
                continue
            
            for server_id in server_ids:
                server = servers_dict.get(server_id)
                if not server:
                    continue
                
                # Find matching software
                for sw in server.installed_software:
                    if sw.id == cve.affected_software_id:
                        tasks.append((cve, server, sw))
                        break
        logger.info(f"Built {len(tasks)} tasks from selected_patches format")
    else:
        # If no selection, create tasks for all CVEs on affected servers
        for cve in cves:
            for server in servers:
                for sw in server.installed_software:
                    if sw.id == cve.affected_software_id:
                        tasks.append((cve, server, sw))
        logger.info(f"Built {len(tasks)} tasks from all CVEs")
    
    if not tasks:
        return jsonify({"error": "No valid tasks to schedule"}), 400
    
    logger.info(f"Scheduling {len(tasks)} tasks with GA")
    
    # Run genetic algorithm
    config = GAConfig(
        population_size=population_size,
        generations=generations,
        planning_weeks=(days + 6) // 7
    )
    
    scheduler = GeneticScheduler(
        servers=servers,
        workers=workers,
        cves=cves,
        tasks=tasks,
        config=config,
        availability_manager=availability_manager,
        start_date=start_date
    )
    
    best_chromosome, patch_tasks = scheduler.run(verbose=True)
    
    execution_time_ms = int((time.time() - start_time) * 1000)
    
    # Convert to response
    schedule = [task_to_dict(t, start_date) for t in patch_tasks]
    
    # Group by date for calendar view
    calendar = {}
    for task in schedule:
        task_date = task['date']
        if task_date not in calendar:
            calendar[task_date] = []
        calendar[task_date].append(task)
    
    # Calculate metrics
    metrics = {
        "total_tasks": len(tasks),
        "scheduled_tasks": len(patch_tasks),
        "success_rate": round((len(patch_tasks) / len(tasks) * 100) if tasks else 0, 1),
        "best_fitness": round(best_chromosome.fitness, 2),
        "by_environment": {},
        "by_severity": {},
        "by_worker": {}
    }
    
    # Count by environment, severity, and worker
    for task in schedule:
        env = task['environment']
        metrics["by_environment"][env] = metrics["by_environment"].get(env, 0) + 1
        
        sev = task['severity']
        metrics["by_severity"][sev] = metrics["by_severity"].get(sev, 0) + 1
        
        for worker_name in task.get('workers', []):
            # workers é uma lista de strings (nomes dos workers)
            metrics["by_worker"][worker_name] = metrics["by_worker"].get(worker_name, 0) + 1
    
    # Build detailed GA execution report
    ga_report = {
        "execution_date": datetime.now().isoformat(),
        "execution_time_ms": execution_time_ms,
        "config": {
            "population_size": population_size,
            "generations": generations,
            "crossover_rate": config.crossover_rate,
            "mutation_rate": config.mutation_rate,
            "elite_size": config.elite_size,
            "tournament_size": config.tournament_size,
            "planning_weeks": config.planning_weeks,
            "max_daily_hours": config.max_daily_hours
        },
        "evolution": {
            "best_fitness_history": scheduler.best_fitness_history,
            "avg_fitness_history": scheduler.avg_fitness_history,
            "initial_fitness": scheduler.best_fitness_history[0] if scheduler.best_fitness_history else 0,
            "final_fitness": best_chromosome.fitness,
            "improvement": round(
                (best_chromosome.fitness - scheduler.best_fitness_history[0]) / max(scheduler.best_fitness_history[0], 1) * 100, 2
            ) if scheduler.best_fitness_history else 0,
            "generations_to_best": max(
                i for i, f in enumerate(scheduler.best_fitness_history) if f == max(scheduler.best_fitness_history)
            ) + 1 if scheduler.best_fitness_history else 0
        },
        "results": {
            "total_tasks": len(tasks),
            "scheduled_tasks": len(patch_tasks),
            "failed_tasks": len(tasks) - len(patch_tasks),
            "success_rate": round((len(patch_tasks) / len(tasks) * 100) if tasks else 0, 2),
            "total_hours_scheduled": sum(t.get('duration', 0) for t in schedule),
            "by_severity": metrics["by_severity"],
            "by_environment": metrics["by_environment"],
            "by_worker": metrics["by_worker"]
        },
        "analysis": {
            "critical_scheduled": metrics["by_severity"].get("Critical", 0),
            "high_scheduled": metrics["by_severity"].get("High", 0),
            "workers_utilized": len(metrics["by_worker"]),
            "total_workers_available": len(workers),
            "worker_utilization_rate": round(len(metrics["by_worker"]) / len(workers) * 100, 2) if workers else 0
        }
    }
    
    # Save report to database
    try:
        db = get_database()
        db_report = GAExecutionReport(
            execution_date=ga_report["execution_date"],
            start_date=start_date.isoformat(),
            planning_days=days,
            population_size=population_size,
            generations=generations,
            total_tasks=len(tasks),
            scheduled_tasks=len(patch_tasks),
            success_rate=metrics["success_rate"],
            best_fitness=best_chromosome.fitness,
            fitness_history=json.dumps(scheduler.best_fitness_history),
            avg_fitness_history=json.dumps(scheduler.avg_fitness_history),
            tasks_by_severity=json.dumps(metrics["by_severity"]),
            tasks_by_environment=json.dumps(metrics["by_environment"]),
            tasks_by_worker=json.dumps(metrics["by_worker"]),
            execution_time_ms=execution_time_ms,
            config_json=json.dumps(ga_report["config"]),
            schedule_json=json.dumps(schedule)
        )
        report_id = db.save_ga_report(db_report)
        ga_report["report_id"] = report_id
    except Exception as e:
        logger.warning(f"Failed to save GA report to database: {e}")
    
    return jsonify({
        "success": True,
        "schedule": schedule,
        "calendar": calendar,
        "metrics": metrics,
        "ga_report": ga_report,
        "config": {
            "start_date": start_date.isoformat(),
            "days": days,
            "population_size": population_size,
            "generations": generations
        }
    })


@app.route('/api/maintenance-windows')
def api_maintenance_windows():
    """Get maintenance windows for calendar display."""
    servers, _, _ = load_data()
    
    start_date_str = request.args.get('start_date')
    days = int(request.args.get('days', 14))
    
    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    else:
        start_date = date.today()
    
    # Build calendar with maintenance windows
    calendar = {}
    day_names = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
    
    for day_offset in range(days):
        current_date = start_date + timedelta(days=day_offset)
        day_of_week = current_date.weekday()
        date_str = current_date.isoformat()
        
        windows = []
        for server in servers:
            for win_day, win_start, win_end in server.downtime_windows:
                if win_day == day_of_week:
                    windows.append({
                        "server_id": server.id,
                        "environment": server.environment,
                        "start": win_start,
                        "end": win_end
                    })
        
        calendar[date_str] = {
            "day_name": day_names[day_of_week],
            "windows": windows
        }
    
    return jsonify({
        "start_date": start_date.isoformat(),
        "days": days,
        "calendar": calendar
    })


@app.route('/api/stats')
def api_stats():
    """Get overall statistics."""
    servers, workers, availability_manager = load_data()
    
    if _data_cache["cves"] is None:
        load_cves_from_csv(servers, 200)
    
    cves = _data_cache["cves"]
    
    # Server stats by environment
    env_counts = {}
    for s in servers:
        env_counts[s.environment] = env_counts.get(s.environment, 0) + 1
    
    # CVE stats by severity
    severity_counts = {}
    for c in cves:
        severity_counts[c.severity] = severity_counts.get(c.severity, 0) + 1
    
    # Worker stats by level
    level_counts = {}
    for w in workers:
        level_counts[w.level] = level_counts.get(w.level, 0) + 1
    
    # Software stats
    software_set = set()
    for s in servers:
        for sw in s.installed_software:
            software_set.add(sw.id)
    
    return jsonify({
        "total_servers": len(servers),
        "total_cves": len(cves),
        "total_workers": len(workers),
        "total_holidays": len(availability_manager.holidays) if availability_manager else 0,
        "servers_by_environment": env_counts,
        "cves_by_severity": severity_counts,
        "workers_by_level": level_counts,
        "unique_software": len(software_set)
    })


@app.route('/api/patches/required')
def api_patches_required():
    """
    Get patches required for each server based on installed software.
    Returns data organized by server with CVE details.
    
    Query params:
        max_cves: Maximum CVEs to load (default: 10000, use 0 for unlimited)
    """
    servers, _, _ = load_data()
    
    # Get max_cves parameter (default 10000 for better coverage)
    max_cves = request.args.get('max_cves', 10000, type=int)
    if max_cves == 0:
        max_cves = 999999  # Effectively unlimited
    
    # Reload CVEs if needed or if requesting more than currently loaded
    current_cves_count = len(_data_cache["cves"]) if _data_cache["cves"] else 0
    if _data_cache["cves"] is None or current_cves_count < max_cves:
        load_cves_from_csv(servers, max_cves)
    
    cves = _data_cache["cves"]
    cve_metadata = _data_cache.get("cve_metadata", {})
    
    # Build list of required patches by server
    result = []
    
    for server in servers:
        server_patches = []
        for cve in cves:
            for sw in server.installed_software:
                if sw.id == cve.affected_software_id:
                    # Get published_date from metadata cache
                    metadata = cve_metadata.get(cve.id, {})
                    published_date = metadata.get("published_date", "")
                    
                    server_patches.append({
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "priority": round(cve.final_priority_score, 2),
                        "software": sw.id,
                        "software_version": sw.version,
                        "duration_hours": cve.estimated_fix_time,
                        "operators_required": cve.operators_required,
                        "published_date": published_date
                    })
                    break
        
        if server_patches:
            result.append({
                "server_id": server.id,
                "environment": server.environment,
                "application_group": server.application_group,
                "patches": sorted(server_patches, key=lambda p: p["priority"], reverse=True)
            })
    
    # Sort by environment priority (PROD > TEST > DEV)
    env_order = {"PROD": 0, "TEST": 1, "DEV": 2}
    result.sort(key=lambda s: (env_order.get(s["environment"], 3), -len(s["patches"])))
    
    return jsonify({
        "servers": result,
        "total_servers": len(result),
        "total_patches": sum(len(s["patches"]) for s in result)
    })


# ============================================================
# DATABASE CVE ENDPOINTS
# ============================================================

@app.route('/api/db/init', methods=['POST'])
def api_db_init():
    """
    Initialize database and import CVEs from CSV.
    
    Request body:
    {
        "clear_existing": false  // If true, removes existing CVEs before import
    }
    """
    data = request.json or {}
    clear_existing = data.get('clear_existing', False)
    
    try:
        db = get_database()
        
        # Find CSV file
        csv_path = os.path.join(os.path.dirname(__file__), 'dataset', 'merged_cve_data.csv')
        
        if not os.path.exists(csv_path):
            return jsonify({"error": f"CVE dataset not found at {csv_path}"}), 404
        
        count = db.import_cves_from_csv(csv_path, clear_existing=clear_existing)
        
        return jsonify({
            "success": True,
            "message": f"Imported {count} CVEs to database",
            "csv_path": csv_path,
            "cleared_existing": clear_existing
        })
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/db/cves')
def api_db_get_cves():
    """
    Get CVEs from database with pagination and filters.
    
    Query parameters:
    - page: Page number (default: 1)
    - per_page: Items per page (default: 50, max: 200)
    - severity: Filter by severity (Critical, High, Medium, Low)
    - min_score: Minimum CVSS score
    - max_score: Maximum CVSS score
    - vendor: Filter by vendor (partial match)
    - search: Search in CVE ID, products, and CWE description
    - sort_by: Sort field (base_score, epss_score, published_date, cve_id)
    - sort_order: ASC or DESC (default: DESC)
    - cisa_kev: If "true", show only CISA KEV listed CVEs
    """
    try:
        page, per_page = validate_pagination(
            request.args.get('page', 1),
            request.args.get('per_page', 50),
            max_per_page=200
        )
        
        severity = request.args.get('severity')
        min_score = request.args.get('min_score')
        max_score = request.args.get('max_score')
        vendor = request.args.get('vendor')
        search = request.args.get('search')
        sort_by = request.args.get('sort_by', 'base_score')
        sort_order = request.args.get('sort_order', 'DESC')
        cisa_kev = request.args.get('cisa_kev', '').lower() == 'true'
        
        # Parse numeric filters
        min_score = float(min_score) if min_score else None
        max_score = float(max_score) if max_score else None
        
        db = get_database()
        cves, total = db.get_all_cves(
            page=page,
            per_page=per_page,
            severity=severity,
            min_score=min_score,
            max_score=max_score,
            vendor=vendor,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            cisa_kev_only=cisa_kev
        )
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            "cves": cves,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            }
        })
    except ValidationError as e:
        return jsonify({"error": e.message}), e.status_code
    except Exception as e:
        logger.error(f"Error getting CVEs from database: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/db/cves/<cve_id>')
def api_db_get_cve(cve_id: str):
    """Get a single CVE by ID from database."""
    try:
        db = get_database()
        cve = db.get_cve_by_id(cve_id)
        
        if not cve:
            return jsonify({"error": f"CVE {cve_id} not found"}), 404
        
        return jsonify(cve)
    except Exception as e:
        logger.error(f"Error getting CVE {cve_id}: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/db/cves/stats')
def api_db_cve_stats():
    """Get CVE statistics from database."""
    try:
        db = get_database()
        stats = db.get_cve_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting CVE stats: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# GA REPORT ENDPOINTS
# ============================================================

@app.route('/api/reports')
def api_get_reports():
    """Get recent GA execution reports."""
    try:
        limit = int(request.args.get('limit', 10))
        limit = min(limit, 100)  # Max 100
        
        db = get_database()
        reports = db.get_recent_ga_reports(limit=limit)
        
        return jsonify({
            "reports": reports,
            "count": len(reports)
        })
    except Exception as e:
        logger.error(f"Error getting reports: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/reports/<int:report_id>')
def api_get_report(report_id: int):
    """Get a specific GA execution report with full details."""
    try:
        db = get_database()
        report = db.get_ga_report(report_id)
        
        if not report:
            return jsonify({"error": f"Report {report_id} not found"}), 404
        
        return jsonify(report)
    except Exception as e:
        logger.error(f"Error getting report {report_id}: {e}")
        return jsonify({"error": str(e)}), 500


# ============================================================
# APPLIED PATCHES ENDPOINTS
# ============================================================

@app.route('/api/patches/applied', methods=['GET'])
def api_get_applied_patches():
    """Get list of applied patches."""
    try:
        server_id = request.args.get('server_id')
        cve_id = request.args.get('cve_id')
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        
        db = get_database()
        patches = db.get_applied_patches(
            server_id=server_id,
            cve_id=cve_id,
            from_date=from_date,
            to_date=to_date
        )
        
        return jsonify({
            "patches": patches,
            "count": len(patches)
        })
    except Exception as e:
        logger.error(f"Error getting applied patches: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/patches/applied', methods=['POST'])
def api_record_applied_patch():
    """Record a patch as applied."""
    try:
        data = request.json or {}
        
        cve_id = data.get('cve_id')
        server_id = data.get('server_id')
        
        if not cve_id or not server_id:
            return jsonify({"error": "cve_id and server_id are required"}), 400
        
        db = get_database()
        
        # Check if already applied
        if db.is_patch_applied(cve_id, server_id):
            return jsonify({"error": f"Patch {cve_id} already applied to {server_id}"}), 409
        
        patch_id = db.record_applied_patch(
            cve_id=cve_id,
            server_id=server_id,
            software_id=data.get('software_id'),
            applied_by=data.get('applied_by'),
            duration_hours=data.get('duration_hours'),
            notes=data.get('notes'),
            ga_report_id=data.get('ga_report_id')
        )
        
        return jsonify({
            "success": True,
            "patch_id": patch_id,
            "message": f"Patch {cve_id} recorded as applied to {server_id}"
        }), 201
    except Exception as e:
        logger.error(f"Error recording applied patch: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/patches/check', methods=['POST'])
def api_check_patches():
    """Check if patches are already applied."""
    try:
        data = request.json or {}
        patches_to_check = data.get('patches', [])
        
        if not patches_to_check:
            return jsonify({"error": "patches array is required"}), 400
        
        db = get_database()
        results = []
        
        for patch in patches_to_check:
            cve_id = patch.get('cve_id')
            server_id = patch.get('server_id')
            
            if cve_id and server_id:
                results.append({
                    "cve_id": cve_id,
                    "server_id": server_id,
                    "is_applied": db.is_patch_applied(cve_id, server_id)
                })
        
        return jsonify({
            "results": results,
            "checked": len(results)
        })
    except Exception as e:
        logger.error(f"Error checking patches: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    
    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(static_dir, exist_ok=True)
    os.makedirs(os.path.join(static_dir, 'css'), exist_ok=True)
    os.makedirs(os.path.join(static_dir, 'js'), exist_ok=True)
    
    # Run the app (debug=False to avoid TTY issues in background)
    app.run(host='0.0.0.0', port=5000, debug=False)
