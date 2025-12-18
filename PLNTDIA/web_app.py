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
from datetime import datetime, date, timedelta
from typing import List, Dict, Tuple, Optional
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.domain import Server, CVE, Software, Worker, PatchTask
from src.repository import load_servers_from_csv, load_workers_from_csv, generate_cves_for_infrastructure
from src.availability import AvailabilityManager, PlanningPeriod
from src.genetic_algorithm import run_genetic_scheduler, GAConfig, GeneticScheduler
from src.logic import calculate_priority

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
CORS(app)

# Global data cache
_data_cache = {
    "servers": None,
    "workers": None,
    "cves": None,
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
    """API health check."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "cached_data": _data_cache["last_load"].isoformat() if _data_cache["last_load"] else None
    })

@app.route('/api/servers')
def api_servers():
    """Get all servers."""
    servers, _, _ = load_data()
    
    # Filter by environment if provided
    env = request.args.get('environment')
    if env:
        servers = [s for s in servers if s.environment == env.upper()]
    
    # Filter by application group if provided
    app_group = request.args.get('application_group')
    if app_group:
        servers = [s for s in servers if s.application_group == app_group]
    
    return jsonify({
        "count": len(servers),
        "servers": [server_to_dict(s) for s in servers]
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
    """Get all CVEs from the real dataset."""
    servers, _, _ = load_data()
    
    # Get count parameter (default 200 for real CVEs)
    count = int(request.args.get('count', 200))
    use_real = request.args.get('real', 'true').lower() == 'true'
    
    # Load real CVEs from CSV or generate
    if _data_cache["cves"] is None:
        if use_real:
            load_cves_from_csv(servers, count)
        else:
            generate_cves(servers, count)
    
    cves = _data_cache["cves"]
    
    # Filter by severity if provided
    severity = request.args.get('severity')
    if severity:
        cves = [c for c in cves if c.severity.lower() == severity.lower()]
    
    # Filter by software if provided
    software = request.args.get('software')
    if software:
        cves = [c for c in cves if software.lower() in c.affected_software_id.lower()]
    
    # Sort options
    sort_by = request.args.get('sort', 'priority')
    if sort_by == 'priority':
        cves = sorted(cves, key=lambda c: c.final_priority_score, reverse=True)
    elif sort_by == 'severity':
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        cves = sorted(cves, key=lambda c: severity_order.get(c.severity, 0), reverse=True)
    elif sort_by == 'epss':
        cves = sorted(cves, key=lambda c: c.epss_score, reverse=True)
    
    return jsonify({
        "count": len(cves),
        "cves": [cve_to_dict(c) for c in cves]
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
    """Get servers affected by a CVE."""
    servers, _, _ = load_data()
    
    if _data_cache["cves"] is None:
        generate_cves(servers, 50)
    
    cve = next((c for c in _data_cache["cves"] if c.id == cve_id), None)
    if not cve:
        return jsonify({"error": "CVE not found"}), 404
    
    # Find affected servers
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
    data = request.json or {}
    
    servers, workers, availability_manager = load_data()
    
    # Get parameters
    start_date_str = data.get('start_date')
    if start_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
    else:
        start_date = date.today()
    
    days = int(data.get('days', 14))
    population_size = int(data.get('population_size', 50))
    generations = int(data.get('generations', 100))
    
    # Get or generate CVEs
    if _data_cache["cves"] is None:
        generate_cves(servers, 50)
    
    cves = _data_cache["cves"]
    cves_dict = {c.id: c for c in cves}
    servers_dict = {s.id: s for s in servers}
    
    # Build tasks from selected patches
    tasks = []
    selected_patches = data.get('selected_patches', [])
    
    if not selected_patches:
        # If no selection, create tasks for all CVEs on affected servers
        for cve in cves:
            for server in servers:
                for sw in server.installed_software:
                    if sw.id == cve.affected_software_id:
                        tasks.append((cve, server, sw))
    else:
        # Build tasks from selection
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
        "by_severity": {}
    }
    
    # Count by environment
    for task in schedule:
        env = task['environment']
        metrics["by_environment"][env] = metrics["by_environment"].get(env, 0) + 1
        
        sev = task['severity']
        metrics["by_severity"][sev] = metrics["by_severity"].get(sev, 0) + 1
    
    return jsonify({
        "success": True,
        "schedule": schedule,
        "calendar": calendar,
        "metrics": metrics,
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
    """
    servers, _, _ = load_data()
    
    if _data_cache["cves"] is None:
        load_cves_from_csv(servers, 200)
    
    cves = _data_cache["cves"]
    
    # Build list of required patches by server
    result = []
    
    for server in servers:
        server_patches = []
        for cve in cves:
            for sw in server.installed_software:
                if sw.id == cve.affected_software_id:
                    server_patches.append({
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "priority": round(cve.final_priority_score, 2),
                        "software": sw.id,
                        "software_version": sw.version,
                        "duration_hours": cve.estimated_fix_time,
                        "operators_required": cve.operators_required
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
