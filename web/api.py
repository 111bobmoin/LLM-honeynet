#!/usr/bin/env python3
"""
Flask API Server for LLM Honeynet Platform
Provides REST API for perception, orchestration, and deception phases
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

# Import project modules
import sys
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from perception import analyze_host, load_rules
from orchestrator import HoneyAgent, HoneyAgentConfig, TrapAgent, TrapAgentConfig
from deception import DeceptionAgent, DeceptionAgentConfig
from perception.analyzer import discover_hosts

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

# Global state for async operations
operations: Dict[str, Dict[str, Any]] = {}
operations_lock = threading.Lock()


class OperationStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


def update_operation_status(op_id: str, status: str, result: Any = None, error: str = None):
    with operations_lock:
        if op_id in operations:
            operations[op_id]["status"] = status
            operations[op_id]["timestamp"] = datetime.now().isoformat()
            if result is not None:
                operations[op_id]["result"] = result
            if error is not None:
                operations[op_id]["error"] = error


def create_operation(operation_type: str, params: Dict = None) -> str:
    op_id = f"{operation_type}_{int(time.time() * 1000)}"
    with operations_lock:
        operations[op_id] = {
            "id": op_id,
            "type": operation_type,
            "status": OperationStatus.PENDING,
            "params": params or {},
            "result": None,
            "error": None,
            "timestamp": datetime.now().isoformat(),
            "created_at": datetime.now().isoformat()
        }
    return op_id


def run_async_task(coro, op_id: str):
    """Run async task in a separate thread"""
    def run_in_thread():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            update_operation_status(op_id, OperationStatus.RUNNING)
            result = loop.run_until_complete(coro)
            update_operation_status(op_id, OperationStatus.COMPLETED, result=result)
            loop.close()
        except Exception as e:
            update_operation_status(op_id, OperationStatus.FAILED, error=str(e))

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()


def run_sync_task(func, op_id: str):
    """Run sync task in a separate thread"""
    def run_in_thread():
        try:
            update_operation_status(op_id, OperationStatus.RUNNING)
            result = func()
            update_operation_status(op_id, OperationStatus.COMPLETED, result=result)
        except Exception as e:
            update_operation_status(op_id, OperationStatus.FAILED, error=str(e))

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()


# ========== API Routes ==========

@app.route('/')
def index():
    """Serve the main HTML page"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })


# ========== Dashboard Summary ==========

@app.route('/api/dashboard/summary')
def dashboard_summary():
    """Get overall dashboard summary"""
    # Get operation statistics
    with operations_lock:
        total_ops = len(operations)
        completed_ops = sum(1 for op in operations.values() if op["status"] == OperationStatus.COMPLETED)
        failed_ops = sum(1 for op in operations.values() if op["status"] == OperationStatus.FAILED)
        running_ops = sum(1 for op in operations.values() if op["status"] == OperationStatus.RUNNING)

    # Check available hosts
    try:
        hosts = discover_hosts(include_base=False)
        host_list = [{"name": h, "path": str(p)} for h, p in hosts.items()]
    except Exception:
        host_list = []

    # Check shadow files
    shadow_path = project_root / "shadow"
    shadow_files = {}
    if shadow_path.exists():
        for f in ["honey_agent.json", "trap_agent.json", "long_memory.json", "attacker_preferences.json"]:
            file_path = shadow_path / f
            shadow_files[f] = {
                "exists": file_path.exists(),
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat() if file_path.exists() else None
            }

    return jsonify({
        "operations": {
            "total": total_ops,
            "completed": completed_ops,
            "failed": failed_ops,
            "running": running_ops
        },
        "hosts": {
            "count": len(host_list),
            "list": host_list
        },
        "shadow_files": shadow_files,
        "timestamp": datetime.now().isoformat()
    })


# ========== Recent Operations ==========

@app.route('/api/operations')
def get_operations():
    """Get all operations, optionally filtered by type or status"""
    op_type = request.args.get('type')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 20))

    with operations_lock:
        ops = list(operations.values())

    # Apply filters
    if op_type:
        ops = [op for op in ops if op["type"] == op_type]
    if status:
        ops = [op for op in ops if op["status"] == status]

    # Sort by created_at descending and limit
    ops.sort(key=lambda x: x["created_at"], reverse=True)
    ops = ops[:limit]

    return jsonify({"operations": ops})


@app.route('/api/operations/<op_id>')
def get_operation(op_id: str):
    """Get specific operation details"""
    with operations_lock:
        if op_id not in operations:
            return jsonify({"error": "Operation not found"}), 404
        return jsonify(operations[op_id])


# ========== Phase 1: Perception ==========

@app.route('/api/perception/hosts')
def get_hosts():
    """Get available hosts for perception analysis"""
    try:
        hosts = discover_hosts(include_base=False)
        host_list = []
        for host_name, log_dir in hosts.items():
            host_info = {
                "name": host_name,
                "log_dir": str(log_dir),
                "log_files": []
            }
            if log_dir.exists():
                for log_file in sorted(log_dir.glob("*.log")):
                    host_info["log_files"].append({
                        "name": log_file.name,
                        "size": log_file.stat().st_size,
                        "modified": datetime.fromtimestamp(log_file.stat().st_mtime).isoformat()
                    })
            host_list.append(host_info)

        return jsonify({"hosts": host_list})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/perception/analyze', methods=['POST'])
def run_perception():
    """Run perception analysis on hosts"""
    data = request.json or {}
    hosts = data.get('hosts')  # None means auto-discover
    use_openai = data.get('use_openai', False)

    def perception_task():
        try:
            discovered = discover_hosts(include_base=False)
            selected = {}

            if hosts:
                for host in hosts:
                    if host in discovered:
                        selected[host] = discovered[host]
            else:
                selected = discovered

            if not selected:
                raise ValueError("No hosts found for analysis")

            analyses = []
            config_dir = project_root / "config"

            for host, log_dir in selected.items():
                if not log_dir.exists():
                    continue

                rules = load_rules(config_dir)
                analysis = analyze_host(host, log_dir, rules)
                analyses.append({
                    "host": analysis.host,
                    "max_stage": analysis.max_stage,
                    "stage_label": analysis.stage_label(),
                    "event_count": len(analysis.events),
                    "events": [
                        {
                            "timestamp": ev.timestamp.isoformat(),
                            "stage": ev.stage,
                            "summary": ev.summary()
                        }
                        for ev in analysis.events[-20:]  # Last 20 events
                    ]
                })

            result = {
                "analyses": analyses,
                "total_hosts": len(analyses),
                "timestamp": datetime.now().isoformat()
            }

            # Optionally call OpenAI for summary
            if use_openai:
                try:
                    from perception import OpenAISummarizer
                    summarizer = OpenAISummarizer()
                    # Convert to HostAnalysis objects
                    from perception.analyzer import HostAnalysis, HostEvent
                    host_analyses = []
                    for a in analyses:
                        events = []
                        # Reconstruct events from summary data
                        for e in a.get("events", []):
                            events.append(HostEvent(
                                timestamp=datetime.fromisoformat(e["timestamp"]),
                                raw={"summary": e["summary"], "stage": e["stage"]}
                            ))
                        host_analyses.append(HostAnalysis(
                            host=a["host"],
                            max_stage=a["max_stage"],
                            events=events
                        ))
                    summary = summarizer.summarize(host_analyses)
                    result["openai_summary"] = summary
                except Exception as e:
                    result["openai_error"] = str(e)

            return result

        except Exception as e:
            raise Exception(f"Perception analysis failed: {e}")

    op_id = create_operation("perception", {"hosts": hosts, "use_openai": use_openai})
    run_sync_task(perception_task, op_id)

    return jsonify({"operation_id": op_id, "status": "started"})


# ========== Phase 2: Orchestration ==========

@app.route('/api/orchestrate/honey', methods=['POST'])
def run_honey_agent():
    """Run Honey Agent to generate decoys"""
    data = request.json or {}
    mode = data.get('mode', 'initialization')  # initialization or finetune

    def honey_task():
        try:
            config = HoneyAgentConfig(
                short_memory_path=project_root / "shadow/honey_agent.json",
                long_memory_path=project_root / "shadow/long_memory.json",
                topology_path=project_root / "shadow/shadow_topology.json",
                fallback_topology_path=project_root / "enterprise/enterprise_topology.json",
                preferences_path=project_root / "shadow/attacker_preferences.json",
                openai_key_path=project_root / "secrets/openai_api_key.txt",
                openai_model=data.get('openai_model', 'gpt-4o-mini'),
                openai_temperature=data.get('openai_temperature', 0.1),
                openai_top_p=data.get('openai_top_p', 0.9)
            )

            agent = HoneyAgent(config)

            if mode == "initialization":
                result = agent.run_initialization()
            else:
                result = agent.run_finetune()

            return {
                "mode": mode,
                "hosts_generated": len(result.get("short_memory", [])),
                "topology": result.get("topology", {}),
                "preferences": result.get("preferences", []),
                "short_memory": result.get("short_memory", []),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            raise Exception(f"Honey Agent failed: {e}")

    op_id = create_operation("honey_agent", {"mode": mode})
    run_sync_task(honey_task, op_id)

    return jsonify({"operation_id": op_id, "status": "started"})


@app.route('/api/orchestrate/trap', methods=['POST'])
def run_trap_agent():
    """Run Trap Agent to generate trap chains"""
    data = request.json or {}
    mode = data.get('mode', 'all')  # host, interhost, or all

    def trap_task():
        try:
            config = TrapAgentConfig(
                short_memory_path=project_root / "shadow/honey_agent.json",
                trap_memory_path=project_root / "shadow/trap_agent.json",
                topology_path=project_root / "shadow/shadow_topology.json",
                fallback_topology_path=project_root / "enterprise/enterprise_topology.json",
                preferences_path=project_root / "shadow/attacker_preferences.json",
                openai_key_path=project_root / "secrets/openai_api_key.txt",
                openai_model=data.get('openai_model', 'gpt-4o-mini'),
                openai_temperature=data.get('openai_temperature', 0.15),
                openai_top_p=data.get('openai_top_p', 0.85)
            )

            agent = TrapAgent(config)

            if mode == "host":
                result = agent.run_host_trap_chain()
            elif mode == "interhost":
                result = agent.run_interhost_trap_chain()
            else:
                result = agent.run_full_pipeline()

            return {
                "mode": mode,
                "hosts": result.get("hosts", []),
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            raise Exception(f"Trap Agent failed: {e}")

    op_id = create_operation("trap_agent", {"mode": mode})
    run_sync_task(trap_task, op_id)

    return jsonify({"operation_id": op_id, "status": "started"})


@app.route('/api/orchestrate/status')
def get_orchestration_status():
    """Get current orchestration status from shadow files"""
    shadow_path = project_root / "shadow"

    status = {
        "honey_agent": {"exists": False, "hosts": 0},
        "trap_agent": {"exists": False, "hosts": 0, "chains": 0},
        "long_memory": {"exists": False},
        "attacker_preferences": {"exists": False, "count": 0}
    }

    # Check honey_agent.json
    honey_path = shadow_path / "honey_agent.json"
    if honey_path.exists():
        try:
            data = json.loads(honey_path.read_text(encoding="utf-8"))
            status["honey_agent"] = {
                "exists": True,
                "hosts": len(data.get("hosts", [])),
                "modified": datetime.fromtimestamp(honey_path.stat().st_mtime).isoformat()
            }
        except Exception:
            pass

    # Check trap_agent.json
    trap_path = shadow_path / "trap_agent.json"
    if trap_path.exists():
        try:
            data = json.loads(trap_path.read_text(encoding="utf-8"))
            status["trap_agent"] = {
                "exists": True,
                "hosts": len(data.get("hosts", [])),
                "chains": len(data.get("chains", [])),
                "modified": datetime.fromtimestamp(trap_path.stat().st_mtime).isoformat()
            }
        except Exception:
            pass

    # Check attacker_preferences.json
    prefs_path = shadow_path / "attacker_preferences.json"
    if prefs_path.exists():
        try:
            data = json.loads(prefs_path.read_text(encoding="utf-8"))
            status["attacker_preferences"] = {
                "exists": True,
                "count": len(data) if isinstance(data, list) else 0,
                "modified": datetime.fromtimestamp(prefs_path.stat().st_mtime).isoformat()
            }
        except Exception:
            pass

    # Check long_memory.json
    long_memory_path = shadow_path / "long_memory.json"
    status["long_memory"]["exists"] = long_memory_path.exists()
    if long_memory_path.exists():
        status["long_memory"]["modified"] = datetime.fromtimestamp(long_memory_path.stat().st_mtime).isoformat()

    return jsonify(status)


# ========== Phase 3: Deception ==========

@app.route('/api/deception/run', methods=['POST'])
def run_deception():
    """Run Deception Agent for consistency check and config generation"""
    data = request.json or {}
    mode = data.get('mode', 'full')  # consistency, generate-configs, or full
    hosts = data.get('hosts')  # Optional host filter

    def deception_task():
        try:
            config = DeceptionAgentConfig(
                deployments_root=project_root / "deployments",
                base_config_dir=project_root / "config",
                short_memory_path=project_root / "shadow/honey_agent.json",
                long_memory_path=project_root / "shadow/long_memory.json",
                trap_memory_path=project_root / "shadow/trap_agent.json"
            )

            agent = DeceptionAgent(config)
            results = {}

            if mode in ["consistency", "full"]:
                consistency_report = agent.run_consistency_check(save=True)
                results["consistency_report"] = consistency_report

            if mode in ["generate-configs", "full"]:
                # Handle hosts parameter - can be string (comma-separated) or list
                if hosts:
                    if isinstance(hosts, str):
                        host_set = [h.strip() for h in hosts.split(",") if h.strip()]
                    elif isinstance(hosts, list):
                        host_set = [str(h).strip() for h in hosts if h]
                    else:
                        host_set = None
                else:
                    host_set = None

                host_configs = agent.generate_host_configs(hosts=host_set)
                results["host_configs"] = {
                    "generated": len(host_configs) if isinstance(host_configs, dict) else 0,
                    "hosts": list(host_configs.keys()) if isinstance(host_configs, dict) else []
                }

            return {
                "mode": mode,
                "results": results,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            raise Exception(f"Deception Agent failed: {e}")

    op_id = create_operation("deception", {"mode": mode, "hosts": hosts})
    run_sync_task(deception_task, op_id)

    return jsonify({"operation_id": op_id, "status": "started"})


@app.route('/api/deception/consistency')
def get_consistency_report():
    """Get the latest consistency report"""
    report_path = project_root / "shadow/deception_consistency_report.json"

    if not report_path.exists():
        return jsonify({"exists": False, "error": "No consistency report found"})

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
        data["exists"] = True
        data["modified"] = datetime.fromtimestamp(report_path.stat().st_mtime).isoformat()
        return jsonify(data)
    except Exception as e:
        return jsonify({"exists": False, "error": str(e)})


@app.route('/api/deployment/hosts')
def get_deployment_hosts():
    """Get available deployment hosts"""
    deployments_path = project_root / "deployments"

    if not deployments_path.exists():
        return jsonify({"hosts": []})

    hosts = []
    for host_dir in sorted(deployments_path.iterdir()):
        if host_dir.is_dir():
            host_info = {
                "name": host_dir.name,
                "path": str(host_dir),
                "has_config": (host_dir / "config").exists(),
                "has_logs": (host_dir / "logs").exists()
            }

            # Check config files
            if host_info["has_config"]:
                configs = []
                for cfg in (host_dir / "config").glob("*_config.json"):
                    configs.append(cfg.name)
                host_info["configs"] = configs

            hosts.append(host_info)

    return jsonify({"hosts": hosts})


# ========== Configuration ==========

@app.route('/api/config/topology')
def get_topology():
    """Get current topology configuration"""
    shadow_path = project_root / "shadow/shadow_topology.json"
    enterprise_path = project_root / "enterprise/enterprise_topology.json"

    result = {"shadow_exists": shadow_path.exists(), "enterprise_exists": enterprise_path.exists()}

    if shadow_path.exists():
        try:
            result["shadow"] = json.loads(shadow_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    if enterprise_path.exists():
        try:
            result["enterprise"] = json.loads(enterprise_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    return jsonify(result)


@app.route('/api/config/preferences', methods=['GET', 'POST'])
def handle_preferences():
    """Get or update attacker preferences"""
    prefs_path = project_root / "shadow/attacker_preferences.json"

    if request.method == 'POST':
        data = request.json
        preferences = data.get('preferences', [])

        prefs_path.parent.mkdir(parents=True, exist_ok=True)
        prefs_path.write_text(
            json.dumps(preferences, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8"
        )

        return jsonify({"success": True, "count": len(preferences)})

    # GET
    if prefs_path.exists():
        try:
            data = json.loads(prefs_path.read_text(encoding="utf-8"))
            return jsonify({"exists": True, "preferences": data})
        except Exception:
            pass

    return jsonify({"exists": False, "preferences": []})


# ========== Utility Routes ==========

@app.route('/api/shadow/data')
def get_shadow_data():
    """Get combined shadow data for visualization"""
    result = {}

    for filename in ["honey_agent.json", "trap_agent.json", "long_memory.json"]:
        path = project_root / "shadow" / filename
        if path.exists():
            try:
                result[filename.replace(".json", "")] = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                result[filename.replace(".json", "")] = {"error": "Failed to parse"}

    return jsonify(result)


def main():
    """Run the Flask development server"""
    print("Starting LLM Honeynet Web API...")
    print("Dashboard will be available at: http://localhost:5000")
    print("API endpoints: http://localhost:5000/api/")
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == '__main__':
    main()
