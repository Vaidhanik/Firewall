import os
import json
from typing import Dict, Any
from flask import Flask, request, jsonify
from network_control import NetworkController

app = Flask(__name__)
controller = NetworkController()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'monitor_active': controller.get_monitor_status()['running']
    })

@app.route('/apps', methods=['GET'])
def list_apps():
    """List installed applications"""
    return jsonify({
        'apps': controller.installed_apps
    })

@app.route('/search', methods=['GET'])
def search_apps():
    """Search applications"""
    query = request.args.get('q', '')
    matches = controller.search_installed_apps(query)
    return jsonify({
        'query': query,
        'matches': matches
    })

@app.route('/block', methods=['POST'])
def block_app():
    """Block application from accessing target"""
    data = request.get_json()
    app_name = data.get('app')
    target = data.get('target')
    
    if not app_name or not target:
        return jsonify({
            'success': False,
            'error': 'Missing app name or target'
        }), 400
        
    success = controller.block_app_network(app_name, target)
    return jsonify({
        'success': success,
        'app': app_name,
        'target': target
    })

@app.route('/unblock', methods=['POST'])
def unblock_app():
    """Remove blocking rule"""
    data = request.get_json()
    rule_id = data.get('rule_id')
    
    if not rule_id:
        return jsonify({
            'success': False,
            'error': 'Missing rule_id'
        }), 400
        
    success = controller.unblock_app_network(rule_id)
    return jsonify({
        'success': success,
        'rule_id': rule_id
    })

@app.route('/rules', methods=['GET'])
def get_rules():
    """Get active blocking rules"""
    return jsonify({
        'rules': controller.get_active_blocks()
    })

# @app.route('/monitor/start', methods=['POST'])
# def start_monitor():
#     """Start network monitoring"""
#     success = controller.start_detached_monitor()
#     return jsonify({
#         'success': success,
#         'status': controller.get_monitor_status()
#     })

@app.route('/monitor/stop', methods=['POST'])
def stop_monitor():
    """Stop network monitoring"""
    success = controller.stop_monitor()
    return jsonify({
        'success': success
    })

@app.route('/monitor/status', methods=['GET'])
def monitor_status():
    """Get monitoring status"""
    return jsonify(controller.get_monitor_status())

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get current statistics"""
    return jsonify(controller.get_statistics())

@app.route('/logs', methods=['GET'])
def get_logs():
    """Get recent logs"""
    log_type = request.args.get('type', 'monitor')
    lines = int(request.args.get('lines', 50))
    
    log_file = None
    if log_type == 'monitor':
        log_file = controller.logs_dir / 'monitor.log'
    elif log_type == 'interceptor':
        log_file = controller.logs_dir / 'interceptor.log'
        
    if not log_file or not log_file.exists():
        return jsonify({
            'success': False,
            'error': 'Log file not found'
        }), 404
        
    with open(log_file, 'r') as f:
        logs = f.readlines()[-lines:]
        return jsonify({
            'success': True,
            'logs': logs
        })

if __name__ == '__main__':
    # Start the monitor in detached mode
    # controller.start_detached_monitor()
    
    # Run the API server
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=False
    )