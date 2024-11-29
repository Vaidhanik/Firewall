import os
import logging
import traceback
import subprocess
from flask import Flask, request, jsonify
from network_control import NetworkController

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/app/logs/app.log')
    ]
)
logger = logging.getLogger(__name__)
# Ensure log directory exists with proper permissions
os.makedirs('/app/logs', exist_ok=True)
os.chmod('/app/logs', 0o777)

app = Flask(__name__)
controller = NetworkController()

def verify_container_permissions():
    """Verify container has necessary permissions"""
    try:
        # Test iptables access
        subprocess.run(['sudo', 'iptables', '-L'], check=True, capture_output=True)
        # Test ip6tables access
        subprocess.run(['sudo', 'ip6tables', '-L'], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Permission verification failed: {e.stderr.decode()}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during permission verification: {str(e)}")
        return False

def initialize_firewall():
    """Initialize firewall rules and verify permissions before first request"""
    try:
        # Verify container permissions
        if not verify_container_permissions():
            logger.error("Container lacks necessary permissions!")
            return

        # Initialize iptables chains
        subprocess.run(['sudo', 'iptables', '-N', 'FIREWALL_CUSTOM'], 
                      check=False)  # Ignore if exists
        subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-j', 'FIREWALL_CUSTOM'], 
                      check=False)

        subprocess.run(['sudo', 'ip6tables', '-N', 'FIREWALL_CUSTOM'], 
                      check=False)
        subprocess.run(['sudo', 'ip6tables', '-A', 'OUTPUT', '-j', 'FIREWALL_CUSTOM'], 
                      check=False)

        logger.info("Firewall initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize firewall: {str(e)}")
        raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        container_healthy = verify_container_permissions()
        monitor_status = controller.get_monitor_status()
        
        return jsonify({
            'status': 'healthy' if container_healthy else 'degraded',
            'monitor_active': monitor_status['running'],
            'container_permissions': container_healthy,
            'iptables_accessible': container_healthy
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/apps', methods=['GET'])
def list_apps():
    """List installed applications"""
    try:
        return jsonify({
            'success': True,
            'apps': controller.installed_apps
        })
    except Exception as e:
        logger.error(f"Failed to list apps: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Failed to list applications: {str(e)}"
        }), 500

@app.route('/search', methods=['GET'])
def search_apps():
    """Search applications"""
    try:
        query = request.args.get('q', '')
        matches = controller.search_installed_apps(query)
        return jsonify({
            'success': True,
            'query': query,
            'matches': matches
        })
    except Exception as e:
        logger.error(f"Search failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Search failed: {str(e)}"
        }), 500

@app.route('/block', methods=['POST'])
def block_app():
    """Block application from accessing target"""
    try:
        # Log incoming request
        logger.debug(f"Received block request: {request.get_json()}")
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
            
        app_name = data.get('app')
        target = data.get('target')
        
        if not app_name or not target:
            return jsonify({
                'success': False,
                'error': 'Missing app name or target'
            }), 400

        # Validate app existence first
        if app_name not in controller.installed_apps:
            matches = controller.search_installed_apps(app_name)
            error_msg = f"Application '{app_name}' not found"
            if matches:
                error_msg += f". Did you mean one of these? {', '.join(matches[:5])}"
            return jsonify({
                'success': False,
                'error': error_msg,
                'suggested_apps': matches[:5] if matches else []
            }), 400

        # Try to block the app
        success = controller.block_app_network(app_name, target)
        
        if not success:
            logger.error(f"Failed to block {app_name} from accessing {target}")
            return jsonify({
                'success': False,
                'error': f"Failed to block {app_name} from accessing {target}",
                'app': app_name,
                'target': target
            }), 400

        logger.info(f"Successfully blocked {app_name} from accessing {target}")
        return jsonify({
            'success': True,
            'app': app_name,
            'target': target
        })
        
    except Exception as e:
        error_msg = f"Unexpected error in block endpoint: {str(e)}"
        logger.error(f"{error_msg}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500

@app.route('/unblock', methods=['POST'])
def unblock_app():
    """Remove blocking rule"""
    try:
        data = request.get_json()
        rule_id = data.get('rule_id')
        
        if not rule_id:
            return jsonify({
                'success': False,
                'error': 'Missing rule_id'
            }), 400
            
        success = controller.unblock_app_network(rule_id)
        
        if not success:
            logger.error(f"Failed to unblock rule {rule_id}")
            return jsonify({
                'success': False,
                'error': f"Failed to unblock rule {rule_id}",
                'rule_id': rule_id
            }), 400

        logger.info(f"Successfully unblocked rule {rule_id}")
        return jsonify({
            'success': True,
            'rule_id': rule_id
        })
    except Exception as e:
        error_msg = f"Failed to unblock rule: {str(e)}"
        logger.error(f"{error_msg}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500
    
@app.route('/rules', methods=['GET'])
def get_rules():
    """Get active blocking rules"""
    try:
        rules = controller.get_active_blocks()
        return jsonify({
            'success': True,
            'rules': rules
        })
    except Exception as e:
        logger.error(f"Failed to get rules: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Failed to get active blocks: {str(e)}"
        }), 500

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
    try:
        success = controller.stop_monitor()
        return jsonify({
            'success': success
        })
    except Exception as e:
        logger.error(f"Failed to stop monitor: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Failed to stop monitor: {str(e)}"
        }), 500

@app.route('/monitor/status', methods=['GET'])
def monitor_status():
    """Get monitoring status"""
    try:
        status = controller.get_monitor_status()
        return jsonify({
            'success': True,
            **status
        })
    except Exception as e:
        logger.error(f"Failed to get monitor status: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Failed to get monitor status: {str(e)}"
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get current statistics"""
    try:
        stats = controller.get_statistics()
        return jsonify({
            'success': True,
            **stats
        })
    except Exception as e:
        logger.error(f"Failed to get statistics: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Failed to get statistics: {str(e)}"
        }), 500

@app.route('/logs', methods=['GET'])
def get_logs():
    """Get recent logs"""
    try:
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
    except Exception as e:
        logger.error(f"Failed to get logs: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': f"Failed to get logs: {str(e)}"
        }), 500

def main():
    try:
        # Initialize and start monitor
        logger.info("Starting network monitor...")
        if controller.start_detached_monitor():
            logger.info("Network monitor started successfully")
        else:
            logger.warning("Failed to start network monitor")

        # Initialize firewall
        initialize_firewall()
        
        # Run the API server
        logger.info("Starting API server...")
        
        # Run the API server
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=False
        )
    except Exception as e:
        logger.critical(f"Failed to start server: {str(e)}\n{traceback.format_exc()}")
        raise

if __name__ == '__main__':
    main()