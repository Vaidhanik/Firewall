import os
import logging
import traceback
import subprocess
from flask import Flask, request, jsonify
from network_controller import NetworkController

from pymongo import MongoClient
from datetime import datetime, timedelta
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError, ConnectionFailure

os.makedirs('src/vaidhanik', exist_ok=True)

MONITOR_MONGO_HOST = os.environ.get('MONITOR_MONGO_HOST', 'localhost')
MONITOR_MONGO_PORT = int(os.environ.get('MONITOR_MONGO_PORT', '27020'))
MONITOR_MONGO_USERNAME = os.environ.get('MONITOR_MONGO_ROOT_USERNAME', 'mongouser')
MONITOR_MONGO_PASSWORD = os.environ.get('MONITOR_MONGO_ROOT_PASSWORD', 'mongopass')

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('src/vaidhanik/vaidhanik.log')
    ]
)
logger = logging.getLogger(__name__)

# Ensure log directory exists with proper permissions
# os.makedirs('/app_logs', exist_ok=True)
# os.chmod('/app_logs', 0o777)

app = Flask(__name__)
controller = NetworkController()

def parse_duration(duration_str: str) -> timedelta:
    """Convert duration string to timedelta"""
    duration_map = {
        'min': {'multiplier': 1, 'unit': 'minutes'},
        'mins': {'multiplier': 1, 'unit': 'minutes'},
        'hour': {'multiplier': 1, 'unit': 'hours'},
        'hr': {'multiplier': 1, 'unit': 'hours'},
        'hrs': {'multiplier': 1, 'unit': 'hours'},
        'day': {'multiplier': 1, 'unit': 'days'},
        'days': {'multiplier': 1, 'unit': 'days'},
        'week': {'multiplier': 7, 'unit': 'days'},
        'weeks': {'multiplier': 7, 'unit': 'days'}
    }
    
    try:
        # Extract number and unit
        import re
        match = re.match(r'(\d+)\s*(\w+)', duration_str.lower())
        if not match:
            raise ValueError("Invalid duration format")
            
        value, unit = match.groups()
        value = int(value)
        
        if unit not in duration_map:
            raise ValueError(f"Unsupported time unit: {unit}")
            
        unit_info = duration_map[unit]
        return timedelta(**{unit_info['unit']: value * unit_info['multiplier']})
        
    except (ValueError, AttributeError) as e:
        raise ValueError(f"Invalid duration format: {str(e)}")

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
    """
    Block application from accessing target. The endpoint handles two steps:
    1. Search step: Search for applications matching a keyword
    2. Block step: Block selected application from accessing target
    
    Request format for search:
    {
        "search": "firefox"  # Search term
    }
    
    Response format for search:
    {
        "success": true,
        "matches": [
            {
                "number": 1,
                "name": "firefox"
            }
        ]
    }
    
    Request format for block:
    {
        "selection": 1,        # Selected application number from search results
        "target": "x.com",     # Target domain/IP to block
        "matches": [           # Original matches array from search step
            {
                "number": 1,
                "name": "firefox"
            }
        ]
    }
    """
    try:
        # Log incoming request
        logger.debug(f"Received block request: {request.get_json()}")
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
            
        # Step 1: Handle search request
        if 'search' in data:
            search_term = data.get('search')
            if not search_term:
                return jsonify({
                    'success': False,
                    'error': 'No search term provided'
                }), 400
                
            # Use existing search_installed_apps method
            matches = controller.search_installed_apps(search_term)
            
            if not matches:
                return jsonify({
                    'success': False,
                    'error': f"No applications found matching '{search_term}'",
                    'matches': []
                }), 404
            
            # Format matches with numbers
            numbered_matches = [
                {
                    'number': i + 1,
                    'name': app
                }
                for i, app in enumerate(matches)
            ]
            
            return jsonify({
                'success': True,
                'matches': numbered_matches
            })
            
        # Step 2: Handle block request
        app_number = data.get('selection')  # User's selection number
        target = data.get('target')         # Target to block
        matches = data.get('matches', [])   # List of matches from previous search
        
        if not all([app_number, target, matches]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: selection, target, and matches'
            }), 400
        
        try:
            app_number = int(app_number)
            if app_number < 1 or app_number > len(matches):
                return jsonify({
                    'success': False,
                    'error': f'Invalid selection. Please choose between 1 and {len(matches)}'
                }), 400
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Selection must be a valid number'
            }), 400
        
        # Get selected app name
        selected_app = matches[app_number - 1]['name']
            
        # Log domain resolution attempt
        logger.info(f"Resolving domain {target}...")
        
        # Try to block the app using the controller's block_app_network method
        success = controller.block_app_network(selected_app, target)
        
        if not success:
            logger.error(f"Failed to block {selected_app} from accessing {target}")
            return jsonify({
                'success': False,
                'error': f"Failed to block {selected_app} from accessing {target}",
                'app': selected_app,
                'target': target
            }), 400

        logger.info(f"Successfully blocked {selected_app} from accessing {target}")
        return jsonify({
            'success': True,
            'app': selected_app,
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
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400

        # Step 1: List current rules
        if data.get('action') == 'list':
            rules = controller.get_active_blocks()
            if not rules:
                return jsonify({
                    'success': False,
                    'error': 'No active blocking rules found'
                }), 404
                
            return jsonify({
                'success': True,
                'rules': rules  # Already contains rule IDs from controller
            })

        # Step 2: Unblock rule
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

@app.route('/network-data', methods=['GET'])
def get_network_data():
    """
    Get network monitoring data for specified duration
    Query parameters:
    - duration: time duration (e.g., "1hr", "30mins", "1day", "1week")
    - type: data type (connections/stats/email) - optional
    """
    try:
        # 1. Validate input parameters
        duration_str = request.args.get('duration')
        data_type = request.args.get('type', 'connections')
        
        if not duration_str:
            return jsonify({
                'success': False,
                'error': 'Duration parameter is required'
            }), 400
        
        # 2. Parse duration
        try:
            duration = parse_duration(duration_str)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e),
                'valid_formats': '30mins, 1hr, 24hrs, 7days, 1week'
            }), 400
        
        # Connect to MongoDB
        try:
            client = MongoClient(
                host=MONITOR_MONGO_HOST,
                port=MONITOR_MONGO_PORT,
                username=MONITOR_MONGO_USERNAME,
                password=MONITOR_MONGO_PASSWORD,
                serverSelectionTimeoutMS=5000
            )
            db = client.network_monitor
            
            end_time = datetime.now()  # Use local time instead of UTC
            start_time = end_time - duration
            
            # Select collection based on data type
            collection_map = {
                'connections': db.connections,
                'stats': db.app_stats,
                'email': db.email_traffic
            }
            
            if data_type not in collection_map:
                return jsonify({
                    'success': False,
                    'error': f'Invalid data type. Valid types are: {", ".join(collection_map.keys())}'
                }), 400
                
            collection = collection_map[data_type]
            
            # Query data
            query = {
                'timestamp': {
                    '$gte': start_time.isoformat(),  # Convert to ISO format string
                    '$lte': end_time.isoformat()     # Convert to ISO format string
                }
            }
            
            total_count = collection.count_documents(query)
            
            # 8. Check if any data exists
            if total_count == 0:
                return jsonify({
                    'success': False,
                    'error': f'No {data_type} data found for the specified duration',
                    'duration': duration_str,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'count': 0
                }), 404

            # Execute query and convert to list
            data = list(collection.find(query, {'_id': 0}))
            
            # Check if data exists
            if not data:
                return jsonify({
                    'success': False,
                    'error': f'No {data_type} data found for the specified duration',
                    'duration': duration_str,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                }), 404
                
            return jsonify({
                'success': True,
                'summary': {
                    'data_type': data_type,
                    'duration': duration_str,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'total_entries': total_count
                },
                'data': data
            })
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            return jsonify({
                'success': False,
                'error': 'Failed to connect to MongoDB',
                'details': str(e)
            }), 503
            
        except Exception as e:
            logger.error(f"Database error: {str(e)}\n{traceback.format_exc()}")
            return jsonify({
                'success': False,
                'error': 'Database error occurred',
                'details': str(e)
            }), 500
            
        finally:
            if 'client' in locals():
                client.close()
                
    except Exception as e:
        logger.error(f"Unexpected error in network-data endpoint: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': 'Internal server error',
            'details': str(e)
        }), 500
    
# Add these routes to the Flask application (app.py)

@app.route('/global/block', methods=['POST'])
def block_global():
    """Block target globally across all applications"""
    try:
        data = request.get_json()
        if not data or not data.get('target'):
            return jsonify({
                'success': False,
                'error': 'Target is required'
            }), 400
            
        target = data['target']
        logger.info(f"NetworkController: Attempting to block {target} globally")
            
        # First resolve the domain
        resolved_ips = controller.interceptor.resolve_domain(target)
        logger.info(f"NetworkController: Resolved to: {', '.join(resolved_ips['ipv4'] + resolved_ips['ipv6'])}")
        
        logger.info("NetworkController: Calling interceptor.add_global_blocking_rule")
        success = controller.block_global(target)
        
        if not success:
            return jsonify({
                'success': False,
                'error': f"Failed to block {target} globally",
                'target': target
            }), 400

        return jsonify({
            'success': True,
            'message': f"Successfully blocked {target} globally",
            'target': target
        })
        
    except Exception as e:
        logger.error(f"Error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/global/rules', methods=['GET'])
def get_global_rules():
    """Get all active global rules"""
    try:
        rules = controller.get_global_blocks()
        
        if not rules:
            return jsonify({
                'success': False,
                'message': 'No active global rules found'
            }), 404

        return jsonify({
            'success': True,
            'rules': rules
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/global/unblock', methods=['POST'])
def unblock_global():
    """Remove global blocking rule"""
    try:
        data = request.get_json()
        if not data or not data.get('rule_id'):
            return jsonify({
                'success': False,
                'error': 'rule_id is required'
            }), 400
            
        rule_id = data['rule_id']
        success = controller.unblock_global(rule_id)
        
        if not success:
            return jsonify({
                'success': False,
                'error': f"Failed to remove global block {rule_id}",
                'rule_id': rule_id
            }), 400

        return jsonify({
            'success': True,
            'message': f"Successfully removed global block {rule_id}",
            'rule_id': rule_id
        })
        
    except Exception as e:
        logger.error(f"Error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    
@app.route('/cleanup', methods=['POST'])
def cleanup():
    """Cleanup firewall rules and save final state"""
    try:
        # Call controller's cleanup method
        controller.cleanup()
        
        return jsonify({
            'success': True,
            'message': 'Successfully cleaned up firewall rules and saved state'
        })
        
    except Exception as e:
        error_msg = f"Failed to cleanup: {str(e)}"
        logger.error(f"{error_msg}\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'error': error_msg
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