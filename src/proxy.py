import time
import json
import queue
import psutil
import socket
import sqlite3
import logging
import asyncio
import threading
from pathlib import Path
from datetime import datetime
from mitmproxy import ctx, http
from mitmproxy.tools import dump
from mitmproxy.script import concurrent
from mitmproxy.options import Options

class ProxyInterceptor:
    def __init__(self, db_path: str = "interceptor.db"):
        self.db_path = db_path
        self.setup_database()
        self.setup_logging()
        
        # Queue for process information
        self.process_queue = queue.Queue()
        
        # Proxy configuration
        self.proxy_thread = None
        self.is_running = False
        self.master = None
        self.loop = None
        self.options = Options(
            listen_host='127.0.0.1',
            listen_port=8080,
            ssl_insecure=True  # For testing only
        )

        # Start process monitor thread
        self.process_monitor = threading.Thread(target=self._monitor_processes)
        self.process_monitor.daemon = True
        self.process_monitor.start()


    def running(self):
        """Required mitmproxy handler"""
        return self.is_running

    def done(self):
        """Required mitmproxy handler"""
        return not self.is_running


    def start(self):
        """Start the proxy server in a new thread"""
        async def _run_async():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                await self.run_proxy()
            except Exception as e:
                self.logger.error(f"Proxy error: {e}")
            finally:
                self.loop.close()

        def _run_thread():
            asyncio.run(_run_async())

        try:
            self.is_running = True
            self.proxy_thread = threading.Thread(target=_run_thread)
            self.proxy_thread.daemon = True
            self.proxy_thread.start()
            self.logger.info("Proxy server thread started")
        except Exception as e:
            self.logger.error(f"Failed to start proxy: {e}")
            self.is_running = False
            raise

    def stop(self):
        """Stop the proxy server"""
        if self.is_running:
            self.is_running = False
            if self.master:
                self.master.shutdown()
            if self.proxy_thread and self.proxy_thread.is_alive():
                self.proxy_thread.join(timeout=5)
            self.logger.info("Proxy server stopped")

    async def run_proxy(self):
        """Run the proxy server"""
        try:
            self.master = dump.DumpMaster(
                self.options,
                with_termlog=False,
                with_dumper=False
            )
            
            # Add our interceptor
            self.master.addons.add(self)
            
            # Run the proxy
            self.logger.info("Starting proxy server...")
            await self.master.run()
            
        except Exception as e:
            self.logger.error(f"Error in proxy server: {e}")
            raise
            
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger('proxy_interceptor')
        self.logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        fh = logging.FileHandler(log_dir / 'proxy_interceptor.log')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def setup_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocking_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    app_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    resolved_ips TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    active BOOLEAN DEFAULT 1
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    app_name TEXT NOT NULL,
                    process_id INTEGER,
                    target TEXT,
                    details TEXT,
                    FOREIGN KEY (rule_id) REFERENCES blocking_rules(id)
                )
            ''')
            conn.commit()

    def _monitor_processes(self):
        """Monitor processes and maintain connection info"""
        while True:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.pid and conn.status == 'ESTABLISHED':
                        try:
                            proc = psutil.Process(conn.pid)
                            self.process_queue.put({
                                'pid': conn.pid,
                                'name': proc.name(),
                                'exe': proc.exe(),
                                'cmdline': proc.cmdline(),
                                'local_addr': conn.laddr,
                                'remote_addr': conn.raddr
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
            
            time.sleep(1)  # Update every second

    def get_process_for_connection(self, client_addr):
        """Get process information for a connection"""
        try:
            # Check queue for matching process
            while not self.process_queue.empty():
                proc_info = self.process_queue.get_nowait()
                if proc_info['local_addr'] == client_addr:
                    return proc_info
            return None
        except Exception as e:
            self.logger.error(f"Error getting process info: {e}")
            return None

    def should_block_request(self, flow: http.HTTPFlow) -> bool:
        """Check if request should be blocked based on rules"""
        try:
            # Get process information
            client_addr = flow.client_conn.address
            proc_info = self.get_process_for_connection(client_addr)
            
            if not proc_info:
                return False
                
            app_name = proc_info['name']
            target_host = flow.request.pretty_host
            
            # Check rules in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id FROM blocking_rules
                    WHERE app_name = ? AND target = ? AND active = 1
                ''', (app_name, target_host))
                
                rule = cursor.fetchone()
                if rule:
                    # Log blocked attempt
                    cursor.execute('''
                        INSERT INTO blocked_attempts 
                        (rule_id, app_name, process_id, target, details)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        rule[0], app_name, proc_info['pid'], target_host,
                        f"Blocked {app_name} from accessing {target_host}"
                    ))
                    conn.commit()
                    
                    self.logger.info(
                        f"Blocked access: {app_name} -> {target_host}"
                    )
                    return True
                    
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking block rules: {e}")
            return False

    @concurrent
    def request(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP request"""
        if self.should_block_request(flow):
            flow.kill()

    def add_blocking_rule(self, app_name: str, target: str) -> bool:
        """Add new blocking rule"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO blocking_rules 
                    (app_name, target, target_type)
                    VALUES (?, ?, ?)
                ''', (app_name, target, 'domain'))
                
                self.logger.info(f"Added blocking rule: {app_name} -> {target}")
                return True
                
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            return False

    def remove_blocking_rule(self, rule_id: int) -> bool:
        """Remove blocking rule"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE blocking_rules 
                    SET active = 0 
                    WHERE id = ?
                ''', (rule_id,))
                
                if cursor.rowcount > 0:
                    self.logger.info(f"Removed blocking rule ID: {rule_id}")
                    return True
                return False
                
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            return False