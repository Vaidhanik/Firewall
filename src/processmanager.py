import psutil
import logging
import subprocess
from pathlib import Path

class ProcessManager:
    """Manages process isolation and identification for firewall rules"""
    
    def __init__(self):
        """Initialize ProcessManager"""
        self.logger = logging.getLogger('interceptor')
        self.cgroup_base = Path("/sys/fs/cgroup")
        self.classids = {}  # Cache for process classids
        
    def _ensure_cgroup_support(self):
        """Ensure cgroup net_cls module is loaded and mounted"""
        try:
            # Check if net_cls cgroup is available
            net_cls_path = self.cgroup_base / "net_cls"
            if not net_cls_path.exists():
                # Load net_cls module
                subprocess.run(['sudo', 'modprobe', 'cls_cgroup'], check=True)
                # Create net_cls cgroup directory
                subprocess.run(['sudo', 'mkdir', '-p', str(net_cls_path)], check=True)
                # Mount cgroup v1 hierarchy if needed
                subprocess.run([
                    'sudo', 'mount', '-t', 'cgroup', '-o', 'net_cls',
                    'net_cls', str(net_cls_path)
                ], check=True)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to setup cgroup support: {e}")
            return False
            
    def setup_process_isolation(self, process_name: str) -> str:
        """Setup process isolation using cgroups and return classid"""
        try:
            # Check if we already have a classid for this process
            if process_name in self.classids:
                return self.classids[process_name]
                
            # Ensure cgroup support is available
            if not self._ensure_cgroup_support():
                return None
                
            # Create app-specific cgroup
            cgroup_path = self.cgroup_base / "net_cls" / process_name
            if not cgroup_path.exists():
                subprocess.run(['sudo', 'mkdir', '-p', str(cgroup_path)], check=True)
            
            # Generate numeric classid (1:1 to 1:65535)
            minor = abs(hash(process_name)) % 65535 + 1
            classid = (1 << 16) + minor  # Major 1, minor from hash
            
            # Write classid to cgroup
            classid_path = cgroup_path / "net_cls.classid"
            subprocess.run([
                'sudo', 'sh', '-c', 
                f'echo {classid} > {classid_path}'
            ], check=True)
            
            # Store in cache
            self.classids[process_name] = str(classid)
            return str(classid)
            
        except Exception as e:
            self.logger.error(f"Failed to setup process isolation for {process_name}: {e}")
            return None
            
    def get_process_mark(self, process_name: str) -> str:
        """Get cgroup mark for process, creating if necessary"""
        classid = self.setup_process_isolation(process_name)
        if not classid:
            return None
            
        return classid
        
    def move_process_to_cgroup(self, pid: int, process_name: str) -> bool:
        """Move a process to its cgroup"""
        try:
            # Get process cgroup path
            cgroup_path = self.cgroup_base / "net_cls" / process_name
            if not cgroup_path.exists():
                return False
                
            # Write pid to cgroup.procs
            procs_file = cgroup_path / "cgroup.procs"
            subprocess.run([
                'sudo', 'sh', '-c',
                f'echo {pid} > {procs_file}'
            ], check=True)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to move process {pid} to cgroup: {e}")
            return False
            
    def list_processes_in_cgroup(self, process_name: str) -> list:
        """List all PIDs in a process cgroup"""
        try:
            cgroup_path = self.cgroup_base / "net_cls" / process_name
            if not cgroup_path.exists():
                return []
                
            procs_file = cgroup_path / "cgroup.procs"
            with open(procs_file, 'r') as f:
                return [int(line.strip()) for line in f.readlines()]
                
        except Exception as e:
            self.logger.error(f"Failed to list processes in cgroup {process_name}: {e}")
            return []
            
    def cleanup_process_cgroup(self, process_name: str) -> bool:
        """Clean up process cgroup when no longer needed"""
        try:
            cgroup_path = self.cgroup_base / "net_cls" / process_name
            if cgroup_path.exists():
                # Remove all processes first
                for pid in self.list_processes_in_cgroup(process_name):
                    try:
                        self.move_process_to_cgroup(pid, "")  # Move to root cgroup
                    except:
                        pass
                        
                # Remove cgroup directory
                subprocess.run(['sudo', 'rmdir', str(cgroup_path)], check=True)
                
            # Remove from cache
            self.classids.pop(process_name, None)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup cgroup for {process_name}: {e}")
            return False
            
    def ensure_process_tracking(self, process_name: str, pid: int = None) -> bool:
        """Ensure process is tracked in its cgroup"""
        try:
            # Setup cgroup if needed
            if not self.setup_process_isolation(process_name):
                return False
                
            # If no PID provided, try to find it
            if pid is None:
                for proc in psutil.process_iter(['name', 'pid']):
                    if proc.info['name'] == process_name:
                        pid = proc.info['pid']
                        break
                        
            if pid:
                return self.move_process_to_cgroup(pid, process_name)
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to ensure process tracking: {e}")
            return False