import os
import glob
import psutil
import platform
import subprocess
from typing import List, Set

class ApplicationDetector:
    @staticmethod
    def get_process_executables() -> Set[str]:
        """Get currently running process executables"""
        executables = set()
        for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
            try:
                # Get process name
                if proc.info['name']:
                    executables.add(proc.info['name'])
                
                # Get executable path
                if proc.info['exe']:
                    executables.add(os.path.basename(proc.info['exe']))
                
                # Check cmdline for additional info
                if proc.info['cmdline']:
                    cmd = proc.info['cmdline'][0]
                    if '/' in cmd:
                        executables.add(os.path.basename(cmd))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return executables

    @staticmethod
    def get_desktop_entries() -> Set[str]:
        """Get applications from .desktop files"""
        desktop_entries = set()
        desktop_paths = [
            "/usr/share/applications",
            "/usr/local/share/applications",
            os.path.expanduser("~/.local/share/applications")
        ]
        
        for path in desktop_paths:
            if os.path.exists(path):
                for entry in glob.glob(f"{path}/*.desktop"):
                    try:
                        with open(entry, 'r', encoding='utf-8') as f:
                            content = f.read().lower()
                            # Extract name from .desktop file
                            for line in content.split('\n'):
                                if line.startswith('name='):
                                    name = line.split('=')[1].strip()
                                    desktop_entries.add(name)
                                elif line.startswith('exec='):
                                    # Get executable name from Exec line
                                    exec_cmd = line.split('=')[1].strip()
                                    # Remove parameters
                                    exec_name = exec_cmd.split()[0]
                                    # Remove path if present
                                    exec_base = os.path.basename(exec_name)
                                    # Remove quotes if present
                                    exec_base = exec_base.strip('"\'')
                                    desktop_entries.add(exec_base)
                    except Exception:
                        continue
        return desktop_entries

    @staticmethod
    def get_bin_executables() -> Set[str]:
        """Get executables from common bin directories"""
        executables = set()
        bin_paths = [
            "/usr/bin",
            "/usr/local/bin",
            "/bin",
            "/opt",
            os.path.expanduser("~/.local/bin")
        ]
        
        # Common application names to look for
        common_apps = {
            'firefox', 'chrome', 'chromium', 'brave', 'discord',
            'slack', 'teams', 'telegram', 'signal-desktop', 'spotify',
            'code', 'sublime_text', 'atom', 'skype', 'zoom'
        }
        
        for path in bin_paths:
            if os.path.exists(path):
                for item in os.listdir(path):
                    item_lower = item.lower()
                    if any(app in item_lower for app in common_apps):
                        executables.add(item)
        return executables

    @staticmethod
    def get_snap_applications() -> Set[str]:
        """Get applications installed via Snap"""
        try:
            output = subprocess.check_output(['snap', 'list'], universal_newlines=True)
            return {line.split()[0] for line in output.split('\n')[1:] if line}
        except (subprocess.SubprocessError, FileNotFoundError):
            return set()

    @staticmethod
    def get_flatpak_applications() -> Set[str]:
        """Get applications installed via Flatpak"""
        try:
            output = subprocess.check_output(['flatpak', 'list', '--app'], universal_newlines=True)
            return {line.split()[-1] for line in output.split('\n') if line}
        except (subprocess.SubprocessError, FileNotFoundError):
            return set()

def get_installed_apps() -> List[str]:
    """Get list of installed applications based on current operating system."""
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        applications_dir = '/Applications'
        return [app for app in os.listdir(applications_dir) 
                if app.endswith('.app')]
                
    elif system == "linux":
        detector = ApplicationDetector()
        apps = set()
        
        # Collect apps from all sources
        apps.update(detector.get_process_executables())
        apps.update(detector.get_desktop_entries())
        apps.update(detector.get_bin_executables())
        apps.update(detector.get_snap_applications())
        apps.update(detector.get_flatpak_applications())
        
        # Filter out system processes and common utilities
        exclude = {'bash', 'sh', 'sudo', 'grep', 'cat', 'ls', 'ps', 'sleep'}
        apps = {app for app in apps if app and app.lower() not in exclude}
        
        return sorted(list(apps))
                
    elif system == "windows":
        import winreg
        apps = []
        registry_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        
        for path in registry_paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as registry_key:
                    for i in range(winreg.QueryInfoKey(registry_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(registry_key, i)
                            with winreg.OpenKey(registry_key, subkey_name) as subkey:
                                app_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                apps.append(app_name)
                        except (OSError, KeyError):
                            continue
            except OSError:
                continue
        return apps
    
    else:
        raise OSError(f"Unsupported operating system: {system}")

if __name__ == "__main__":
    try:
        print("\nScanning for installed applications...")
        apps = get_installed_apps()
        print(f"\nFound {len(apps)} installed applications:")
        for app in apps:
            print(f"- {app}")
    except OSError as e:
        print(f"Error: {e}")