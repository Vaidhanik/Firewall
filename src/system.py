import os
import platform
import glob
from typing import List

def get_installed_apps() -> List[str]:
    """Get list of installed applications based on current operating system."""
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        applications_dir = '/Applications'
        return [app for app in os.listdir(applications_dir) 
                if app.endswith('.app')]
                
    elif system == "linux":
        application_paths = glob.glob("/usr/share/applications/*.desktop")
        return [os.path.basename(path).replace('.desktop', '')
                for path in application_paths]
                
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
        apps = get_installed_apps()
        print(f"\nFound {len(apps)} installed applications:")
        for app in sorted(apps):
            print(app)
    except OSError as e:
        print(f"Error: {e}")