import os

# for mac
def list_installed_apps():
    apps = []
    applications_dir = '/Applications'
    
    # Iterate through the directory to find all applications
    for app in os.listdir(applications_dir):
        if app.endswith('.app'):  # Check if it's an application bundle
            apps.append(app)
    
    return apps

installed_apps = list_installed_apps()
for app in installed_apps:
    print(app)

#for linux
import glob

def list_installed_apps():
    apps = []
    application_paths = glob.glob("/usr/share/applications/*.desktop")
    for path in application_paths:
        app_name = os.path.basename(path).replace('.desktop', '')
        apps.append(app_name)
    return apps

installed_apps = list_installed_apps()
for app in installed_apps:
    print(app)

# for windows
import winreg

def list_installed_apps():
    apps = []
    registry_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    
    for path in registry_paths:
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            for i in range(0, winreg.QueryInfoKey(registry_key)[0]):
                subkey_name = winreg.EnumKey(registry_key, i)
                subkey = winreg.OpenKey(registry_key, subkey_name)
                try:
                    app_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    apps.append(app_name)
                except FileNotFoundError:
                    pass  # Skip if "DisplayName" key is not found
                finally:
                    winreg.CloseKey(subkey)
            winreg.CloseKey(registry_key)
        except FileNotFoundError:
            pass  # If registry path is not found
    
    return apps

installed_apps = list_installed_apps()
for app in installed_apps:
    print(app)
