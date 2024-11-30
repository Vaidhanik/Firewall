import sys
import logging
from typing import Optional, Dict, Callable
from .base import NetworkMonitorBase
from .exceptions import UnsupportedOSError, DependencyError

class MonitorFactory:
    _registry: Dict[str, Callable[[], Optional[NetworkMonitorBase]]] = {}

    @classmethod
    def register(cls, os_type: str, creator_fn: Callable[[], Optional[NetworkMonitorBase]]):
        """Register a monitor creator function for a specific OS"""
        cls._registry[os_type] = creator_fn

    @classmethod
    def create_monitor(cls) -> Optional[NetworkMonitorBase]:
        """Create appropriate monitor based on registered creators"""
        try:
            # Determine OS type
            os_type = 'linux' if sys.platform.startswith('linux') else sys.platform

            # Get creator function from registry
            creator = cls._registry.get(os_type)
            if creator:
                return creator()
            else:
                raise UnsupportedOSError(f"Unsupported operating system: {sys.platform}")

        except Exception as e:
            if isinstance(e, ImportError):
                raise DependencyError(f"Missing required dependencies: {str(e)}")
            raise

def create_linux_monitor() -> Optional[NetworkMonitorBase]:
    try:
        from monitor.linux import LinuxNetworkMonitor
        return LinuxNetworkMonitor()
    except ImportError as e:
        logging.error(f"Error loading Linux monitor: {e}")
        logging.error("Please install required packages: pip install netifaces")
        raise

def create_windows_monitor() -> Optional[NetworkMonitorBase]:
    try:
        from monitor.windows import WindowsNetworkMonitor
        return WindowsNetworkMonitor()
    except ImportError as e:
        logging.error(f"Error loading Windows monitor: {e}")
        raise

# Register monitors
MonitorFactory.register('linux', create_linux_monitor)
MonitorFactory.register('win32', create_windows_monitor)