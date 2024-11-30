class MonitorError(Exception):
    """Base exception for network monitor errors"""
    pass

class UnsupportedOSError(MonitorError):
    """Raised when the OS is not supported"""
    pass

class DependencyError(MonitorError):
    """Raised when required dependencies are missing"""
    pass