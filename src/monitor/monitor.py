import sys
import logging
from .factory import MonitorFactory
from .exceptions import MonitorError

def main():
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

    try:
        # Create and start the appropriate monitor using factory
        monitor = MonitorFactory.create_monitor()
        if monitor:
            monitor.monitor()
    except MonitorError as e:
        logging.error(f"Monitor error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()