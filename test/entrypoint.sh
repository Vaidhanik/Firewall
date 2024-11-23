#!/bin/bash

# entrypoint.sh
echo "Running access checks..."
/access.sh

echo "Ensuring proper permissions..."
chmod -R 777 /app/logs

echo "Starting network monitor..."
exec python /app/monitor.py