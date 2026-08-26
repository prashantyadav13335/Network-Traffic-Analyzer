#!/bin/bash
set -e

echo "Checking DVWA container..."
if [ -z "$(docker ps -q --filter ancestor=vulnerables/web-dvwa)" ]; then
    if [ -z "$(docker ps -aq --filter ancestor=vulnerables/web-dvwa)" ]; then
        echo "Creating new DVWA container..."
        docker run -d -p 8080:80 vulnerables/web-dvwa
        sleep 5
    else
        echo "Starting existing DVWA container..."
        docker start $(docker ps -aq --filter ancestor=vulnerables/web-dvwa)
        sleep 2
    fi
else
    echo "DVWA container already running."
fi

TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -q --filter ancestor=vulnerables/web-dvwa))
echo "Target IP detected: $TARGET_IP"

IFACE=$(ip route get "$TARGET_IP" | awk '{print $3; exit}')
echo "Interface detected: $IFACE"

export TARGET_IP
export IFACE

echo ""
echo "Starting Flask dashboard on port 5000..."
python3 app.py