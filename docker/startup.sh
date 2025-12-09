#!/bin/bash

# If WEBMAP_TOKEN is set, use it. Otherwise generate one.
if [ -z "$WEBMAP_TOKEN" ]; then
    if [ ! -f /root/token.sha256 ]; then
        echo "Generating new token..."
        python3 /opt/nmapdashboard/nmapreport/guitoken.py
    else
        echo "Token file already exists."
    fi
else
    echo "Using WEBMAP_TOKEN from environment."
fi

bash /opt/nmapdashboard/nmapreport/nmap/runcron.sh > /dev/null 2>&1 &
python3 /opt/nmapdashboard/manage.py runserver 0:8000
