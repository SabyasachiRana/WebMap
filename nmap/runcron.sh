#!/bin/bash

while true; do
	python3 /opt/nmapdashboard/nmapreport/nmap/cron.py &&
	echo "[SLEEP] for a while..."
	sleep 10
done
