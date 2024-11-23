FIREWALL_DIR=$(shell pwd)

run-tracer:
	sudo rm -rf test/logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/monitor_sys.py

build:
	sudo docker compose build --no-cache

up:
	sudo docker compose up -d

clogs:
	sudo docker logs network_monitor

down:
	sudo docker compose down