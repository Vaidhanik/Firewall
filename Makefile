FIREWALL_DIR=$(shell pwd)

run-tracer:
	sudo rm -rf test/logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/monitor.py

run-panel:
	sudo rm -rf test/logs
	sudo rm -rf logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/network_control.py

test-firewall:
	$(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/tester.py

build:
	sudo docker compose build --no-cache

up:
	sudo docker compose up -d

clogs:
	sudo docker logs network_monitor

down:
	sudo docker compose down