FIREWALL_DIR=$(shell pwd)

run-tracer:
	sudo rm -rf test/logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/monitor_sys.py

build-containers:
	sudo docker compose build --no-cache