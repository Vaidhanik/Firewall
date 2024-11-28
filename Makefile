FIREWALL_DIR=$(shell pwd)

run-tracer:
	sudo rm -rf test/logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/monitor.py

run-panel:
	sudo rm -rf test/logs
	sudo rm -rf logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./src/network_control.py

test-firewall:
	$(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/tester.py

build:
	sudo docker compose build --no-cache

upd:
	sudo docker compose up -d

up:
	sudo docker compose up

clogs:
	sudo docker logs network_monitor

down:
	sudo docker compose down

# SERVER
server-health:
	curl http://localhost:5000/health

server-apps:
	curl http://localhost:5000/apps

server-rules:
	curl http://localhost:5000/rules

# server-block:
# 	curl -X POST http://localhost:5000/block \
#   -H "Content-Type: application/json" \
#   -d '{"app":"firefox","target":"x.com"}'

server-block:
	@echo "Sending block request..."
	@curl -X POST \
		-H "Content-Type: application/json" \
		-d '{"app":"firefox","target":"x.com"}' \
		http://localhost:5000/block | jq '.'

verify-block:
	@echo "Verifying block..."
	@curl -s http://localhost:5000/rules | jq '.'
	@echo "\nTesting connection to x.com..."
	@firefox --headless https://x.com || echo "Connection blocked (expected)"

block-and-verify: server-block verify-block

#====================================================================================#

# Firewall

fw-linux-d:
	sudo iptables -L OUTPUT -n
	sudo ip6tables -L OUTPUT -n

fw-linux-rm:
	sudo iptables -F OUTPUT
	sudo ip6tables -F OUTPUT