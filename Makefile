FIREWALL_DIR=$(shell pwd)
API_URL ?= http://localhost:5000

# Default values
SEARCH ?= 
TARGET ?= 
APP_NUMBER ?= 

# Colors for output
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[0;33m
NC := \033[0m # No Color

.PHONY: Firewall controller

help:
	@echo "Available commands:"
	@echo "  make block APP=firefox TARGET=x.com    - Block an application from accessing a target"
	@echo "  make search-app APP=fire               - Search for applications matching a pattern"
	@echo "  make confirm-block APP=firefox TARGET=x.com - Directly block with exact app name"
	@echo "  make test-block                        - Run test cases for block endpoint"

check_vars = @if [ -z "$(1)" ]; then \
    echo "$(RED)Error: $(2) is not set$(NC)"; \
    echo "Usage: make $(3) $(2)=value"; \
    exit 1; \
fi

#================================================================#
#=============================SERVER=============================#
#================================================================#

TEMP_FILE := .search_results.tmp

start:
	rm -rf src/vaidhanik
	mkdir -p src/vaidhanik
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./src/server.py

stop:
	@echo "$(YELLOW)Stopping server...$(NC)"
	@sudo pkill -f "python3 ./src/server.py" || true
	@echo "$(GREEN)Server stopped$(NC)"

cleanup-rules:
	@echo "$(YELLOW)Cleaning up firewall rules and saving state...$(NC)"
	@curl -s -X POST $(API_URL)/cleanup | jq '.'
	@make stop

# Two-step blocking process
search-app:
	$(call check_vars,$(SEARCH_TERM),SEARCH_TERM,search-app)
	@echo "$(YELLOW)Searching for applications matching '$(SEARCH_TERM)'...$(NC)"
	@curl -s -X POST $(API_URL)/block \
		-H "Content-Type: application/json" \
		-d '{"search":"$(SEARCH_TERM)"}' | tee $(TEMP_FILE) | jq '.'
	@if [ $$? -eq 0 ] && [ -f $(TEMP_FILE) ]; then \
		echo "\n$(GREEN)To block an app, use:$(NC)"; \
		echo "make block-app APP_NUMBER=<number> TARGET=<domain/ip>"; \
	fi

block-app:
	$(call check_vars,$(APP_NUMBER),APP_NUMBER,block-app)
	$(call check_vars,$(TARGET),TARGET,block-app)
	@if [ ! -f $(TEMP_FILE) ]; then \
		echo "$(RED)Error: Please run 'make search-app SEARCH_TERM=<name>' first$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Blocking application from accessing $(TARGET)...$(NC)"
	@curl -s -X POST $(API_URL)/block \
		-H "Content-Type: application/json" \
		-d "{\"selection\":$(APP_NUMBER),\"target\":\"$(TARGET)\",\"matches\":$$(cat $(TEMP_FILE) | jq '.matches')}" | \
		jq '.'

# Example usage targets
example-block:
	@echo "$(YELLOW)Example: Blocking Firefox from accessing x.com$(NC)"
	@echo "\n1. First, search for Firefox:"
	@make search-app SEARCH_TERM=firefox
	@echo "\n2. Then block it (assuming Firefox is match #1):"
	@make block-app APP_NUMBER=1 TARGET=x.com

list-rules:
	@echo "$(YELLOW)Getting current blocking rules...$(NC)"
	@curl -s -X POST $(API_URL)/unblock \
		-H "Content-Type: application/json" \
		-d '{"action":"list"}' | jq '.'

unblock-rule:
	$(call check_vars,$(RULE_ID),RULE_ID,unblock-rule)
	@echo "$(YELLOW)Unblocking rule $(RULE_ID)...$(NC)"
	@curl -s -X POST $(API_URL)/unblock \
		-H "Content-Type: application/json" \
		-d '{"rule_id":$(RULE_ID)}' | jq '.'

server-health:
	curl http://localhost:5000/health

server-apps:
	curl http://localhost:5000/apps

server-rules:
	curl http://localhost:5000/rules

clean:
	@rm -f $(TEMP_FILE)
	@echo "$(GREEN)Cleaned up temporary files$(NC)"

#================================================================#
#=======================NETWORK_CONTROLLER=======================#
#================================================================#

run-tracer:
# sudo rm -rf src/network_controller/logs
	sudo rm -rf src/monitor/logs
# sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./src/network_controller/monitor.py
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./src/run_tracer.py

run-panel:
	sudo rm -rf logs
	sudo rm -rf src/network_controller/logs
	make upd
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./src/run_controller.py

test-firewall:
	$(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/tester.py $(URLS)

build:
	sudo docker compose build --no-cache

buildwc:
	sudo docker compose build

upd:
	sudo docker compose up -d

up:
	sudo docker compose up

clogs:
	sudo docker logs network_monitor

down:
	sudo docker compose down

#================================================================#
#============================Firewall============================#
#================================================================#

fw-linux-d:
	sudo iptables -L OUTPUT -n
	sudo ip6tables -L OUTPUT -n

fw-linux-rm:
	sudo iptables -F
	sudo iptables -X

fw-win-d:
	netsh advfirewall firewall show rule name=APP_* verbose

fw-win-rm:
	netsh advfirewall firewall delete rule name=APP_*

#=================================================================#
#=============================Cleanup=============================#
#=================================================================#

cleanup:
	sudo rm -rf $(FIREWALL_DIR)/logs
	sudo rm -rf $(FIREWALL_DIR)/src/monitor/logs