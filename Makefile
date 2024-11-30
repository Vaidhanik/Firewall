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

# Store matches in a temporary file
MATCHES_FILE := .matches.tmp

search-app:
	$(call check_var,$(SEARCH_TERM),SEARCH_TERM,search-app)
	@echo "$(YELLOW)Searching for applications matching '$(SEARCH_TERM)'...$(NC)"
	@curl -s -X POST $(API_URL)/block \
		-H "Content-Type: application/json" \
		-d '{"search":"$(SEARCH_TERM)"}' | tee $(TEMP_FILE) | jq '.'
	@echo "\n$(GREEN)To block an app, use:$(NC)"
	@echo "make block-app APP_NUMBER=<number> TARGET=<domain/ip>"

block-app:
	$(call check_var,$(APP_NUMBER),APP_NUMBER,block-app)
	$(call check_var,$(TARGET),TARGET,block-app)
	@if [ ! -f $(TEMP_FILE) ]; then \
		echo "$(RED)Error: Please run 'make search-app SEARCH_TERM=<name>' first$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Blocking application from accessing $(TARGET)...$(NC)"
	@curl -s -X POST $(API_URL)/block \
		-H "Content-Type: application/json" \
		-d "{\"selection\":$(APP_NUMBER),\"target\":\"$(TARGET)\",\"matches\":$$(cat $(TEMP_FILE) | jq '.matches')}" | \
		jq '.'

run-tracer:
	sudo rm -rf test/logs
	sudo $(FIREWALL_DIR)/test/.firewall/bin/python3 ./test/monitor.py

run-panel:
	sudo rm -rf test/logs
	sudo rm -rf logs
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

# SERVER
server-health:
	curl http://localhost:5000/health

server-apps:
	curl http://localhost:5000/apps

server-rules:
	curl http://localhost:5000/rules


# server-search-app:
# 	$(call check_vars,$(APP),APP,search-app)
# 	@echo "$(YELLOW)Searching for applications matching '$(APP)'...$(NC)"
# 	@curl -s "$(API_URL)/search?q=$(APP)" | jq '.' || echo "Failed to parse JSON response"
# 	@echo ""

# server-block:
# 	$(call check_vars,$(APP),APP,block)
# 	$(call check_vars,$(TARGET),TARGET,block)
# 	@echo "$(YELLOW)Attempting to block $(APP) from accessing $(TARGET)...$(NC)"
# 	@curl -s -X POST $(API_URL)/block \
# 		-H "Content-Type: application/json" \
# 		-d '{"app":"$(APP)","target":"$(TARGET)"}' | \
# 		jq '.' || echo "Failed to parse JSON response"
# 	@echo ""

# confirm-block:
# 	$(call check_vars,$(APP),APP,confirm-block)
# 	$(call check_vars,$(TARGET),TARGET,confirm-block)
# 	@echo "$(YELLOW)Blocking exact application '$(APP)' from accessing '$(TARGET)'...$(NC)"
# 	@curl -s -X POST $(API_URL)/block \
# 		-H "Content-Type: application/json" \
# 		-d '{"app":"$(APP)","target":"$(TARGET)"}' | \
# 		jq '.' || echo "Failed to parse JSON response"
# 	@echo ""

# test-block:
# 	@echo "$(YELLOW)Running block endpoint tests...$(NC)"
	
# 	@echo "\n1. Testing with missing app name..."
# 	@curl -s -X POST $(API_URL)/block \
# 		-H "Content-Type: application/json" \
# 		-d '{"target":"x.com"}' | jq '.'
	
# 	@echo "\n2. Testing with missing target..."
# 	@curl -s -X POST $(API_URL)/block \
# 		-H "Content-Type: application/json" \
# 		-d '{"app":"firefox"}' | jq '.'
	
# 	@echo "\n3. Testing with partial app name..."
# 	@curl -s -X POST $(API_URL)/block \
# 		-H "Content-Type: application/json" \
# 		-d '{"app":"fire","target":"x.com"}' | jq '.'
	
# 	@echo "\n4. Testing with non-existent app..."
# 	@curl -s -X POST $(API_URL)/block \
# 		-H "Content-Type: application/json" \
# 		-d '{"app":"nonexistentapp","target":"x.com"}' | jq '.'
	
# 	@echo "\n$(GREEN)Tests completed$(NC)"

#====================================================================================#

# Firewall

fw-linux-d:
	sudo iptables -L OUTPUT -n
	sudo ip6tables -L OUTPUT -n

fw-linux-rm:
	sudo iptables -F
	sudo iptables -X

#====================================================================================#

# Cleanup

cleanup:
	sudo rm -rf $(FIREWALL_DIR)/src/logs
	sudo rm -rf $(FIREWALL_DIR)/logs