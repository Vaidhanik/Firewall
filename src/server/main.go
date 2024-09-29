package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type FirewallRule struct {
	AppName          string   `json:"app_name"`
	AllowedDomains   []string `json:"allowed_domains"`
	AllowedIPs       []string `json:"allowed_ips"`
	AllowedProtocols []string `json:"allowed_protocols"`
}

type CentralServer struct {
	Rules map[string]FirewallRule
}

func NewCentralServer() *CentralServer {
	return &CentralServer{
		Rules: make(map[string]FirewallRule),
	}
}

func (s *CentralServer) HandleGetRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	appName := vars["app_name"]

	rule, ok := s.Rules[appName]
	if !ok {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(rule)
}

func (s *CentralServer) HandleSetRule(w http.ResponseWriter, r *http.Request) {
	var rule FirewallRule
	err := json.NewDecoder(r.Body).Decode(&rule)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.Rules[rule.AppName] = rule
	w.WriteHeader(http.StatusCreated)
}

func (s *CentralServer) HandleReceiveLogs(w http.ResponseWriter, r *http.Request) {
	// Implement log receiving logic
}

func main() {
	server := NewCentralServer()
	router := mux.NewRouter()

	router.HandleFunc("/rule/{app_name}", server.HandleGetRule).Methods("GET")
	router.HandleFunc("/rule", server.HandleSetRule).Methods("POST")
	router.HandleFunc("/logs", server.HandleReceiveLogs).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
