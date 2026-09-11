package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

// AgentRequest represents the payload from the AI Agent
type AgentRequest struct {
	AgentID  string                 `json:"agent_id"`
	Action   string                 `json:"action"`
	Payload  map[string]interface{} `json:"payload"`
}

// GatewayEvent represents the event pushed to Redpanda/Kafka
type GatewayEvent struct {
	AgentID   string                 `json:"agent_id"`
	Action    string                 `json:"action"`
	Payload   map[string]interface{} `json:"payload"`
	Decision  string                 `json:"decision"`
	Timestamp string                 `json:"timestamp"`
}

var kafkaProducer *kafka.Producer
var topic = "sentinel-audit-events"
var enforcer *casbin.Enforcer

func main() {
	// 1. Initialize Kafka Producer
	p, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": "localhost:9092"})
	if err != nil {
		log.Printf("Failed to create Kafka producer: %s\n", err)
		log.Println("WARNING: Gateway will run, but audit events will not be pushed to Redpanda.")
	} else {
		kafkaProducer = p
		defer p.Close()
		log.Println("✅ Connected to Redpanda (localhost:9092)")
	}

	// 1.5 Initialize Casbin Enforcer
	var casbinErr error
	enforcer, casbinErr = casbin.NewEnforcer("../casbin_policies/model.conf", "../casbin_policies/policy.csv")
	if casbinErr != nil {
		log.Fatalf("Failed to initialize Casbin Enforcer: %s", casbinErr)
	}
	log.Println("✅ Casbin RBAC Initialized")

	// 2. Set up HTTP Handlers
	http.HandleFunc("/enforce", enforceHandler)

	// 3. Start Server
	port := ":8080"
	log.Printf("🛡️  SENTINEL Go Checkpoint Gateway running on http://localhost%s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed to start: %s", err)
	}
}

func enforceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AgentRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// -------------------------------------------------------------------
	// SECURITY: Strict Input Validation
	// -------------------------------------------------------------------
	if req.AgentID == "" || len(req.AgentID) > 255 {
		http.Error(w, "Invalid or missing agent_id", http.StatusBadRequest)
		return
	}
	if req.Action == "" || len(req.Action) > 255 {
		http.Error(w, "Invalid or missing action", http.StatusBadRequest)
		return
	}
	if req.Payload == nil {
		req.Payload = make(map[string]interface{})
	}

	// -------------------------------------------------------------------
	// SECURITY: Casbin RBAC Edge Check
	// -------------------------------------------------------------------
	if enforcer != nil {
		ok, err := enforcer.Enforce(req.AgentID, req.Action, "execute")
		if err != nil {
			log.Printf("⚠️ Casbin error: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !ok {
			log.Printf("⛔ RBAC REJECTED: %s is not authorized to %s", req.AgentID, req.Action)
			
			// Respond instantly with a hard DENY without waking up Python Case Law Engine
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			response := map[string]string{"status": "DENY", "message": "Transaction denied by Edge RBAC Policy (Unauthorized)."}
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	// -------------------------------------------------------------------
	// THE CHECKPOINT LOGIC (Final 15% Integration)
	// Query the Python Case Law Engine to get the precedent-based decision.
	// -------------------------------------------------------------------
	decision := "DENY" // Fail-Safe Default

	// Prepare payload for Python engine
	engineURL := "http://localhost:8000/evaluate"
	engineReqBody, _ := json.Marshal(req)

	// Call the Python engine with a short timeout
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(engineURL, "application/json", bytes.NewBuffer(engineReqBody))
	
	if err != nil {
		log.Printf("⚠️ Case Law Engine unreachable. Falling back to Fail-Safe DENY. Error: %s", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			var engineResp struct {
				Decision string `json:"decision"`
			}
			if decodeErr := json.NewDecoder(resp.Body).Decode(&engineResp); decodeErr == nil {
				if engineResp.Decision == "ALLOW" || engineResp.Decision == "DENY" {
					decision = engineResp.Decision
				}
			}
		} else {
			log.Printf("⚠️ Case Law Engine returned non-200 status: %d", resp.StatusCode)
		}
	}

	log.Printf("Received Request - Agent: %s | Action: %s -> Decision: %s", req.AgentID, req.Action, decision)

	// 1. Respond to Agent instantly
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	responseMessage := "Transaction permitted."
	if decision == "DENY" {
		responseMessage = "Transaction denied by Case Law precedent or Fail-Safe."
	}
	response := map[string]string{"status": decision, "message": responseMessage}
	json.NewEncoder(w).Encode(response)

	// 2. Asynchronously push the event to Redpanda for the Python Worker (Immigration Office)
	if kafkaProducer != nil {
		event := GatewayEvent{
			AgentID:   req.AgentID,
			Action:    req.Action,
			Payload:   req.Payload,
			Decision:  decision,
			Timestamp: time.Now().Format(time.RFC3339),
		}
		eventBytes, _ := json.Marshal(event)

		kafkaProducer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
			Value:          eventBytes,
		}, nil)
		
		log.Printf("📤 Event pushed to Redpanda topic: %s", topic)
	}
}
