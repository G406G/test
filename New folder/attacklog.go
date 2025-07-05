package attacklogs

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Attack struct {
	Method    string    `json:"method"`
	Target    string    `json:"target"`
	Port      int       `json:"port,omitempty"`
	Duration  int       `json:"duration"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	logFile = "attacks.json"
	mu      sync.Mutex
)

func LogAttack(a Attack) error {
	mu.Lock()
	defer mu.Unlock()

	attacks, err := loadAttacks()
	if err != nil {
		attacks = []Attack{}
	}

	attacks = append(attacks, a)

	data, err := json.MarshalIndent(attacks, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(logFile, data, 0644)
}

func loadAttacks() ([]Attack, error) {
	data, err := os.ReadFile(logFile)
	if err != nil {
		return nil, err
	}

	var attacks []Attack
	err = json.Unmarshal(data, &attacks)
	return attacks, err
}
