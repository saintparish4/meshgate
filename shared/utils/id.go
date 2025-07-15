package utils

import (
	"fmt"
	"time"
)

// GenerateID generates a unique ID
func GenerateID() string {
	// Simple ID generation - in production use UUID
	return fmt.Sprintf("id_%d", time.Now().UnixNano())
}
