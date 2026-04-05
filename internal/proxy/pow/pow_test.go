package pow

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestPoW_Validation(t *testing.T) {
	s := NewSystem(2, "test-secret")
	ip := "127.0.0.1"
	challenge := s.GenerateChallenge(ip)
	
	// Parse seed from challenge: ip:timestamp:seed:salt:signature
	parts := strings.Split(challenge, ":")
	seed, _ := strconv.Atoi(parts[2])
	ghostProof := (seed * (seed - 1)) / 2
	
	// Mock environment
	envStr := `{"wd":false,"hc":8,"dm":"1920x1080","tz":"UTC","mem":8}`
	envBase64 := base64.StdEncoding.EncodeToString([]byte(envStr))

	// Test solving the challenge
	var solution int
	for {
		data := fmt.Sprintf("%s%s%d%d", challenge, envStr, ghostProof, solution)
		h := sha256.Sum256([]byte(data))
		hHex := fmt.Sprintf("%x", h)
		if strings.HasPrefix(hHex, "00") {
			break
		}
		solution++
		if solution > 100000 {
			t.Fatal("Could not find a solution for difficulty 2 in 100k attempts")
		}
	}
	
	// Format: challenge|nonce|envBase64
	solutionStr := fmt.Sprintf("%s|%d|%s", challenge, solution, envBase64)
	
	if !s.ValidateSolution(ip, challenge, solutionStr) {
		t.Errorf("Validation failed for a correct solution. Nonce: %d", solution)
	}
	
	// Test bot detection (webdriver: true)
	botEnv := `{"wd":true,"hc":8}`
	botEnvBase64 := base64.StdEncoding.EncodeToString([]byte(botEnv))
	botSolutionStr := fmt.Sprintf("%s|%d|%s", challenge, solution, botEnvBase64)
	if s.ValidateSolution(ip, challenge, botSolutionStr) {
		t.Error("Validation should fail for bot environment (webdriver:true)")
	}
}
