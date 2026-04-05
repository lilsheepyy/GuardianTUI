package pow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config holds the configuration for the PoW system
type Config struct {
	Difficulty int
	Secret     []byte
	Timeout    time.Duration
}

// System manages the PoW challenges and verification
type System struct {
	config Config
	cache  sync.Map // To prevent replay attacks: challenge -> timestamp
}

// NewSystem initializes a new PoW manager
func NewSystem(difficulty int, secret string) *System {
	if secret == "" {
		secret = generateRandomString(32)
	}
	return &System{
		config: Config{
			Difficulty: difficulty,
			Secret:     []byte(secret),
			Timeout:    5 * time.Minute,
		},
	}
}

// GenerateChallenge creates a new cryptographically signed challenge for a client.
// Now includes a random seed for dynamic WASM verification.
func (s *System) GenerateChallenge(ip string) string {
	timestamp := time.Now().Unix()
	salt := generateRandomString(8)
	seed := rand.Intn(10000) + 1000
	
	// Format: ip:timestamp:seed:salt
	base := fmt.Sprintf("%s:%d:%d:%s", ip, timestamp, seed, salt)
	
	// Sign it
	mac := hmac.New(sha256.New, s.config.Secret)
	mac.Write([]byte(base))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	
	return fmt.Sprintf("%s:%s", base, signature)
}

// ValidateSolution checks if the provided solution meets the difficulty and integrity requirements.
func (s *System) ValidateSolution(ip, challenge, solutionStr string) bool {
	// 1. Format check: nonce|envBase64
	// (Note: proxy.go passes parts[1] which contains "nonce|envBase64")
	parts := strings.Split(solutionStr, "|")
	if len(parts) != 2 {
		return false
	}
	nonceStr, envBase64 := parts[0], parts[1]

	// 2. Signature & Integrity Verification
	cParts := strings.Split(challenge, ":")
	if len(cParts) != 5 {
		return false
	}
	
	reqIP, timestampStr, _, _, signature := cParts[0], cParts[1], cParts[2], cParts[3], cParts[4]
	
	if reqIP != ip { return false }
	
	// Re-verify signature
	base := strings.Join(cParts[:4], ":")
	mac := hmac.New(sha256.New, s.config.Secret)
	mac.Write([]byte(base))
	if signature != base64.URLEncoding.EncodeToString(mac.Sum(nil)) {
		return false
	}

	// 3. Expiration
	ts, _ := strconv.ParseInt(timestampStr, 10, 64)
	if time.Since(time.Unix(ts, 0)) > s.config.Timeout { return false }

	// 4. Environment Integrity
	envData, err := base64.StdEncoding.DecodeString(envBase64)
	if err != nil { return false }
	if strings.Contains(string(envData), "\"wd\":true") {
		return false // Bot detected via webdriver:true
	}

	// 5. Verify the Work
	// The WASM uses FNV-1a algorithm:
	// hash = 2166136261
	// for char in combinedStr: hash = (hash ^ char) * 16777619
	// finalHash = (hash ^ nonce) * 16777619
	// target: finalHash < (1 << (32 - difficulty))
	
	nonce, err := strconv.ParseUint(nonceStr, 10, 32)
	if err != nil {
		return false
	}

	combinedStr := challenge + string(envData)
	
	// FNV-1a 32-bit
	var h uint32 = 2166136261
	for i := 0; i < len(combinedStr); i++ {
		h ^= uint32(combinedStr[i])
		h *= 16777619
	}
	
	// Apply nonce
	h ^= uint32(nonce)
	h *= 16777619
	
	// Check difficulty
	// For difficulty 24, h must be < 1 << (32 - 24) = 256
	if s.config.Difficulty > 0 {
		target := uint32(1) << (32 - uint32(s.config.Difficulty))
		if h >= target {
			return false
		}
	}

	// Replay protection
	if _, exists := s.cache.Load(challenge); exists { return false }
	s.cache.Store(challenge, time.Now())
	
	return true
}

// cleanupCache removes expired challenges from the replay cache
func (s *System) cleanupCache() {
	now := time.Now()
	s.cache.Range(func(key, value interface{}) bool {
		timestamp, ok := value.(time.Time)
		if ok && now.Sub(timestamp) > s.config.Timeout {
			s.cache.Delete(key)
		}
		return true
	})
}

// GhostWASM is the new WASM binary from the WASM-challenge repository.
// It performs a math-based PoW challenge-solving algorithm.
const GhostWASM = "AGFzbQEAAAABCAFgA39/fwF/AwIBAAUDAQABBxICBm1lbW9yeQIABXNvbHZlAAAKYQFfAQN/QQAhAwNAQcW78oh4IQRBACEFA0AgBCAAIAVqLQAAc0GTg4AIbCEEIAVBAWohBSAFIAFIDQALIAQgA3NBk4OACGwhBCAEZyACTwRAIAMPCyADQQFqIQMMAAtBfws="

// JSInjector returns an invisible, automatic challenge page.
func (s *System) JSInjector(challenge string) string {
	difficulty := s.config.Difficulty
	
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Check | GuardianTUI</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { background: #050505; color: #00f2ff; font-family: monospace; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .loader { border: 2px solid #111; border-top: 2px solid #00f2ff; border-radius: 50%%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin-bottom: 20px; }
        .text { font-size: 0.8rem; letter-spacing: 2px; opacity: 0.5; }
        @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="loader"></div>
    <div class="text">INITIALIZING GHOST SHIELD...</div>
    <script>
        (async function() {
            const wasmBase64 = "%s";
            const challengeStr = "%s";
            const difficulty = %d;
            try {
                const wasmBuffer = Uint8Array.from(atob(wasmBase64), c => c.charCodeAt(0));
                const { instance } = await WebAssembly.instantiate(wasmBuffer, {});
                const env = {
                    wd: navigator.webdriver || false,
                    hc: navigator.hardwareConcurrency || 0,
                    dm: window.innerWidth + "x" + window.innerHeight,
                    tz: new Intl.DateTimeFormat().resolvedOptions().timeZone,
                };
                const envStr = JSON.stringify(env);
                const encoder = new TextEncoder();
                const bytes = encoder.encode(challengeStr + envStr);
                const memory = new Uint8Array(instance.exports.memory.buffer);
                memory.set(bytes);
                const nonce = instance.exports.solve(0, bytes.length, difficulty);
                const solution = challengeStr + "|" + nonce + "|" + btoa(envStr);
                document.cookie = "gtui_pow=" + encodeURIComponent(solution) + "; path=/; Max-Age=3600; SameSite=Lax";
                window.location.reload();
            } catch (e) { console.error("Shield Error:", e); }
        })();
    </script>
</body>
</html>
`, GhostWASM, challenge, difficulty)
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
