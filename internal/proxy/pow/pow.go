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

// GenerateChallenge creates a new cryptographically signed challenge for a client
func (s *System) GenerateChallenge(ip string) string {
	timestamp := time.Now().Unix()
	salt := generateRandomString(8)
	
	// Format: ip:timestamp:salt
	base := fmt.Sprintf("%s:%d:%s", ip, timestamp, salt)
	
	// Sign it so clients can't forge challenges
	mac := hmac.New(sha256.New, s.config.Secret)
	mac.Write([]byte(base))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	
	return fmt.Sprintf("%s:%s", base, signature)
}

// ValidateSolution checks if the provided solution meets the difficulty for the given challenge
func (s *System) ValidateSolution(ip, challenge, solutionStr string) bool {
	// 1. Basic format check
	parts := strings.Split(challenge, ":")
	if len(parts) != 4 {
		return false
	}
	
	reqIP, timestampStr, salt, signature := parts[0], parts[1], parts[2], parts[3]
	
	// 2. IP matching (prevents challenge farming/sharing)
	if reqIP != ip {
		return false
	}
	
	// 3. Expiration check
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(timestamp, 0)) > s.config.Timeout {
		return false
	}
	
	// 4. Signature verification (prevents fake challenges)
	base := fmt.Sprintf("%s:%s:%s", reqIP, timestampStr, salt)
	mac := hmac.New(sha256.New, s.config.Secret)
	mac.Write([]byte(base))
	expectedSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	if signature != expectedSignature {
		return false
	}
	
	// 5. Replay attack prevention
	if _, exists := s.cache.Load(challenge); exists {
		return false // Challenge already solved
	}
	
	// 6. Verify the Work
	solution, err := strconv.Atoi(solutionStr)
	if err != nil {
		return false
	}
	
	// The work is: SHA256(challenge + solution) must start with 'Difficulty' number of '0's
	data := fmt.Sprintf("%s%d", challenge, solution)
	hash := sha256.Sum256([]byte(data))
	hashHex := fmt.Sprintf("%x", hash)
	
	targetPrefix := strings.Repeat("0", s.config.Difficulty)
	if strings.HasPrefix(hashHex, targetPrefix) {
		// Mark as solved
		s.cache.Store(challenge, time.Now())
		s.cleanupCache()
		return true
	}
	
	return false
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

// JSInjector returns the JavaScript required to solve the challenge invisibly in the browser
func (s *System) JSInjector(challenge string) string {
	difficulty := s.config.Difficulty
	return fmt.Sprintf(`
<script>
(function() {
    // Invisible Proof of Work Solver
    const challenge = "%s";
    const difficulty = %d;
    const targetPrefix = "0".repeat(difficulty);
    
    async function sha256(message) {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    async function solve() {
        let nonce = 0;
        while (true) {
            const hash = await sha256(challenge + nonce);
            if (hash.startsWith(targetPrefix)) {
                // Set the solution as a cookie that expires quickly
                document.cookie = "gtui_pow=" + encodeURIComponent(challenge + "|" + nonce) + "; path=/; max-age=300";
                // Reload the page automatically to proceed to the destination
                window.location.reload();
                break;
            }
            nonce++;
            
            // Yield to main thread every 1000 iterations to not freeze the browser
            if (nonce %% 1000 === 0) {
                await new Promise(r => setTimeout(r, 0));
            }
        }
    }
    solve();
})();
</script>
<noscript>Please enable JavaScript to access this site.</noscript>
<div style="font-family: sans-serif; text-align: center; margin-top: 20vh; color: #666;">
    <h2>Checking your browser...</h2>
    <p>Please wait a moment while we verify your connection.</p>
</div>
`, challenge, difficulty)
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
