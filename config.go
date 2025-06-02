package keycloakauth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds the configuration for Keycloak authentication
type Config struct {
	// Method 1: Static public key from environment (your current approach)
	PublicKeyBase64 string

	// Method 2: JWKS endpoint (recommended for production)
	KeycloakURL string // e.g., "http://localhost:8080/keycloak"
	Realm       string // e.g., "master"

	// Optional configurations
	RequiredClaims []string // Claims that must be present in the token
	SkipPaths      []string // Paths to skip authentication (e.g., "/health")

	// Advanced options
	KeyRefreshInterval time.Duration // How often to refresh JWKS keys
	HTTPTimeout        time.Duration // Timeout for JWKS requests
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() Config {
	return Config{
		KeyRefreshInterval: 1 * time.Hour,
		HTTPTimeout:        10 * time.Second,
		RequiredClaims:     []string{"sub"}, // At minimum, we need a subject
	}
}

// LoadFromEnv loads configuration from environment variables
func (c *Config) LoadFromEnv() {
	if publicKey := os.Getenv("KEYCLOAK_PUBLIC_KEY"); publicKey != "" {
		c.PublicKeyBase64 = publicKey
	}

	if keycloakURL := os.Getenv("KEYCLOAK_URL"); keycloakURL != "" {
		c.KeycloakURL = keycloakURL
	}

	if realm := os.Getenv("KEYCLOAK_REALM"); realm != "" {
		c.Realm = realm
	}
}

// JWKS represents the JSON Web Key Set response from Keycloak
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// KeyProvider handles public key retrieval and caching
type KeyProvider struct {
	config    Config
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
	client    *http.Client
}

// NewKeyProvider creates a new key provider
func NewKeyProvider(config Config) *KeyProvider {
	return &KeyProvider{
		config: config,
		keys:   make(map[string]*rsa.PublicKey),
		client: &http.Client{Timeout: config.HTTPTimeout},
	}
}

// GetPublicKey retrieves the public key for token validation
func (kp *KeyProvider) GetPublicKey(token *jwt.Token) (interface{}, error) {
	// Validate signing method
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	// Method 1: Use static key from environment
	if kp.config.PublicKeyBase64 != "" {
		return kp.getStaticPublicKey()
	}

	// Method 2: Use JWKS endpoint
	if kp.config.KeycloakURL != "" && kp.config.Realm != "" {
		return kp.getJWKSPublicKey(token)
	}

	return nil, fmt.Errorf("no public key configuration provided")
}

// getStaticPublicKey retrieves the public key from environment variable
func (kp *KeyProvider) getStaticPublicKey() (*rsa.PublicKey, error) {
	publicKeyPEM := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", kp.config.PublicKeyBase64)

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	return publicKey, nil
}

// getJWKSPublicKey retrieves the public key from JWKS endpoint
func (kp *KeyProvider) getJWKSPublicKey(token *jwt.Token) (*rsa.PublicKey, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token header missing kid")
	}

	// Check if we need to refresh keys
	if time.Since(kp.lastFetch) > kp.config.KeyRefreshInterval {
		if err := kp.refreshKeys(); err != nil {
			return nil, fmt.Errorf("failed to refresh keys: %v", err)
		}
	}

	// Get key from cache
	if key, exists := kp.keys[kid]; exists {
		return key, nil
	}

	// Try to refresh keys once more if key not found
	if err := kp.refreshKeys(); err != nil {
		return nil, fmt.Errorf("failed to refresh keys: %v", err)
	}

	if key, exists := kp.keys[kid]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid %s not found", kid)
}

// refreshKeys fetches the latest keys from JWKS endpoint
func (kp *KeyProvider) refreshKeys() error {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", kp.config.KeycloakURL, kp.config.Realm)

	resp, err := kp.client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %v", err)
	}

	// Convert JWKs to RSA public keys
	newKeys := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			rsaKey, err := parseJWKToRSA(key)
			if err != nil {
				continue // Skip invalid keys
			}
			newKeys[key.Kid] = rsaKey
		}
	}

	kp.keys = newKeys
	kp.lastFetch = time.Now()

	return nil
}

// parseJWKToRSA converts a JWK to an RSA public key
func parseJWKToRSA(key JWK) (*rsa.PublicKey, error) {
	// This is a simplified implementation
	// In production, you'd want to use a proper JWK library
	// But for now, we'll focus on the base64 env var approach
	return nil, fmt.Errorf("JWK to RSA conversion not implemented")
}
