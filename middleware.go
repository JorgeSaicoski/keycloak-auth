package keycloakauth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// KeycloakClaims represents the standard claims from Keycloak
type KeycloakClaims struct {
	UserID         string                    `json:"sub"`
	Username       string                    `json:"preferred_username"`
	Email          string                    `json:"email"`
	EmailVerified  bool                      `json:"email_verified"`
	Name           string                    `json:"name"`
	GivenName      string                    `json:"given_name"`
	FamilyName     string                    `json:"family_name"`
	RealmAccess    RealmAccess               `json:"realm_access"`
	ResourceAccess map[string]ResourceAccess `json:"resource_access"`
	Groups         []string                  `json:"groups"`
	jwt.RegisteredClaims
}

// RealmAccess represents realm-level roles
type RealmAccess struct {
	Roles []string `json:"roles"`
}

// ResourceAccess represents client-level roles
type ResourceAccess struct {
	Roles []string `json:"roles"`
}

// ClaimsExtractor function type for custom claims extraction
type ClaimsExtractor func(claims jwt.MapClaims) map[string]interface{}

// ErrorHandler function type for custom error handling
type ErrorHandler func(c *gin.Context, err error)

// AuthMiddlewareOptions holds options for the auth middleware
type AuthMiddlewareOptions struct {
	ClaimsExtractor ClaimsExtractor
	ErrorHandler    ErrorHandler
	ContextKeys     map[string]string // Map of claim names to context keys
}

// AuthMiddleware creates a Gin middleware for Keycloak JWT authentication
func AuthMiddleware(config Config, options ...AuthMiddlewareOptions) gin.HandlerFunc {
	keyProvider, err := NewKeyProvider(config)
	if err != nil {
		panic("Failed to create key provider: " + err.Error())
	}

	// Set default options
	opts := AuthMiddlewareOptions{
		ClaimsExtractor: defaultClaimsExtractor,
		ErrorHandler:    defaultErrorHandler,
		ContextKeys: map[string]string{
			"sub":                "userID",
			"preferred_username": "username",
		},
	}

	// Apply custom options
	if len(options) > 0 {
		if options[0].ClaimsExtractor != nil {
			opts.ClaimsExtractor = options[0].ClaimsExtractor
		}
		if options[0].ErrorHandler != nil {
			opts.ErrorHandler = options[0].ErrorHandler
		}
		if options[0].ContextKeys != nil {
			opts.ContextKeys = options[0].ContextKeys
		}
	}

	return func(c *gin.Context) {
		// Check if path should be skipped
		if shouldSkipPath(c.Request.URL.Path, config.SkipPaths) {
			c.Next()
			return
		}

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			opts.ErrorHandler(c, &AuthError{
				Code:    "missing_authorization_header",
				Message: "Authorization header required",
			})
			return
		}

		// Extract token from header
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			opts.ErrorHandler(c, &AuthError{
				Code:    "invalid_authorization_format",
				Message: "Authorization header must be in format 'Bearer <token>'",
			})
			return
		}

		// Parse and validate token with retry logic
		token, err := jwt.Parse(tokenString, keyProvider.GetPublicKey)
		if err != nil {
			// If parsing fails with JWKS, try refreshing keys once
			if strings.Contains(err.Error(), "key with kid") && config.KeycloakURL != "" {
				// Force refresh and try again
				if refreshErr := keyProvider.refreshKeys(); refreshErr == nil {
					token, err = jwt.Parse(tokenString, keyProvider.GetPublicKey)
				}
			}

			if err != nil {
				opts.ErrorHandler(c, &AuthError{
					Code:    "invalid_token",
					Message: "Invalid token: " + err.Error(),
				})
				return
			}
		}

		// Extract and validate claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Check required claims
			if err := validateRequiredClaims(claims, config.RequiredClaims); err != nil {
				opts.ErrorHandler(c, err)
				return
			}

			// Extract claims to context
			extractedClaims := opts.ClaimsExtractor(claims)
			for claimName, contextKey := range opts.ContextKeys {
				if value, exists := extractedClaims[claimName]; exists {
					c.Set(contextKey, value)
				}
			}

			// Store all claims for advanced usage
			c.Set("keycloak_claims", claims)
			c.Set("keycloak_token", token)

			c.Next()
		} else {
			opts.ErrorHandler(c, &AuthError{
				Code:    "invalid_token_claims",
				Message: "Invalid token claims",
			})
		}
	}
}

// SimpleAuthMiddleware creates a basic auth middleware with your current behavior
func SimpleAuthMiddleware(config Config) gin.HandlerFunc {
	return AuthMiddleware(config)
}

// AuthError represents an authentication error
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *AuthError) Error() string {
	return e.Message
}

// defaultClaimsExtractor extracts standard claims with safe type assertions
func defaultClaimsExtractor(claims jwt.MapClaims) map[string]interface{} {
	result := make(map[string]interface{})

	// Safe extraction with type checking
	if sub, ok := claims["sub"].(string); ok {
		result["sub"] = sub
	}

	if username, ok := claims["preferred_username"].(string); ok {
		result["preferred_username"] = username
	}

	if email, ok := claims["email"].(string); ok {
		result["email"] = email
	}

	if name, ok := claims["name"].(string); ok {
		result["name"] = name
	}

	// Handle groups array safely
	if groupsInterface, ok := claims["groups"]; ok {
		if groups, ok := groupsInterface.([]interface{}); ok {
			var groupStrings []string
			for _, group := range groups {
				if groupStr, ok := group.(string); ok {
					groupStrings = append(groupStrings, groupStr)
				}
			}
			result["groups"] = groupStrings
		}
	}

	return result
}

// defaultErrorHandler handles authentication errors
func defaultErrorHandler(c *gin.Context, err error) {
	if authErr, ok := err.(*AuthError); ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": authErr.Message,
			"code":  authErr.Code,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": err.Error(),
			"code":  "authentication_failed",
		})
	}
	c.Abort()
}

// validateRequiredClaims checks if all required claims are present
func validateRequiredClaims(claims jwt.MapClaims, required []string) error {
	for _, claim := range required {
		if value, exists := claims[claim]; !exists || value == nil {
			return &AuthError{
				Code:    "missing_required_claim",
				Message: "Required claim '" + claim + "' not found in token",
			}
		}
	}
	return nil
}

// shouldSkipPath checks if the current path should skip authentication
func shouldSkipPath(path string, skipPaths []string) bool {
	for _, skipPath := range skipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}
