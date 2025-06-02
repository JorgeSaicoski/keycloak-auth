package keycloakauth

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// GetUserID extracts the user ID from the Gin context
func GetUserID(c *gin.Context) (string, bool) {
	userID, exists := c.Get("userID")
	if !exists {
		return "", false
	}

	if id, ok := userID.(string); ok {
		return id, true
	}

	return "", false
}

// GetUsername extracts the username from the Gin context
func GetUsername(c *gin.Context) (string, bool) {
	username, exists := c.Get("username")
	if !exists {
		return "", false
	}

	if name, ok := username.(string); ok {
		return name, true
	}

	return "", false
}

// GetClaims retrieves all Keycloak claims from the context
func GetClaims(c *gin.Context) (jwt.MapClaims, bool) {
	claims, exists := c.Get("keycloak_claims")
	if !exists {
		return nil, false
	}

	if keycloakClaims, ok := claims.(jwt.MapClaims); ok {
		return keycloakClaims, true
	}

	return nil, false
}

// GetToken retrieves the JWT token from the context
func GetToken(c *gin.Context) (*jwt.Token, bool) {
	token, exists := c.Get("keycloak_token")
	if !exists {
		return nil, false
	}

	if jwtToken, ok := token.(*jwt.Token); ok {
		return jwtToken, true
	}

	return nil, false
}

// HasRole checks if the user has a specific realm role
func HasRole(c *gin.Context, role string) bool {
	claims, exists := GetClaims(c)
	if !exists {
		return false
	}

	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return false
	}

	roles, ok := realmAccess["roles"].([]interface{})
	if !ok {
		return false
	}

	for _, r := range roles {
		if roleStr, ok := r.(string); ok && roleStr == role {
			return true
		}
	}

	return false
}

// HasClientRole checks if the user has a specific client role
func HasClientRole(c *gin.Context, client, role string) bool {
	claims, exists := GetClaims(c)
	if !exists {
		return false
	}

	resourceAccess, ok := claims["resource_access"].(map[string]interface{})
	if !ok {
		return false
	}

	clientAccess, ok := resourceAccess[client].(map[string]interface{})
	if !ok {
		return false
	}

	roles, ok := clientAccess["roles"].([]interface{})
	if !ok {
		return false
	}

	for _, r := range roles {
		if roleStr, ok := r.(string); ok && roleStr == role {
			return true
		}
	}

	return false
}

// GetUserEmail extracts the user email from claims
func GetUserEmail(c *gin.Context) (string, bool) {
	claims, exists := GetClaims(c)
	if !exists {
		return "", false
	}

	if email, ok := claims["email"].(string); ok {
		return email, true
	}

	return "", false
}

// IsEmailVerified checks if the user's email is verified
func IsEmailVerified(c *gin.Context) bool {
	claims, exists := GetClaims(c)
	if !exists {
		return false
	}

	if verified, ok := claims["email_verified"].(bool); ok {
		return verified
	}

	return false
}

// GetUserGroups extracts the user groups from claims
func GetUserGroups(c *gin.Context) ([]string, bool) {
	claims, exists := GetClaims(c)
	if !exists {
		return nil, false
	}

	groups, ok := claims["groups"].([]interface{})
	if !ok {
		return nil, false
	}

	var userGroups []string
	for _, group := range groups {
		if groupStr, ok := group.(string); ok {
			userGroups = append(userGroups, groupStr)
		}
	}

	return userGroups, len(userGroups) > 0
}

// RequireRole creates a middleware that requires a specific realm role
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasRole(c, role) {
			c.JSON(403, gin.H{"error": "Insufficient privileges: missing role " + role})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireClientRole creates a middleware that requires a specific client role
func RequireClientRole(client, role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasClientRole(c, client, role) {
			c.JSON(403, gin.H{"error": "Insufficient privileges: missing client role " + client + ":" + role})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireEmailVerified creates a middleware that requires verified email
func RequireEmailVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !IsEmailVerified(c) {
			c.JSON(403, gin.H{"error": "Email verification required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
