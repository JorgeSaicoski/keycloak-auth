package keycloakauth

import (
	"net/http"

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

// HasRole checks if the user has a specific realm role with safe type assertions
func HasRole(c *gin.Context, role string) bool {
	claims, exists := GetClaims(c)
	if !exists {
		return false
	}

	realmAccess, ok := claims["realm_access"].(map[string]interface{})
	if !ok {
		return false
	}

	rolesInterface, ok := realmAccess["roles"]
	if !ok {
		return false
	}

	// Handle both []interface{} and []string
	switch roles := rolesInterface.(type) {
	case []interface{}:
		for _, r := range roles {
			if roleStr, ok := r.(string); ok && roleStr == role {
				return true
			}
		}
	case []string:
		for _, r := range roles {
			if r == role {
				return true
			}
		}
	}

	return false
}

// HasClientRole checks if the user has a specific client role with safe type assertions
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

	rolesInterface, ok := clientAccess["roles"]
	if !ok {
		return false
	}

	// Handle both []interface{} and []string
	switch roles := rolesInterface.(type) {
	case []interface{}:
		for _, r := range roles {
			if roleStr, ok := r.(string); ok && roleStr == role {
				return true
			}
		}
	case []string:
		for _, r := range roles {
			if r == role {
				return true
			}
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

// GetUserGroups extracts the user groups from claims with safe type assertions
func GetUserGroups(c *gin.Context) ([]string, bool) {
	claims, exists := GetClaims(c)
	if !exists {
		return nil, false
	}

	groupsInterface, ok := claims["groups"]
	if !ok {
		return nil, false
	}

	var userGroups []string

	// Handle both []interface{} and []string
	switch groups := groupsInterface.(type) {
	case []interface{}:
		for _, group := range groups {
			if groupStr, ok := group.(string); ok {
				userGroups = append(userGroups, groupStr)
			}
		}
	case []string:
		userGroups = groups
	default:
		return nil, false
	}

	return userGroups, len(userGroups) > 0
}

// GetUserAttribute extracts a custom user attribute from claims
func GetUserAttribute(c *gin.Context, attribute string) (interface{}, bool) {
	claims, exists := GetClaims(c)
	if !exists {
		return nil, false
	}

	if value, exists := claims[attribute]; exists {
		return value, true
	}

	return nil, false
}

// RequireRole creates a middleware that requires a specific realm role
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !HasRole(c, role) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient privileges: missing role " + role,
				"code":  "missing_role",
			})
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
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient privileges: missing client role " + client + ":" + role,
				"code":  "missing_client_role",
			})
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
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Email verification required",
				"code":  "email_not_verified",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireAnyRole creates a middleware that requires at least one of the specified roles
func RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, role := range roles {
			if HasRole(c, role) {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error": "Insufficient privileges: missing any of required roles",
			"code":  "missing_any_role",
		})
		c.Abort()
	}
}

// RequireAllRoles creates a middleware that requires all specified roles
func RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, role := range roles {
			if !HasRole(c, role) {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Insufficient privileges: missing role " + role,
					"code":  "missing_required_role",
				})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
