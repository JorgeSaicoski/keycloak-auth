# keycloak-auth

A lightweight Go library for Keycloak JWT authentication with Gin framework. Designed for microservices architecture with support for both static public keys and JWKS endpoint integration.

## Features

- 🔐 JWT token validation with RSA signatures
- 🔑 Support for both static public keys and JWKS endpoints
- 🚀 Easy integration with Gin framework
- 🛡️ Role-based access control
- ⚙️ Configurable claims extraction
- 🎯 Path-based authentication skipping
- 📦 Helper functions for common operations

## Installation

```bash
go get github.com/JorgeSaicoski/keycloak-auth
```

## Quick Start

### Basic Usage (Static Public Key)

```go
package main

import (
    "github.com/gin-gonic/gin"
    keycloakauth "github.com/JorgeSaicoski/keycloak-auth"
)

func main() {
    // Configure authentication
    config := keycloakauth.DefaultConfig()
    config.LoadFromEnv() // Loads KEYCLOAK_PUBLIC_KEY from environment
    
    // Create Gin router
    r := gin.Default()
    
    // Apply auth middleware
    r.Use(keycloakauth.SimpleAuthMiddleware(config))
    
    r.GET("/protected", func(c *gin.Context) {
        userID, _ := keycloakauth.GetUserID(c)
        username, _ := keycloakauth.GetUsername(c)
        
        c.JSON(200, gin.H{
            "message": "Protected endpoint accessed",
            "userID": userID,
            "username": username,
        })
    })
    
    r.Run(":8080")
}
```

### Advanced Usage (JWKS Endpoint)

```go
config := keycloakauth.Config{
    KeycloakURL: "http://localhost:8080/keycloak",
    Realm: "master",
    SkipPaths: []string{"/health", "/metrics"},
    RequiredClaims: []string{"sub", "preferred_username"},
}

// Custom claims extraction
options := keycloakauth.AuthMiddlewareOptions{
    ClaimsExtractor: func(claims jwt.MapClaims) map[string]interface{} {
        return map[string]interface{}{
            "sub": claims["sub"],
            "username": claims["preferred_username"],
            "email": claims["email"],
            "roles": claims["realm_access"].(map[string]interface{})["roles"],
        }
    },
    ContextKeys: map[string]string{
        "sub": "userID",
        "preferred_username": "username",
        "email": "userEmail",
    },
}

r.Use(keycloakauth.AuthMiddleware(config, options))
```

## Configuration

### Environment Variables

```bash
KEYCLOAK_PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
KEYCLOAK_URL=http://localhost:8080/keycloak
KEYCLOAK_REALM=master
```

### Config Options

```go
type Config struct {
    // Static public key (base64 encoded)
    PublicKeyBase64 string
    
    // JWKS endpoint configuration
    KeycloakURL string
    Realm       string
    
    // Security options
    RequiredClaims []string
    SkipPaths      []string
    
    // Performance options
    KeyRefreshInterval time.Duration
    HTTPTimeout        time.Duration
}
```

## Helper Functions

### User Information

```go
// Get user ID
userID, exists := keycloakauth.GetUserID(c)

// Get username
username, exists := keycloakauth.GetUsername(c)

// Get email
email, exists := keycloakauth.GetUserEmail(c)

// Check if email is verified
verified := keycloakauth.IsEmailVerified(c)

// Get user groups
groups, exists := keycloakauth.GetUserGroups(c)
```

### Role Management

```go
// Check realm role
hasRole := keycloakauth.HasRole(c, "admin")

// Check client role
hasClientRole := keycloakauth.HasClientRole(c, "my-client", "viewer")

// Require role middleware
r.GET("/admin", keycloakauth.RequireRole("admin"), adminHandler)

// Require client role middleware
r.GET("/client-admin", keycloakauth.RequireClientRole("my-client", "admin"), clientAdminHandler)

// Require verified email
r.GET("/verified-only", keycloakauth.RequireEmailVerified(), verifiedHandler)
```

### Access Raw Claims and Token

```go
// Get all claims
claims, exists := keycloakauth.GetClaims(c)

// Get JWT token
token, exists := keycloakauth.GetToken(c)
```

## Migration from Existing Code

If you're currently using a custom middleware similar to the one in your project:

### Before:
```go
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        // ... existing validation logic
        c.Set("userID", claims["sub"])
        c.Set("username", claims["preferred_username"])
        c.Next()
    }
}
```

### After:
```go
import keycloakauth "github.com/JorgeSaicoski/keycloak-auth"

config := keycloakauth.DefaultConfig()
config.LoadFromEnv()
r.Use(keycloakauth.SimpleAuthMiddleware(config))

// Your existing code using c.Get("userID") will work unchanged
// Or use the new helper functions:
userID, _ := keycloakauth.GetUserID(c)
```

## Error Handling

### Custom Error Handler

```go
options := keycloakauth.AuthMiddlewareOptions{
    ErrorHandler: func(c *gin.Context, err error) {
        c.JSON(401, gin.H{
            "error": "Authentication failed",
            "details": err.Error(),
            "timestamp": time.Now(),
        })
        c.Abort()
    },
}

r.Use(keycloakauth.AuthMiddleware(config, options))
```

## Production Considerations

1. **Use JWKS endpoints** instead of static keys for automatic key rotation
2. **Set appropriate timeouts** for JWKS requests
3. **Configure key refresh intervals** based on your security requirements
4. **Monitor authentication failures** and implement rate limiting
5. **Use HTTPS** for all Keycloak communications

## Examples

See the `examples/` directory for complete working examples:

- Basic authentication with static keys
- JWKS endpoint integration
- Role-based access control
- Custom claims extraction
- Microservice integration patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details