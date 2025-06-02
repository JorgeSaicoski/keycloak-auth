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
- 🔄 Automatic key rotation with JWKS
- 🛡️ Thread-safe concurrent key access
- ⚡ Retry logic for network failures

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

### Production Usage (JWKS Endpoint - Recommended)

```go
config := keycloakauth.Config{
    KeycloakURL: "http://localhost:8080/keycloak",
    Realm: "master",
    SkipPaths: []string{"/health", "/metrics"},
    RequiredClaims: []string{"sub", "preferred_username"},
    KeyRefreshInterval: 1 * time.Hour,
    HTTPTimeout: 10 * time.Second,
}

// Custom claims extraction
options := keycloakauth.AuthMiddlewareOptions{
    ClaimsExtractor: func(claims jwt.MapClaims) map[string]interface{} {
        return map[string]interface{}{
            "sub": claims["sub"],
            "username": claims["preferred_username"],
            "email": claims["email"],
            "roles": extractRoles(claims), // Custom role extraction
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
# Static key method
KEYCLOAK_PUBLIC_KEY=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...

# JWKS method (recommended)
KEYCLOAK_URL=http://localhost:8080/keycloak
KEYCLOAK_REALM=master
```

### Config Options

```go
type Config struct {
    // Static public key (base64 encoded)
    PublicKeyBase64 string
    
    // JWKS endpoint configuration (recommended)
    KeycloakURL string
    Realm       string
    
    // Security options
    RequiredClaims []string
    SkipPaths      []string
    
    // Performance options
    KeyRefreshInterval time.Duration // Default: 1 hour
    HTTPTimeout        time.Duration // Default: 10 seconds
}
```

## JWKS Configuration

For production environments, use JWKS endpoints for automatic key rotation:

### Keycloak Setup

1. **Get your JWKS URL:**
   ```
   http://your-keycloak-server/keycloak/realms/your-realm/protocol/openid-connect/certs
   ```

2. **Configure your application:**
   ```go
   config := keycloakauth.Config{
       KeycloakURL: "http://your-keycloak-server/keycloak",
       Realm: "your-realm",
       KeyRefreshInterval: 1 * time.Hour, // Adjust based on key rotation frequency
       HTTPTimeout: 30 * time.Second,     // Increase for slow networks
   }
   ```

3. **Network considerations:**
   - Ensure your application can reach Keycloak
   - Consider using internal network addresses for better performance
   - Set appropriate timeouts for your network conditions

### Static Key vs JWKS Comparison

| Feature | Static Key | JWKS Endpoint |
|---------|------------|---------------|
| Setup Complexity | Simple | Medium |
| Key Rotation | Manual | Automatic |
| Network Dependency | None | Required |
| Production Ready | Limited | Yes |
| Performance | Fastest | Fast (with caching) |

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

// Get custom attribute
value, exists := keycloakauth.GetUserAttribute(c, "custom_field")
```

### Role Management

```go
// Check realm role
hasRole := keycloakauth.HasRole(c, "admin")

// Check client role
hasClientRole := keycloakauth.HasClientRole(c, "my-client", "viewer")

// Require single role
r.GET("/admin", keycloakauth.RequireRole("admin"), adminHandler)

// Require client role
r.GET("/client-admin", keycloakauth.RequireClientRole("my-client", "admin"), clientAdminHandler)

// Require any of multiple roles
r.GET("/moderator", keycloakauth.RequireAnyRole("admin", "moderator"), moderatorHandler)

// Require all roles
r.GET("/super-admin", keycloakauth.RequireAllRoles("admin", "super-user"), superAdminHandler)

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

If you're currently using a custom middleware:

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
        if authErr, ok := err.(*keycloakauth.AuthError); ok {
            c.JSON(401, gin.H{
                "error": authErr.Message,
                "code": authErr.Code,
                "timestamp": time.Now(),
            })
        } else {
            c.JSON(401, gin.H{
                "error": "Authentication failed",
                "details": err.Error(),
                "timestamp": time.Now(),
            })
        }
        c.Abort()
    },
}

r.Use(keycloakauth.AuthMiddleware(config, options))
```

### Error Types

The library provides structured error handling:

```go
type AuthError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}
```

**Common error codes:**
- `missing_authorization_header`: No Authorization header provided
- `invalid_authorization_format`: Authorization header format is incorrect
- `invalid_token`: Token validation failed
- `missing_required_claim`: Required claim not present in token
- `invalid_token_claims`: Token claims are invalid

## Production Considerations

### 1. JWKS Configuration
```go
config := keycloakauth.Config{
    KeycloakURL: "https://your-keycloak.com/keycloak",
    Realm: "production",
    KeyRefreshInterval: 30 * time.Minute,  // Refresh more frequently
    HTTPTimeout: 30 * time.Second,         // Longer timeout for production
    RequiredClaims: []string{"sub", "iss", "aud"}, // Validate issuer and audience
}
```

### 2. Monitoring and Logging
```go
// Custom error handler with logging
options := keycloakauth.AuthMiddlewareOptions{
    ErrorHandler: func(c *gin.Context, err error) {
        // Log authentication failures
        log.Printf("Auth failure for %s: %v", c.ClientIP(), err)
        
        // Return generic error to client
        c.JSON(401, gin.H{"error": "Authentication required"})
        c.Abort()
    },
}
```

### 3. Performance Optimization
- Use JWKS endpoints with appropriate refresh intervals
- Set reasonable HTTP timeouts
- Consider caching strategies for high-traffic applications
- Monitor key refresh failures and implement alerting

### 4. Security Best Practices
- Always use HTTPS in production
- Validate `iss` (issuer) and `aud` (audience) claims
- Implement rate limiting on authentication failures
- Monitor for unusual authentication patterns
- Regularly rotate Keycloak signing keys

## Testing

### Mock Authentication for Tests

```go
func TestProtectedEndpoint(t *testing.T) {
    gin.SetMode(gin.TestMode)
    router := gin.New()
    
    // Skip authentication in tests
    config := keycloakauth.Config{
        SkipPaths: []string{"/test"},
    }
    
    router.Use(keycloakauth.SimpleAuthMiddleware(config))
    router.GET("/test", handler)
    
    // Test without authentication
    req := httptest.NewRequest("GET", "/test", nil)
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, 200, w.Code)
}
```

### Integration Testing

```go
func TestKeycloakIntegration(t *testing.T) {
    // Use test Keycloak instance
    config := keycloakauth.Config{
        KeycloakURL: "http://localhost:8080/keycloak",
        Realm: "test",
    }
    
    // Get test token from Keycloak
    token := getTestTokenFromKeycloak()
    
    req := httptest.NewRequest("GET", "/protected", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    
    // Test with real token
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, 200, w.Code)
}
```

## Troubleshooting

### Common Issues

**1. "Key with kid X not found"**
- Check your JWKS endpoint is accessible
- Verify Keycloak is using the expected key ID
- Try refreshing keys manually

**2. "Invalid token signature"**
- Verify your public key is correct
- Check token hasn't expired
- Ensure token was issued by expected Keycloak instance

**3. "Network timeout"**
- Increase `HTTPTimeout` in config
- Check network connectivity to Keycloak
- Consider using internal network addresses

**4. "Missing required claim"**
- Check token includes all required claims
- Verify Keycloak client configuration
- Update `RequiredClaims` in config if needed

### Debug Mode

Enable debug logging to troubleshoot issues:

```go
// Add debug logging
options := keycloakauth.AuthMiddlewareOptions{
    ErrorHandler: func(c *gin.Context, err error) {
        log.Printf("Auth error: %+v", err)
        // ... handle error
    },
}
```

## Examples

See the `examples/` directory for complete working examples:

- Basic authentication with static keys
- JWKS endpoint integration  
- Role-based access control
- Custom claims extraction
- Microservice integration patterns
- Testing strategies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Ensure all tests pass
5. Submit a pull request

## Changelog

### v1.1.0
- ✅ Implemented complete JWKS support
- ✅ Added thread-safe key caching
- ✅ Enhanced error handling with retry logic
- ✅ Added configuration validation
- ✅ Improved type safety in helper functions
- ✅ Added new helper functions (`RequireAnyRole`, `RequireAllRoles`, `GetUserAttribute`)

### v1.0.0
- Initial release with basic JWT validation
- Static public key support
- Basic role checking

## License

MIT License - see LICENSE file for details