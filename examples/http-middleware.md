# HTTP Middleware Integration Examples

This document shows how to integrate simple-ldap-go with popular Go web frameworks for authentication and authorization.

## Table of Contents

- [Fiber Framework](#fiber-framework)
- [Echo Framework](#echo-framework)
- [Gin Framework](#gin-framework)
- [Chi Framework](#chi-framework)

## Fiber Framework

### Basic Authentication Middleware

```go
package middleware

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	ldap2 "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"
)

var (
	ErrAuthHeaderMissing   = errors.New("authorization header not found")
	ErrAuthHeaderMalformed = errors.New("authorization was not in the format of 'username:password'")
	ErrAuthFailed          = errors.New("authorization failed")
)

func basicAuth(auth string) (string, string, error) {
	if len(auth) < 6 || strings.ToLower(auth[:6]) != "basic " {
		return "", "", ErrAuthHeaderMissing
	}

	raw, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", ErrAuthHeaderMalformed
	}

	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", ErrAuthHeaderMalformed
	}

	return parts[0], parts[1], nil
}

func LDAPAuth(l *ldap.LDAP) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sAMAccountName, password, err := basicAuth(c.Get(fiber.HeaderAuthorization))
		if err != nil {
			c.Set(fiber.HeaderWWWAuthenticate, "Basic realm=Restricted")
			return c.Status(fiber.StatusUnauthorized).SendString(err.Error())
		}

		user, err := l.CheckPasswordForSAMAccountName(sAMAccountName, password)
		if err != nil {
			e, ok := err.(*ldap2.Error)
			if ok && e.ResultCode == ldap2.LDAPResultInvalidCredentials {
				c.Set(fiber.HeaderWWWAuthenticate, "Basic realm=Restricted")
				return c.Status(fiber.StatusUnauthorized).SendString("invalid credentials")
			}

			if err == ldap.ErrUserNotFound || err == ldap.ErrSAMAccountNameDuplicated {
				c.Set(fiber.HeaderWWWAuthenticate, "Basic realm=Restricted")
				return c.Status(fiber.StatusUnauthorized).SendString("authentication failed")
			}

			return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
		}

		c.Locals("user", *user)
		return c.Next()
	}
}
```

### Group-Based Authorization Middleware

```go
// RequireGroup middleware checks if authenticated user is member of specified group
func RequireGroup(groupDN string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user, ok := c.Locals("user").(ldap.User)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).SendString("authentication required")
		}

		if !user.IsMemberOf(groupDN) {
			return c.Status(fiber.StatusForbidden).SendString("insufficient permissions")
		}

		return c.Next()
	}
}

// Example usage:
func SetupRoutes(app *fiber.App, ldapClient *ldap.LDAP) {
	// Public routes
	app.Get("/", handleHome)

	// Protected routes - authentication required
	api := app.Group("/api", LDAPAuth(ldapClient))
	api.Get("/profile", handleProfile)

	// Admin-only routes - requires admin group membership
	adminGroup := "CN=Admins,OU=Groups,DC=example,DC=com"
	admin := api.Group("/admin", RequireGroup(adminGroup))
	admin.Get("/users", handleListUsers)
	admin.Post("/users", handleCreateUser)
}
```

## Echo Framework

### Basic Authentication Middleware

```go
package middleware

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	ldap2 "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"
)

func LDAPAuth(l *ldap.LDAP) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth := c.Request().Header.Get("Authorization")
			sAMAccountName, password, err := basicAuth(auth)
			if err != nil {
				c.Response().Header().Set("WWW-Authenticate", "Basic realm=Restricted")
				return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
			}

			user, err := l.CheckPasswordForSAMAccountName(sAMAccountName, password)
			if err != nil {
				e, ok := err.(*ldap2.Error)
				if ok && e.ResultCode == ldap2.LDAPResultInvalidCredentials {
					c.Response().Header().Set("WWW-Authenticate", "Basic realm=Restricted")
					return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials")
				}

				if err == ldap.ErrUserNotFound || err == ldap.ErrSAMAccountNameDuplicated {
					c.Response().Header().Set("WWW-Authenticate", "Basic realm=Restricted")
					return echo.NewHTTPError(http.StatusUnauthorized, "authentication failed")
				}

				return echo.NewHTTPError(http.StatusInternalServerError, "internal server error")
			}

			c.Set("user", *user)
			return next(c)
		}
	}
}

// RequireGroup middleware for Echo
func RequireGroup(groupDN string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, ok := c.Get("user").(ldap.User)
			if !ok {
				return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
			}

			if !user.IsMemberOf(groupDN) {
				return echo.NewHTTPError(http.StatusForbidden, "insufficient permissions")
			}

			return next(c)
		}
	}
}
```

## Gin Framework

### Basic Authentication Middleware

```go
package middleware

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	ldap2 "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"
)

func LDAPAuth(l *ldap.LDAP) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		sAMAccountName, password, err := basicAuth(auth)
		if err != nil {
			c.Header("WWW-Authenticate", "Basic realm=Restricted")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		user, err := l.CheckPasswordForSAMAccountName(sAMAccountName, password)
		if err != nil {
			e, ok := err.(*ldap2.Error)
			if ok && e.ResultCode == ldap2.LDAPResultInvalidCredentials {
				c.Header("WWW-Authenticate", "Basic realm=Restricted")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
				return
			}

			if err == ldap.ErrUserNotFound || err == ldap.ErrSAMAccountNameDuplicated {
				c.Header("WWW-Authenticate", "Basic realm=Restricted")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
				return
			}

			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.Set("user", *user)
		c.Next()
	}
}

// RequireGroup middleware for Gin
func RequireGroup(groupDN string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userValue, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}

		user, ok := userValue.(ldap.User)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user context"})
			return
		}

		if !user.IsMemberOf(groupDN) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		c.Next()
	}
}

// Example usage:
func SetupRoutes(r *gin.Engine, ldapClient *ldap.LDAP) {
	// Public routes
	r.GET("/", handleHome)

	// Protected routes
	api := r.Group("/api")
	api.Use(LDAPAuth(ldapClient))
	{
		api.GET("/profile", handleProfile)

		// Admin-only routes
		adminGroup := "CN=Admins,OU=Groups,DC=example,DC=com"
		admin := api.Group("/admin")
		admin.Use(RequireGroup(adminGroup))
		{
			admin.GET("/users", handleListUsers)
			admin.POST("/users", handleCreateUser)
		}
	}
}
```

## Chi Framework

### Basic Authentication Middleware

```go
package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	ldap2 "github.com/go-ldap/ldap/v3"
	ldap "github.com/netresearch/simple-ldap-go"
)

type contextKey string

const userContextKey contextKey = "user"

func LDAPAuth(l *ldap.LDAP) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			sAMAccountName, password, err := basicAuth(auth)
			if err != nil {
				w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			user, err := l.CheckPasswordForSAMAccountName(sAMAccountName, password)
			if err != nil {
				e, ok := err.(*ldap2.Error)
				if ok && e.ResultCode == ldap2.LDAPResultInvalidCredentials {
					w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
					http.Error(w, "invalid credentials", http.StatusUnauthorized)
					return
				}

				if err == ldap.ErrUserNotFound || err == ldap.ErrSAMAccountNameDuplicated {
					w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
					http.Error(w, "authentication failed", http.StatusUnauthorized)
					return
				}

				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, *user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireGroup middleware for Chi
func RequireGroup(groupDN string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userValue := r.Context().Value(userContextKey)
			if userValue == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}

			user, ok := userValue.(ldap.User)
			if !ok {
				http.Error(w, "invalid user context", http.StatusUnauthorized)
				return
			}

			if !user.IsMemberOf(groupDN) {
				http.Error(w, "insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Example usage:
func SetupRoutes(ldapClient *ldap.LDAP) *chi.Mux {
	r := chi.NewRouter()

	// Public routes
	r.Get("/", handleHome)

	// Protected routes
	r.Route("/api", func(r chi.Router) {
		r.Use(LDAPAuth(ldapClient))
		r.Get("/profile", handleProfile)

		// Admin-only routes
		r.Route("/admin", func(r chi.Router) {
			adminGroup := "CN=Admins,OU=Groups,DC=example,DC=com"
			r.Use(RequireGroup(adminGroup))
			r.Get("/users", handleListUsers)
			r.Post("/users", handleCreateUser)
		})
	})

	return r
}
```

## Batch User Lookup Example

For endpoints that need to fetch multiple users (e.g., admin panels):

```go
// Using FindUsersBySAMAccountNames for efficient batch lookup
func handleGetUserDetails(c *fiber.Ctx) error {
	// Parse comma-separated usernames from query parameter
	usernames := strings.Split(c.Query("usernames"), ",")

	// Batch lookup - much more efficient than individual calls
	users, err := ldapClient.FindUsersBySAMAccountNames(usernames)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to fetch users",
		})
	}

	// Convert to response format
	userDetails := make([]fiber.Map, 0, len(users))
	for _, user := range users {
		userDetails = append(userDetails, fiber.Map{
			"username": user.SAMAccountName,
			"dn":       user.DN(),
			"groups":   user.Groups,
		})
	}

	return c.JSON(fiber.Map{
		"users": userDetails,
	})
}
```

## Best Practices

### 1. Error Handling

Always distinguish between authentication failures (401) and authorization failures (403):

```go
// Authentication failure - credentials invalid
if err == ldap.ErrUserNotFound || invalidCredentials {
	return c.Status(401).SendString("authentication failed")
}

// Authorization failure - authenticated but insufficient permissions
if !user.IsMemberOf(requiredGroup) {
	return c.Status(403).SendString("insufficient permissions")
}
```

### 2. Context Support

Use context-aware methods for timeout and cancellation support:

```go
ctx := c.Request().Context()
users, err := ldapClient.FindUsersBySAMAccountNamesContext(ctx, usernames)
```

### 3. Group DN Configuration

Store group DNs in configuration, not hardcoded:

```go
type Config struct {
	AdminGroupDN     string `env:"LDAP_ADMIN_GROUP_DN"`
	ModeratorGroupDN string `env:"LDAP_MODERATOR_GROUP_DN"`
}

func RequireGroup(cfg *Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		user := c.Locals("user").(ldap.User)

		if !user.IsMemberOf(cfg.AdminGroupDN) {
			return c.Status(403).SendString("admin access required")
		}

		return c.Next()
	}
}
```

### 4. Logging

Add structured logging for security auditing:

```go
import "log/slog"

func LDAPAuth(l *ldap.LDAP, logger *slog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		sAMAccountName, password, err := basicAuth(c.Get(fiber.HeaderAuthorization))
		if err != nil {
			logger.Warn("authentication_attempt_failed",
				slog.String("reason", "invalid_auth_header"),
				slog.String("ip", c.IP()))
			return c.Status(401).SendString(err.Error())
		}

		user, err := l.CheckPasswordForSAMAccountName(sAMAccountName, password)
		if err != nil {
			logger.Warn("authentication_failed",
				slog.String("username", sAMAccountName),
				slog.String("ip", c.IP()),
				slog.String("error", err.Error()))
			return c.Status(401).SendString("authentication failed")
		}

		logger.Info("authentication_success",
			slog.String("username", user.SAMAccountName),
			slog.String("dn", user.DN()),
			slog.String("ip", c.IP()))

		c.Locals("user", *user)
		return c.Next()
	}
}
```

## See Also

- [User.IsMemberOf() documentation](../users.go#L103-L136)
- [FindUsersBySAMAccountNames() documentation](../users.go#L457-L561)
- [Main README](../README.md)