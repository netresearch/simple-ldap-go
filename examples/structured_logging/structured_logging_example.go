package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

func demonstrateStructuredLogging() {
	// Example 1: JSON structured logging to stdout
	jsonLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
		Logger:            jsonLogger,
	}

	client, err := ldap.New(&config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		slog.Error("Failed to create LDAP client", slog.String("error", err.Error()))
		return
	}

	// Example 2: Text structured logging to file with different log level
	logFile, err := os.OpenFile("ldap.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		slog.Error("Failed to open log file", slog.String("error", err.Error()))
		return
	}
	defer func() { _ = logFile.Close() }()

	textLogger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelInfo, // Only log Info and above to file
	}))

	configWithTextLogger := config
	configWithTextLogger.Logger = textLogger

	_, err = ldap.New(&configWithTextLogger, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		slog.Error("Failed to create second LDAP client", slog.String("error", err.Error()))
		return
	}

	// Example operations with structured logging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Authentication operations - will log success/failure with timing
	user, err := client.CheckPasswordForSAMAccountNameContext(ctx, "jdoe", "userpassword")
	if err != nil {
		slog.Error("Authentication failed", slog.String("username", "jdoe"), slog.String("error", err.Error()))
		return
	}
	slog.Info("User authenticated successfully", slog.String("username", user.SAMAccountName), slog.String("dn", user.DN()))

	// Search operations - will log search parameters and results
	users, err := client.FindUsersContext(ctx)
	if err != nil {
		slog.Error("User search failed", slog.String("error", err.Error()))
		return
	}
	slog.Info("User search completed", slog.Int("count", len(users)))

	// Group operations - will log membership changes
	err = client.AddUserToGroupContext(ctx, user.DN(), "CN=IT Department,CN=Groups,DC=example,DC=com")
	if err != nil {
		slog.Error("Failed to add user to group",
			slog.String("user_dn", user.DN()),
			slog.String("group_dn", "CN=IT Department,CN=Groups,DC=example,DC=com"),
			slog.String("error", err.Error()))
	} else {
		slog.Info("User added to group successfully",
			slog.String("user_dn", user.DN()),
			slog.String("group_dn", "CN=IT Department,CN=Groups,DC=example,DC=com"))
	}

	// Example 3: No logging (using default no-op logger)
	configNoLogging := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
		// Logger is nil - will use no-op logger
	}

	client3, err := ldap.New(&configNoLogging, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		slog.Error("Failed to create third LDAP client", slog.String("error", err.Error()))
		return
	}

	// This operation will not generate any log output
	_, err = client3.FindUserBySAMAccountNameContext(ctx, "jdoe")
	if err != nil {
		slog.Error("Silent client operation failed", slog.String("error", err.Error()))
	}

	// Example 4: Custom logger with additional context
	customLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})).With(
		slog.String("service", "user-management"),
		slog.String("version", "1.0.0"),
		slog.String("environment", "production"),
	)

	configWithContext := config
	configWithContext.Logger = customLogger

	client4, err := ldap.New(&configWithContext, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		slog.Error("Failed to create contextual LDAP client", slog.String("error", err.Error()))
		return
	}

	// All operations will now include the additional context fields
	_, err = client4.FindUsersContext(ctx)
	if err != nil {
		slog.Error("Contextual client operation failed", slog.String("error", err.Error()))
	}

	slog.Info("Structured logging examples completed")
}

func main() {
	demonstrateStructuredLogging()
}
