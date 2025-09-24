// Package main demonstrates modern Go patterns in the LDAP library.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	ldap "github.com/netresearch/simple-ldap-go"
)

func main() {
	modernPatternsDemo()
}

func modernPatternsDemo() {
	// Create a structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Example 1: Modern client creation with functional options
	fmt.Println("=== Modern Client Creation with Functional Options ===")
	if err := demonstrateModernClientCreation(logger); err != nil {
		log.Printf("Modern client creation demo failed: %v", err)
	}

	// Example 2: Builder patterns
	fmt.Println("\n=== Builder Patterns ===")
	if err := demonstrateBuilderPatterns(); err != nil {
		log.Printf("Builder patterns demo failed: %v", err)
	}

	// Example 3: Generic type safety (requires Go 1.18+)
	fmt.Println("\n=== Generic Type Safety ===")
	if err := demonstrateGenerics(logger); err != nil {
		log.Printf("Generics demo failed: %v", err)
	}

	// Example 4: Modern concurrency patterns
	fmt.Println("\n=== Modern Concurrency Patterns ===")
	if err := demonstrateConcurrencyPatterns(logger); err != nil {
		log.Printf("Concurrency patterns demo failed: %v", err)
	}

	// Example 5: Interface segregation
	fmt.Println("\n=== Interface Segregation ===")
	if err := demonstrateInterfaceSegregation(logger); err != nil {
		log.Printf("Interface segregation demo failed: %v", err)
	}

	// Example 6: Resource management patterns
	fmt.Println("\n=== Resource Management Patterns ===")
	if err := demonstrateResourceManagement(); err != nil {
		log.Printf("Resource management demo failed: %v", err)
	}

	// Example 7: Error handling patterns
	fmt.Println("\n=== Error Handling Patterns ===")
	demonstrateErrorHandling()

	// Helper functions demonstration (these are used by other examples)
	fmt.Println("\n=== Helper Functions (used internally) ===")
	// These helper functions are used throughout the examples:
	// - parseUserFromDN: Simulates parsing user from DN
	// - stringPtr: Creates string pointers for struct fields
	testDN := "CN=TestUser,DC=example,DC=com"
	_ = parseUserFromDN(testDN)
	_ = stringPtr("test-string")
}

// demonstrateModernClientCreation shows the functional options pattern
func demonstrateModernClientCreation(logger *slog.Logger) error {
	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	// Example 1: Basic client with custom logger
	fmt.Println("Creating basic client with custom logger...")
	client1, err := ldap.NewWithOptions(config, "CN=admin,CN=Users,DC=example,DC=com", "password",
		ldap.WithLogger(logger),
	)
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
	} else {
		defer func() {
		_ = client1.Close()
	}()
		fmt.Println("✓ Basic client created successfully")
	}

	// Example 2: High-performance client with all modern features
	fmt.Println("Creating high-performance client...")
	client2, err := ldap.NewWithOptions(config, "CN=admin,CN=Users,DC=example,DC=com", "password",
		ldap.WithLogger(logger),
		ldap.WithConnectionPool(&ldap.PoolConfig{
			MaxConnections:      20,
			MinConnections:      5,
			MaxIdleTime:         10 * time.Minute,
			HealthCheckInterval: 1 * time.Minute,
		}),
		ldap.WithCache(&ldap.CacheConfig{
			Enabled:     true,
			TTL:         5 * time.Minute,
			MaxSize:     1000,
			MaxMemoryMB: 100,
		}),
		ldap.WithPerformanceMonitoring(&ldap.PerformanceConfig{
			Enabled:            true,
			SlowQueryThreshold: 500 * time.Millisecond,
		}),
		ldap.WithConnectionOptions(&ldap.ConnectionOptions{
			ConnectionTimeout:    30 * time.Second,
			OperationTimeout:     60 * time.Second,
			MaxRetries:           3,
			RetryDelay:           1 * time.Second,
			EnableTLS:            true,
			ValidateCertificates: true,
		}),
	)
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
	} else {
		defer func() {
		_ = client2.Close()
	}()
		fmt.Println("✓ High-performance client created successfully")
	}

	// Example 3: Using convenient factory methods
	fmt.Println("Using factory methods...")

	// Secure client
	secureClient, err := ldap.NewSecureClient(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
	} else {
		defer func() { _ = secureClient.Close() }()
		fmt.Println("✓ Secure client created successfully")
	}

	// Read-only client
	readOnlyClient, err := ldap.NewReadOnlyClient(config, "CN=reader,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
	} else {
		defer func() { _ = readOnlyClient.Close() }()
		fmt.Println("✓ Read-only client created successfully")
	}

	// High-performance client
	perfClient, err := ldap.NewHighPerformanceClient(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
	} else {
		defer func() { _ = perfClient.Close() }()
		fmt.Println("✓ High-performance client created successfully")
	}

	return nil
}

// demonstrateBuilderPatterns shows the modern builder patterns
func demonstrateBuilderPatterns() error {
	fmt.Println("Building users with builder pattern...")

	// Example 1: Create a user with the builder pattern
	user1, err := ldap.NewUserBuilder().
		WithCN("John Doe").
		WithSAMAccountName("jdoe").
		WithMail("john.doe@example.com").
		WithDescription("Software Engineer").
		WithEnabled(true).
		WithGroups([]string{
			"CN=Developers,OU=Groups,DC=example,DC=com",
			"CN=Domain Users,CN=Users,DC=example,DC=com",
		}).
		Build()

	if err != nil {
		return fmt.Errorf("failed to build user: %w", err)
	}
	fmt.Printf("✓ Built user: %s (%s)\n", user1.CN, *user1.SAMAccountName)

	// Example 2: Create a group with the builder pattern
	group1, err := ldap.NewGroupBuilder().
		WithCN("DevOps Team").
		WithDescription("DevOps and Infrastructure Team").
		WithGroupType(0x80000002). // Global Security Group
		WithSAMAccountName("DevOps").
		WithMembers([]string{
			"CN=John Doe,OU=Users,DC=example,DC=com",
			"CN=Jane Smith,OU=Users,DC=example,DC=com",
		}).
		Build()

	if err != nil {
		return fmt.Errorf("failed to build group: %w", err)
	}
	fmt.Printf("✓ Built group: %s (%s)\n", group1.CN, group1.SAMAccountName)

	// Example 3: Create a computer with the builder pattern
	computer1, err := ldap.NewComputerBuilder().
		WithCN("DEV-WORKSTATION-01").
		WithSAMAccountName("DEV-WORKSTATION-01$").
		WithDescription("Development Workstation").
		WithDNSHostName("dev-ws-01.example.com").
		WithOperatingSystem("Windows 11 Pro").
		WithEnabled(true).
		Build()

	if err != nil {
		return fmt.Errorf("failed to build computer: %w", err)
	}
	fmt.Printf("✓ Built computer: %s (%s)\n", computer1.CN, computer1.SAMAccountName)

	// Example 4: Create configuration with builder pattern
	config, err := ldap.NewConfigBuilder().
		WithServer("ldaps://ad.example.com:636").
		WithBaseDN("DC=example,DC=com").
		WithActiveDirectory(true).
		WithConnectionPool(&ldap.PoolConfig{
			MaxConnections: 15,
			MinConnections: 3,
		}).
		WithCache(&ldap.CacheConfig{
			Enabled: true,
			TTL:     5 * time.Minute,
			MaxSize: 500,
		}).
		Build()

	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}
	fmt.Printf("✓ Built config for server: %s\n", config.Server)

	// Example 5: Validation demonstration
	fmt.Println("Demonstrating validation...")

	// This should fail due to invalid email
	_, err = ldap.NewUserBuilder().
		WithCN("Invalid User").
		WithSAMAccountName("invalid").
		WithMail("not-an-email").
		Build()

	if err != nil {
		fmt.Printf("✓ Validation correctly caught error: %v\n", err)
	} else {
		return fmt.Errorf("validation should have failed for invalid email")
	}

	return nil
}

// demonstrateGenerics shows type-safe generic operations (requires Go 1.18+)
func demonstrateGenerics(logger *slog.Logger) error {
	// Note: This is demonstration code - actual usage would require a real LDAP connection
	fmt.Println("Demonstrating generic type safety...")

	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	// Create client (will fail in demo, but shows the pattern)
	client, err := ldap.NewWithOptions(config, "CN=admin,CN=Users,DC=example,DC=com", "password",
		ldap.WithLogger(logger),
	)
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
		fmt.Println("✓ Generic patterns demonstrated (would work with real connection)")
		return nil
	}
	defer func() { _ = client.Close() }()

	// Example 1: Generic search (type-safe)
	fmt.Println("Generic search operations...")
	/*
		ctx := context.Background()
		// This would work with a real connection:
		users, err := ldap.Search[*ldap.User](ctx, client, "(objectClass=user)", "")
		if err != nil {
			return fmt.Errorf("user search failed: %w", err)
		}
		fmt.Printf("Found %d users\n", len(users))

		groups, err := ldap.Search[*ldap.Group](ctx, client, "(objectClass=group)", "")
		if err != nil {
			return fmt.Errorf("group search failed: %w", err)
		}
		fmt.Printf("Found %d groups\n", len(groups))
	*/

	// Example 2: Generic pipeline processing
	fmt.Println("Generic pipeline processing...")
	/*
		pipeline := ldap.NewPipeline[string, *ldap.User](ctx, logger, 100)

		// Add parsing stage
		pipeline.AddStage("parse", func(ctx context.Context, dn string) (*ldap.FullUser, error) {
			// Parse DN and create user object
			return parseUserFromDN(dn), nil
		}, 5)

		// Add creation stage
		pipeline.AddStage("create", func(ctx context.Context, user *ldap.FullUser) (*ldap.User, error) {
			dn, err := client.CreateUserContext(ctx, *user, "password")
			if err != nil {
				return nil, err
			}
			return client.FindUserByDNContext(ctx, dn)
		}, 10)

		go pipeline.Start()
	*/

	fmt.Println("✓ Generic patterns demonstrated")
	return nil
}

// demonstrateConcurrencyPatterns shows modern concurrency patterns
func demonstrateConcurrencyPatterns(logger *slog.Logger) error {
	fmt.Println("Demonstrating concurrency patterns...")

	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	client, err := ldap.NewHighPerformanceClient(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
		fmt.Println("✓ Concurrency patterns demonstrated (would work with real connection)")
		return nil
	}
	defer func() { _ = client.Close() }()

	// Example 1: Worker pool pattern
	fmt.Println("Worker pool pattern...")
	/*
		pool := ldap.NewWorkerPool[*ldap.FullUser](client, &ldap.WorkerPoolConfig{
			WorkerCount: 10,
			BufferSize:  50,
			Timeout:     2 * time.Minute,
		})
		defer func() { _ = pool.Close() }()

		// Submit work items
		users := []*ldap.FullUser{
			// ... user objects
		}

		for i, user := range users {
			pool.Submit(ldap.WorkItem[*ldap.FullUser]{
				ID:   fmt.Sprintf("user-%d", i),
				Data: user,
				Fn: func(ctx context.Context, client *ldap.LDAP, data *ldap.FullUser) error {
					_, err := client.CreateUserContext(ctx, *data, "defaultPassword")
					return err
				},
			})
		}

		// Collect results
		for result := range pool.Results() {
			if result.Error != nil {
				logger.Error("worker_pool_item_failed",
					slog.String("id", result.ID),
					slog.String("error", result.Error.Error()))
			} else {
				logger.Info("worker_pool_item_success",
					slog.String("id", result.ID),
					slog.Duration("duration", result.Duration))
			}
		}

		stats := pool.Stats()
		fmt.Printf("Processed: %d, Errors: %d, Avg Duration: %v\n",
			stats.Processed, stats.Errors, stats.AverageDuration)
	*/

	// Example 2: Batch processor
	fmt.Println("Batch processor pattern...")
	/*
		processor := ldap.NewBatchProcessor(client, 10, 1*time.Second,
			func(ctx context.Context, client *ldap.LDAP, users []*ldap.FullUser) error {
				logger.Info("processing_batch", slog.Int("size", len(users)))
				for _, user := range users {
					_, err := client.CreateUserContext(ctx, *user, "password")
					if err != nil {
						return err
					}
				}
				return nil
			})
		defer func() { _ = processor.Close() }()

		// Add items for processing
		for _, user := range users {
			processor.Add(user)
		}
	*/

	// Example 3: Semaphore-controlled operations
	fmt.Println("Semaphore-controlled operations...")
	semaphore := ldap.NewSemaphore(5) // Max 5 concurrent operations

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Example operation with semaphore
	err = semaphore.WithSemaphore(ctx, func() error {
		// Simulated LDAP operation
		time.Sleep(100 * time.Millisecond)
		fmt.Println("✓ Semaphore-controlled operation completed")
		return nil
	})

	if err != nil {
		return fmt.Errorf("semaphore operation failed: %w", err)
	}

	// Example 4: Concurrent operations helper
	fmt.Println("Concurrent operations helper...")
	/*
		concurrentOps := ldap.NewConcurrentOperations(client, 10)

		userDNs := []string{
			"CN=User1,OU=Users,DC=example,DC=com",
			"CN=User2,OU=Users,DC=example,DC=com",
			"CN=User3,OU=Users,DC=example,DC=com",
		}

		users, errors := concurrentOps.BulkFindUsers(ctx, userDNs)
		for i, user := range users {
			if errors[i] != nil {
				fmt.Printf("Error finding user %s: %v\n", userDNs[i], errors[i])
			} else if user != nil {
				fmt.Printf("Found user: %s\n", user.CN())
			}
		}
	*/

	fmt.Println("✓ Concurrency patterns demonstrated")
	return nil
}

// demonstrateInterfaceSegregation shows interface segregation principle
func demonstrateInterfaceSegregation(logger *slog.Logger) error {
	fmt.Println("Demonstrating interface segregation...")

	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	client, err := ldap.NewReadOnlyClient(config, "CN=reader,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
		fmt.Println("✓ Interface segregation demonstrated (would work with real connection)")
		return nil
	}
	defer func() { _ = client.Close() }()

	// Example 1: Using client as UserReader interface
	fmt.Println("Using UserReader interface...")
	useUserReader(client)

	// Example 2: Using client as ReadOnlyDirectory interface
	fmt.Println("Using ReadOnlyDirectory interface...")
	// NOTE: These interface demonstrations are for documentation purposes
	// The interfaces are not fully implemented yet, but show the intended usage pattern
	// When ready: useReadOnlyDirectory(client)
	_ = useReadOnlyDirectory // Mark as intentionally unused (demonstration function)

	// Example 3: Using client as DirectoryManager interface
	fmt.Println("Using DirectoryManager interface...")
	// When ready: useDirectoryManager(client)
	_ = useDirectoryManager // Mark as intentionally unused (demonstration function)

	fmt.Println("✓ Interface segregation demonstrated")
	return nil
}

// useUserReader demonstrates using the UserReader interface
func useUserReader(reader ldap.UserReader) {
	fmt.Println("  - UserReader interface allows only user read operations")
	// This function can only call user read methods:
	// - FindUserByDN
	// - FindUserByDNContext
	// - FindUserBySAMAccountName
	// - FindUserBySAMAccountNameContext
	// - FindUserByMail
	// - FindUserByMailContext
}

// useReadOnlyDirectory demonstrates using the ReadOnlyDirectory interface
func useReadOnlyDirectory(readOnly ldap.ReadOnlyDirectory) {
	fmt.Println("  - ReadOnlyDirectory interface allows read operations for all object types")
	// This function can call read methods for users, groups, and computers
	// but cannot perform any write operations
}

// useDirectoryManager demonstrates using the full DirectoryManager interface
func useDirectoryManager(manager ldap.DirectoryManager) {
	fmt.Println("  - DirectoryManager interface allows full CRUD operations")
	// This function has access to all LDAP operations:
	// - User, Group, and Computer management
	// - Connection management
	// - Statistics and monitoring
}

// Resource management patterns demonstration
func demonstrateResourceManagement() error {
	fmt.Println("Demonstrating modern resource management...")

	config := ldap.Config{
		Server:            "ldaps://ad.example.com:636",
		BaseDN:            "DC=example,DC=com",
		IsActiveDirectory: true,
	}

	client, err := ldap.NewWithOptions(config, "CN=admin,CN=Users,DC=example,DC=com", "password")
	if err != nil {
		fmt.Printf("Expected connection error in demo: %v\n", err)
		return nil
	}
	defer func() { _ = client.Close() }() // Modern resource cleanup

	// Example 1: WithConnection pattern for resource management
	fmt.Println("WithConnection pattern...")
	/*
		err = client.WithConnection(ctx, func(conn *ldap.Conn) error {
			// Use connection for multiple operations
			// Connection is automatically cleaned up when function returns

			searchResult, err := conn.Search(searchRequest)
			if err != nil {
				return err
			}

			// Process results...
			return nil
		})
	*/

	// Example 2: Transaction pattern for grouped operations
	fmt.Println("Transaction pattern...")
	/*
		err = client.Transaction(ctx, func(tx *ldap.Transaction) error {
			// All operations use the same connection
			user, err := tx.CreateUser(userData, "password")
			if err != nil {
				return err
			}

			err = tx.AddUserToGroup(user.DN(), groupDN)
			if err != nil {
				// Attempt cleanup on error
				tx.DeleteUser(user.DN())
				return err
			}

			return nil
		})
	*/

	fmt.Println("✓ Resource management patterns demonstrated")
	return nil
}

// Error handling patterns demonstration
func demonstrateErrorHandling() {
	fmt.Println("Demonstrating modern error handling patterns...")

	// Example 1: Enhanced error types with context
	config := ldap.Config{
		Server: "invalid://server",
		BaseDN: "DC=example,DC=com",
	}

	_, err := ldap.NewWithOptions(config, "user", "password")
	if err != nil {
		fmt.Printf("✓ Enhanced error with context: %v\n", err)

		// Check for specific error types
		var ldapErr *ldap.LDAPError
		if errors.As(err, &ldapErr) {
			fmt.Printf("  - LDAP Error Code: %d\n", ldapErr.Code)
			fmt.Printf("  - Server: %s\n", ldapErr.Server)
			fmt.Printf("  - Operation: %s\n", ldapErr.Op)
		}
	}

	// Example 2: Validation errors with details
	_, err = ldap.NewUserBuilder().
		WithCN("").
		WithSAMAccountName("invalid/name").
		Build()

	if err != nil {
		fmt.Printf("✓ Validation error with details: %v\n", err)
	}
}

// Helper function to simulate parsing user from DN (for demo purposes)
func parseUserFromDN(dn string) *ldap.FullUser {
	return &ldap.FullUser{
		CN:             "Parsed User",
		SAMAccountName: stringPtr("parsed"),
		Description:    stringPtr(fmt.Sprintf("Parsed from %s", dn)),
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
