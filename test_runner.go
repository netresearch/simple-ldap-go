package ldap

import (
	"context"
	"flag"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestRunnerConfig configures test execution behavior
type TestRunnerConfig struct {
	// Parallel execution settings
	EnableParallel     bool
	MaxParallelTests   int
	ParallelPackages   bool

	// Timeout settings
	TestTimeout        time.Duration
	IntegrationTimeout time.Duration
	UnitTimeout        time.Duration

	// Test selection
	RunIntegrationTests bool
	RunUnitTests        bool
	RunBenchmarks       bool

	// Performance settings
	EnableCPUProfiling bool
	EnableMemProfiling bool

	// Container settings
	ReuseContainers    bool
	ContainerTimeout   time.Duration
}

// DefaultTestConfig returns optimized test configuration
func DefaultTestConfig() *TestRunnerConfig {
	numCPU := runtime.NumCPU()
	maxParallel := numCPU
	if maxParallel > 8 {
		maxParallel = 8 // Cap at 8 for container limits
	}

	return &TestRunnerConfig{
		EnableParallel:      true,
		MaxParallelTests:    maxParallel,
		ParallelPackages:    true,
		TestTimeout:         30 * time.Second,  // Reduced from default 10m
		IntegrationTimeout:  60 * time.Second,  // Specific timeout for integration tests
		UnitTimeout:         5 * time.Second,   // Fast timeout for unit tests
		RunIntegrationTests: !testing.Short(),
		RunUnitTests:        true,
		RunBenchmarks:       false,
		EnableCPUProfiling:  false,
		EnableMemProfiling:  false,
		ReuseContainers:     true,
		ContainerTimeout:    120 * time.Second, // Container startup timeout
	}
}

// TestCategory defines the type of test
type TestCategory int

const (
	UnitTest TestCategory = iota
	IntegrationTest
	BenchmarkTest
	PerformanceTest
)

// TestMetadata provides information about test characteristics
type TestMetadata struct {
	Category     TestCategory
	RequiresLDAP bool
	RequiresDB   bool
	CanParallel  bool
	Timeout      time.Duration
	Tags         []string
}

// GetTestMetadata determines test characteristics from test name and context
func GetTestMetadata(testName string) TestMetadata {
	metadata := TestMetadata{
		Category:     UnitTest,
		RequiresLDAP: false,
		RequiresDB:   false,
		CanParallel:  true,
		Timeout:      5 * time.Second,
		Tags:         []string{},
	}

	// Categorize tests based on naming patterns
	switch {
	case containsAny(testName, []string{"Integration", "integration"}):
		metadata.Category = IntegrationTest
		metadata.RequiresLDAP = true
		metadata.Timeout = 60 * time.Second
		metadata.CanParallel = false // Integration tests share containers
		metadata.Tags = append(metadata.Tags, "integration", "slow")

	case containsAny(testName, []string{"Benchmark", "benchmark"}):
		metadata.Category = BenchmarkTest
		metadata.Timeout = 30 * time.Second
		metadata.CanParallel = false // Benchmarks need isolated resources
		metadata.Tags = append(metadata.Tags, "benchmark", "performance")

	case containsAny(testName, []string{"Performance", "performance"}):
		metadata.Category = PerformanceTest
		metadata.RequiresLDAP = true
		metadata.Timeout = 120 * time.Second
		metadata.CanParallel = false
		metadata.Tags = append(metadata.Tags, "performance", "slow")

	case containsAny(testName, []string{"Auth", "auth", "Password", "password", "CheckPassword"}):
		// Authentication tests can be parallel if using shared container
		if containsAny(testName, []string{"Integration", "integration"}) {
			metadata.Category = IntegrationTest
			metadata.RequiresLDAP = true
			metadata.CanParallel = true // Auth tests can share read-only container
			metadata.Timeout = 30 * time.Second
		}
		metadata.Tags = append(metadata.Tags, "auth")

	case containsAny(testName, []string{"Pool", "pool", "Connection", "connection"}):
		// Pool tests may need integration
		if containsAny(testName, []string{"Integration", "integration"}) {
			metadata.Category = IntegrationTest
			metadata.RequiresLDAP = true
			metadata.CanParallel = false // Pool tests modify connection state
			metadata.Timeout = 45 * time.Second
		}
		metadata.Tags = append(metadata.Tags, "pool")

	case containsAny(testName, []string{"Cache", "cache"}):
		// Cache tests are usually unit tests
		metadata.Category = UnitTest
		metadata.CanParallel = true
		metadata.Tags = append(metadata.Tags, "cache")

	default:
		// Default unit test characteristics
		metadata.Tags = append(metadata.Tags, "unit")
	}

	return metadata
}

// OptimizedTestRunner provides test execution optimization
type OptimizedTestRunner struct {
	config       *TestRunnerConfig
	sharedCtx    context.Context
	cancel       context.CancelFunc
}

// NewOptimizedTestRunner creates a test runner with optimizations
func NewOptimizedTestRunner(config *TestRunnerConfig) *OptimizedTestRunner {
	if config == nil {
		config = DefaultTestConfig()
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)

	return &OptimizedTestRunner{
		config:    config,
		sharedCtx: ctx,
		cancel:    cancel,
	}
}

// RunTest executes a test with optimizations based on metadata
func (otr *OptimizedTestRunner) RunTest(t *testing.T, testFunc func(*testing.T)) {
	metadata := GetTestMetadata(t.Name())

	// Skip tests based on configuration
	if !otr.shouldRunTest(metadata) {
		t.Skipf("Skipping %s test (category: %v)", metadata.Tags, metadata.Category)
		return
	}

	// Note: Go's testing package doesn't allow setting deadlines programmatically
	// Test timeouts are handled via context and the test runner's timeout configuration

	// Enable parallel execution for safe tests
	if metadata.CanParallel && otr.config.EnableParallel {
		t.Parallel()
	}

	// Add test metadata to context
	ctx := context.WithValue(otr.sharedCtx, "test_metadata", metadata)
	ctx = context.WithValue(ctx, "test_name", t.Name())

	// Create timeout context for the test
	testCtx, testCancel := context.WithTimeout(ctx, metadata.Timeout)
	defer testCancel()

	// Store context in test for access by test functions
	if metadata.RequiresLDAP || metadata.Category == IntegrationTest {
		// Integration tests need special handling
		otr.runIntegrationTest(t, testCtx, testFunc)
	} else {
		// Unit tests run normally
		testFunc(t)
	}
}

// runIntegrationTest handles integration test execution with container management
func (otr *OptimizedTestRunner) runIntegrationTest(t *testing.T, ctx context.Context, testFunc func(*testing.T)) {
	// Check if we should use shared container
	if otr.config.ReuseContainers {
		// Integration tests using shared container
		t.Cleanup(func() {
			// Cleanup is handled by shared container
		})
	}

	testFunc(t)
}

// shouldRunTest determines if a test should run based on configuration
func (otr *OptimizedTestRunner) shouldRunTest(metadata TestMetadata) bool {
	switch metadata.Category {
	case UnitTest:
		return otr.config.RunUnitTests
	case IntegrationTest:
		return otr.config.RunIntegrationTests && !testing.Short()
	case BenchmarkTest, PerformanceTest:
		return otr.config.RunBenchmarks
	default:
		return true
	}
}

// Close cleans up the test runner
func (otr *OptimizedTestRunner) Close() {
	if otr.cancel != nil {
		otr.cancel()
	}
}

// Helper functions

func containsAny(str string, substrings []string) bool {
	for _, substr := range substrings {
		if len(str) >= len(substr) {
			for i := 0; i <= len(str)-len(substr); i++ {
				if str[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

// TestMain helper for optimized test execution
func OptimizedTestMain(m *testing.M) {
	// Parse test flags
	flag.Parse()

	// Set up optimized test environment
	config := DefaultTestConfig()

	// Override based on environment
	if os.Getenv("CI") != "" {
		// CI environment optimizations
		config.MaxParallelTests = 4
		config.TestTimeout = 60 * time.Second
		config.ReuseContainers = true
	}

	if testing.Short() {
		// Short mode optimizations
		config.RunIntegrationTests = false
		config.TestTimeout = 10 * time.Second
		config.MaxParallelTests = runtime.NumCPU()
	}

	// Set runtime parameters
	if config.EnableParallel {
		runtime.GOMAXPROCS(config.MaxParallelTests)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	if sharedContainer != nil {
		// Final cleanup of shared resources
		containerMu.Lock()
		if sharedContainer != nil {
			sharedContainer.cleanup(&testing.T{})
			sharedContainer = nil
		}
		containerMu.Unlock()
	}

	os.Exit(code)
}