package pool

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	// ErrPoolClosed is returned when attempting to use a closed connection pool
	ErrPoolClosed = errors.New("connection pool is closed")
	// ErrPoolExhausted is returned when the pool has reached max connections and timeout is reached
	ErrPoolExhausted = errors.New("connection pool exhausted")
	// ErrConnectionUnhealthy is returned when a connection fails health checks
	ErrConnectionUnhealthy = errors.New("connection is unhealthy")
)

// PoolConfig holds configuration options for the connection pool
type PoolConfig struct {
	// MaxConnections is the maximum number of concurrent connections (default: 10)
	MaxConnections int
	// MinConnections is the minimum number of idle connections to maintain (default: 2)
	MinConnections int
	// MaxIdleTime is the maximum time a connection can remain idle before cleanup (default: 5min)
	MaxIdleTime time.Duration
	// HealthCheckInterval is how frequently to check connection health (default: 30s)
	HealthCheckInterval time.Duration
	// ConnectionTimeout is the timeout for establishing new connections (default: 30s)
	ConnectionTimeout time.Duration
	// GetTimeout is the timeout for getting a connection from the pool (default: 10s)
	GetTimeout time.Duration
}

// DefaultPoolConfig returns a PoolConfig with sensible defaults
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxConnections:      10,
		MinConnections:      2,
		MaxIdleTime:         5 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		ConnectionTimeout:   30 * time.Second,
		GetTimeout:          10 * time.Second,
	}
}

// PoolStats provides statistics and metrics about the connection pool
type PoolStats struct {
	// ActiveConnections is the number of connections currently in use
	ActiveConnections int32
	// IdleConnections is the number of connections available in the pool
	IdleConnections int32
	// TotalConnections is the total number of connections (active + idle)
	TotalConnections int32
	// PoolHits is the number of successful connection retrievals from pool
	PoolHits int64
	// PoolMisses is the number of times new connections had to be created
	PoolMisses int64
	// HealthChecksPassed is the number of successful health checks
	HealthChecksPassed int64
	// HealthChecksFailed is the number of failed health checks
	HealthChecksFailed int64
	// ConnectionsCreated is the total number of connections created
	ConnectionsCreated int64
	// ConnectionsClosed is the total number of connections closed
	ConnectionsClosed int64
}

// pooledConnection wraps an LDAP connection with metadata for pool management
type pooledConnection struct {
	conn       *ldap.Conn
	createdAt  time.Time
	lastUsed   time.Time
	usageCount int64
	isHealthy  bool
	inUse      bool
}

// ConnectionPool manages a pool of LDAP connections with health monitoring and lifecycle management
type ConnectionPool struct {
	config     *PoolConfig
	ldapConfig Config
	user       string
	password   string
	logger     *slog.Logger

	// Pool management
	connections []*pooledConnection
	available   chan *pooledConnection
	mu          sync.RWMutex
	closed      bool

	// Statistics (atomic counters for thread safety)
	stats PoolStats

	// Background tasks
	healthCheckStop chan struct{}
	cleanupStop     chan struct{}
	wg              sync.WaitGroup

	// Connection tracking for proper cleanup
	connMap   map[*ldap.Conn]*pooledConnection
	connMapMu sync.Mutex
}

// NewConnectionPool creates a new connection pool with the specified configuration
func NewConnectionPool(config *PoolConfig, ldapConfig Config, user, password string, logger *slog.Logger) (*ConnectionPool, error) {
	if config == nil {
		config = DefaultPoolConfig()
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Validate configuration
	if config.MaxConnections <= 0 {
		config.MaxConnections = 10
	}
	if config.MinConnections < 0 {
		config.MinConnections = 0
	}
	if config.MinConnections > config.MaxConnections {
		config.MinConnections = config.MaxConnections
	}
	if config.MaxIdleTime <= 0 {
		config.MaxIdleTime = 5 * time.Minute
	}
	if config.HealthCheckInterval <= 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	if config.ConnectionTimeout <= 0 {
		config.ConnectionTimeout = 30 * time.Second
	}
	if config.GetTimeout <= 0 {
		config.GetTimeout = 10 * time.Second
	}

	pool := &ConnectionPool{
		config:          config,
		ldapConfig:      ldapConfig,
		user:            user,
		password:        password,
		logger:          logger,
		connections:     make([]*pooledConnection, 0, config.MaxConnections),
		available:       make(chan *pooledConnection, config.MaxConnections),
		healthCheckStop: make(chan struct{}),
		cleanupStop:     make(chan struct{}),
		connMap:         make(map[*ldap.Conn]*pooledConnection),
	}

	// Pre-warm the pool with minimum connections
	if err := pool.warmPool(context.Background()); err != nil {
		logger.Error("pool_warm_failed", slog.String("error", err.Error()))
		return nil, err
	}

	// Start background tasks
	pool.startBackgroundTasks()

	logger.Info("connection_pool_created",
		slog.Int("max_connections", config.MaxConnections),
		slog.Int("min_connections", config.MinConnections),
		slog.Duration("max_idle_time", config.MaxIdleTime),
		slog.Duration("health_check_interval", config.HealthCheckInterval))

	return pool, nil
}

// Get retrieves a connection from the pool, creating one if necessary
func (p *ConnectionPool) Get(ctx context.Context) (*ldap.Conn, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	p.mu.RUnlock()

	// Try to get connection with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, p.config.GetTimeout)
	defer cancel()

	select {
	case conn := <-p.available:
		if conn != nil && p.isConnectionHealthy(conn) {
			conn.inUse = true
			conn.lastUsed = time.Now()
			atomic.AddInt64(&conn.usageCount, 1)
			atomic.AddInt32(&p.stats.ActiveConnections, 1)
			atomic.AddInt32(&p.stats.IdleConnections, -1)
			atomic.AddInt64(&p.stats.PoolHits, 1)

			// Add to connection map for tracking
			p.connMapMu.Lock()
			p.connMap[conn.conn] = conn
			p.connMapMu.Unlock()

			p.logger.Debug("connection_retrieved_from_pool",
				slog.Time("created_at", conn.createdAt),
				slog.Int64("usage_count", conn.usageCount))

			return conn.conn, nil
		}
		// Connection was unhealthy, create a new one
		if conn != nil {
			p.closeConnection(conn)
		}
		// Try to create a new connection
		return p.createConnection(ctx)

	case <-timeoutCtx.Done():
		// No available connection, try to create new one
		return p.createConnection(ctx)

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(conn *ldap.Conn) error {
	if conn == nil {
		return nil
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		if err := conn.Close(); err != nil {
			p.logger.Debug("connection_close_error",
				slog.String("operation", "Put"),
				slog.String("error", err.Error()))
		}
		return ErrPoolClosed
	}
	p.mu.RUnlock()

	// Find the pooled connection wrapper
	p.connMapMu.Lock()
	pooledConn, exists := p.connMap[conn]
	if exists {
		delete(p.connMap, conn)
	}
	p.connMapMu.Unlock()

	if !exists {
		// Connection not from pool, close directly
		if err := conn.Close(); err != nil {
			p.logger.Debug("connection_close_error",
				slog.String("operation", "Put"),
				slog.String("error", err.Error()))
		}
		return nil
	}

	pooledConn.inUse = false
	pooledConn.lastUsed = time.Now()

	// Check if connection is still healthy before returning to pool
	if p.isConnectionHealthy(pooledConn) {
		select {
		case p.available <- pooledConn:
			atomic.AddInt32(&p.stats.ActiveConnections, -1)
			atomic.AddInt32(&p.stats.IdleConnections, 1)
			p.logger.Debug("connection_returned_to_pool",
				slog.Time("last_used", pooledConn.lastUsed),
				slog.Int64("usage_count", pooledConn.usageCount))
			return nil
		default:
			// Pool is full, close the connection
			p.closeConnection(pooledConn)
			atomic.AddInt32(&p.stats.ActiveConnections, -1)
			return nil
		}
	} else {
		// Connection is unhealthy, close it
		p.closeConnection(pooledConn)
		atomic.AddInt32(&p.stats.ActiveConnections, -1)
		return nil
	}
}

// Stats returns current pool statistics
func (p *ConnectionPool) Stats() PoolStats {
	return PoolStats{
		ActiveConnections:  atomic.LoadInt32(&p.stats.ActiveConnections),
		IdleConnections:    atomic.LoadInt32(&p.stats.IdleConnections),
		TotalConnections:   atomic.LoadInt32(&p.stats.TotalConnections),
		PoolHits:           atomic.LoadInt64(&p.stats.PoolHits),
		PoolMisses:         atomic.LoadInt64(&p.stats.PoolMisses),
		HealthChecksPassed: atomic.LoadInt64(&p.stats.HealthChecksPassed),
		HealthChecksFailed: atomic.LoadInt64(&p.stats.HealthChecksFailed),
		ConnectionsCreated: atomic.LoadInt64(&p.stats.ConnectionsCreated),
		ConnectionsClosed:  atomic.LoadInt64(&p.stats.ConnectionsClosed),
	}
}

// Close shuts down the pool and closes all connections
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	// Stop background tasks
	close(p.healthCheckStop)
	close(p.cleanupStop)
	p.wg.Wait()

	// Close all connections
	p.mu.Lock()
	defer p.mu.Unlock()

	// Drain available channel
	for {
		select {
		case conn := <-p.available:
			if conn != nil {
				p.closeConnection(conn)
			}
		default:
			goto closeDirect
		}
	}

closeDirect:
	// Close any remaining connections
	for _, conn := range p.connections {
		if conn != nil && conn.conn != nil {
			p.closeConnection(conn)
		}
	}

	p.connections = nil
	close(p.available)

	p.logger.Info("connection_pool_closed",
		slog.Int64("total_created", atomic.LoadInt64(&p.stats.ConnectionsCreated)),
		slog.Int64("total_closed", atomic.LoadInt64(&p.stats.ConnectionsClosed)))

	return nil
}

// warmPool pre-populates the pool with minimum connections
func (p *ConnectionPool) warmPool(ctx context.Context) error {
	for i := 0; i < p.config.MinConnections; i++ {
		_, err := p.createConnection(ctx)
		if err != nil {
			p.logger.Error("pool_warm_connection_failed",
				slog.Int("attempt", i+1),
				slog.String("error", err.Error()))
			return err
		}
	}

	p.logger.Debug("pool_warmed",
		slog.Int("connections_created", p.config.MinConnections))

	return nil
}

// createConnection creates a new LDAP connection and adds it to the pool
func (p *ConnectionPool) createConnection(ctx context.Context) (*ldap.Conn, error) {
	// Check if we've reached max connections
	p.mu.RLock()
	currentTotal := len(p.connections)
	p.mu.RUnlock()

	if currentTotal >= p.config.MaxConnections {
		atomic.AddInt64(&p.stats.PoolMisses, 1)
		return nil, ErrPoolExhausted
	}

	// Create connection with timeout
	connCtx, cancel := context.WithTimeout(ctx, p.config.ConnectionTimeout)
	defer cancel()

	start := time.Now()
	p.logger.Debug("creating_new_connection",
		slog.String("server", p.ldapConfig.Server))

	dialOpts := make([]ldap.DialOpt, 0)
	if p.ldapConfig.DialOptions != nil {
		dialOpts = p.ldapConfig.DialOptions
	}

	// Check for context cancellation before dialing
	select {
	case <-connCtx.Done():
		return nil, connCtx.Err()
	default:
	}

	conn, err := ldap.DialURL(p.ldapConfig.Server, dialOpts...)
	if err != nil {
		p.logger.Error("connection_dial_failed",
			slog.String("server", p.ldapConfig.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	// Check for context cancellation before binding
	select {
	case <-connCtx.Done():
		if err := conn.Close(); err != nil {
			p.logger.Debug("connection_close_error",
				slog.String("operation", "createConnection"),
				slog.String("error", err.Error()))
		}
		return nil, connCtx.Err()
	default:
	}

	if err = conn.Bind(p.user, p.password); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			p.logger.Debug("connection_close_error",
				slog.String("operation", "createConnection"),
				slog.String("error", closeErr.Error()))
		}
		p.logger.Error("connection_bind_failed",
			slog.String("server", p.ldapConfig.Server),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(start)))
		return nil, err
	}

	// Wrap connection for pool management
	pooledConn := &pooledConnection{
		conn:       conn,
		createdAt:  time.Now(),
		lastUsed:   time.Now(),
		usageCount: 1,
		isHealthy:  true,
		inUse:      true,
	}

	// Add to pool
	p.mu.Lock()
	p.connections = append(p.connections, pooledConn)
	p.mu.Unlock()

	// Add to connection map for tracking
	p.connMapMu.Lock()
	p.connMap[conn] = pooledConn
	p.connMapMu.Unlock()

	// Update statistics
	atomic.AddInt32(&p.stats.ActiveConnections, 1)
	atomic.AddInt32(&p.stats.TotalConnections, 1)
	atomic.AddInt64(&p.stats.ConnectionsCreated, 1)
	atomic.AddInt64(&p.stats.PoolMisses, 1)

	p.logger.Debug("connection_created",
		slog.String("server", p.ldapConfig.Server),
		slog.Duration("duration", time.Since(start)),
		slog.Int("total_connections", int(atomic.LoadInt32(&p.stats.TotalConnections))))

	return conn, nil
}

// isConnectionHealthy checks if a connection is still usable
func (p *ConnectionPool) isConnectionHealthy(conn *pooledConnection) bool {
	if conn == nil || conn.conn == nil {
		return false
	}

	// Check if connection has been idle too long
	if time.Since(conn.lastUsed) > p.config.MaxIdleTime {
		p.logger.Debug("connection_idle_too_long",
			slog.Duration("idle_time", time.Since(conn.lastUsed)),
			slog.Duration("max_idle", p.config.MaxIdleTime))
		return false
	}

	// Perform a simple bind operation to test connection health
	// We'll use a no-op search as it's less intrusive than re-binding
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a minimal search request to test connection
	searchReq := &ldap.SearchRequest{
		BaseDN:       p.ldapConfig.BaseDN,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
		Attributes:   []string{"1.1"}, // Request no attributes for efficiency
		SizeLimit:    1,
	}

	done := make(chan bool, 1)
	var searchErr error

	go func() {
		_, searchErr = conn.conn.Search(searchReq)
		done <- true
	}()

	select {
	case <-done:
		healthy := searchErr == nil
		if healthy {
			atomic.AddInt64(&p.stats.HealthChecksPassed, 1)
		} else {
			atomic.AddInt64(&p.stats.HealthChecksFailed, 1)
			p.logger.Debug("connection_health_check_failed",
				slog.String("error", searchErr.Error()),
				slog.Time("created_at", conn.createdAt))
		}
		conn.isHealthy = healthy
		return healthy
	case <-ctx.Done():
		atomic.AddInt64(&p.stats.HealthChecksFailed, 1)
		p.logger.Debug("connection_health_check_timeout",
			slog.Time("created_at", conn.createdAt))
		conn.isHealthy = false
		return false
	}
}

// closeConnection safely closes a pooled connection and updates statistics
func (p *ConnectionPool) closeConnection(conn *pooledConnection) {
	if conn == nil || conn.conn == nil {
		return
	}

	// Remove from connection map
	p.connMapMu.Lock()
	delete(p.connMap, conn.conn)
	p.connMapMu.Unlock()

	if err := conn.conn.Close(); err != nil {
		p.logger.Debug("connection_close_error",
			slog.String("error", err.Error()))
	}
	atomic.AddInt32(&p.stats.TotalConnections, -1)
	atomic.AddInt64(&p.stats.ConnectionsClosed, 1)

	// Remove from connections slice
	for i, c := range p.connections {
		if c == conn {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}

	p.logger.Debug("connection_closed",
		slog.Time("created_at", conn.createdAt),
		slog.Int64("usage_count", conn.usageCount),
		slog.Duration("lifetime", time.Since(conn.createdAt)))
}

// startBackgroundTasks starts health checking and cleanup routines
func (p *ConnectionPool) startBackgroundTasks() {
	// Health check routine
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.config.HealthCheckInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.performHealthChecks()
			case <-p.healthCheckStop:
				return
			}
		}
	}()

	// Cleanup routine for idle connections
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(p.config.MaxIdleTime / 2) // Check twice per idle period
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.cleanupIdleConnections()
			case <-p.cleanupStop:
				return
			}
		}
	}()
}

// performHealthChecks checks health of idle connections
func (p *ConnectionPool) performHealthChecks() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	var unhealthyConnections []*pooledConnection

	// Check connections in available channel (idle connections)
	availableCount := len(p.available)
	for i := 0; i < availableCount; i++ {
		select {
		case conn := <-p.available:
			if conn != nil && !p.isConnectionHealthy(conn) {
				unhealthyConnections = append(unhealthyConnections, conn)
			} else if conn != nil {
				// Return healthy connection to pool
				select {
				case p.available <- conn:
				default:
					// Pool is full, close connection
					p.closeConnection(conn)
				}
			}
		default:
		}
	}

	// Close unhealthy connections
	for _, conn := range unhealthyConnections {
		p.closeConnection(conn)
		atomic.AddInt32(&p.stats.IdleConnections, -1)

		// Try to maintain minimum connections
		if len(p.connections) < p.config.MinConnections {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), p.config.ConnectionTimeout)
				defer cancel()
				_, err := p.createConnection(ctx)
				if err != nil {
					p.logger.Debug("health_check_replacement_failed",
						slog.String("error", err.Error()))
				}
			}()
		}
	}

	if len(unhealthyConnections) > 0 {
		p.logger.Debug("health_check_completed",
			slog.Int("unhealthy_removed", len(unhealthyConnections)),
			slog.Int("total_connections", int(atomic.LoadInt32(&p.stats.TotalConnections))))
	}
}

// cleanupIdleConnections removes connections that have been idle too long
func (p *ConnectionPool) cleanupIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	currentTotal := len(p.connections)
	if currentTotal <= p.config.MinConnections {
		return // Don't go below minimum
	}

	var cleanedUp int
	availableCount := len(p.available)

	for i := 0; i < availableCount && currentTotal > p.config.MinConnections; i++ {
		select {
		case conn := <-p.available:
			if conn != nil && time.Since(conn.lastUsed) > p.config.MaxIdleTime {
				p.closeConnection(conn)
				atomic.AddInt32(&p.stats.IdleConnections, -1)
				cleanedUp++
				currentTotal--
			} else if conn != nil {
				// Return non-expired connection to pool
				select {
				case p.available <- conn:
				default:
					// Pool is full, this shouldn't happen but handle it
					p.closeConnection(conn)
					atomic.AddInt32(&p.stats.IdleConnections, -1)
				}
			}
		default:
		}
	}

	if cleanedUp > 0 {
		p.logger.Debug("idle_connections_cleaned",
			slog.Int("cleaned_up", cleanedUp),
			slog.Int("remaining_total", int(atomic.LoadInt32(&p.stats.TotalConnections))))
	}
}
