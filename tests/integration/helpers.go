package integration

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"cerberus/config"
	"cerberus/core"
	"cerberus/storage"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
)

// Container configuration constants
const (
	clickhouseImage       = "clickhouse/clickhouse-server:latest"
	clickhouseNativePort  = "9000/tcp"
	clickhouseHTTPPort    = "8123/tcp"
	testDatabaseName      = "cerberus_integration_test"
	containerStartTimeout = 120 * time.Second
)

// TestInfrastructure holds all test dependencies (containers, connections, etc.)
type TestInfrastructure struct {
	ClickHouseContainer testcontainers.Container
	ClickHouse          *storage.ClickHouse
	ClickHouseConfig    *config.Config
	Redis               *miniredis.Miniredis
	RedisCache          *core.RedisCache
	Logger              *zap.SugaredLogger
	Cleanup             func()
}

// SetupTestInfrastructure creates all test dependencies (ClickHouse container, Redis, etc.)
// TASK 61.1: Setup testcontainers infrastructure for integration tests
func SetupTestInfrastructure(t *testing.T) *TestInfrastructure {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	// Setup ClickHouse container
	clickHouseContainer := setupClickHouseContainer(t, ctx)

	// Create ClickHouse connection
	host, err := clickHouseContainer.Host(ctx)
	require.NoError(t, err, "Failed to get ClickHouse container host")

	mappedPort, err := clickHouseContainer.MappedPort(ctx, "9000")
	require.NoError(t, err, "Failed to get ClickHouse mapped port")

	clickHouseConfig := &config.Config{}
	clickHouseConfig.ClickHouse.Addr = fmt.Sprintf("%s:%s", host, mappedPort.Port())
	clickHouseConfig.ClickHouse.Database = testDatabaseName
	clickHouseConfig.ClickHouse.Username = "default"
	clickHouseConfig.ClickHouse.Password = "testpassword"
	clickHouseConfig.ClickHouse.TLS = false
	clickHouseConfig.ClickHouse.MaxPoolSize = 10
	clickHouseConfig.ClickHouse.BatchSize = 1000
	clickHouseConfig.ClickHouse.FlushInterval = 5

	clickHouse, err := storage.NewClickHouse(clickHouseConfig, logger)
	require.NoError(t, err, "Failed to create ClickHouse connection")

	// Setup miniredis for Redis
	redis := miniredis.RunT(t)
	// Note: RedisCache may not be needed for all tests - can be nil if not used
	var redisCache *core.RedisCache
	// Uncomment if RedisCache is actually needed:
	// redisCache = core.NewRedisCache(
	// 	redis.Addr(), // miniredis provides a real address
	// 	"",           // no password
	// 	0,            // default DB
	// 	10,           // pool size
	// 	logger,
	// )

	cleanup := func() {
		// Cleanup ClickHouse container
		if err := clickHouseContainer.Terminate(ctx); err != nil {
			t.Logf("Warning: failed to terminate ClickHouse container: %v", err)
		}
		// Cleanup Redis
		redis.Close()
		// Close ClickHouse connection
		if clickHouse != nil && clickHouse.Conn != nil {
			clickHouse.Conn.Close()
		}
	}

	infra := &TestInfrastructure{
		ClickHouseContainer: clickHouseContainer,
		ClickHouse:          clickHouse,
		ClickHouseConfig:    clickHouseConfig,
		Redis:               redis,
		RedisCache:          redisCache,
		Logger:              logger,
		Cleanup:             cleanup,
	}

	// Register cleanup with test
	t.Cleanup(cleanup)

	return infra
}

// setupClickHouseContainer creates and starts a ClickHouse testcontainer
func setupClickHouseContainer(t *testing.T, ctx context.Context) testcontainers.Container {
	req := testcontainers.ContainerRequest{
		Image:        clickhouseImage,
		ExposedPorts: []string{clickhouseNativePort, clickhouseHTTPPort},
		Env: map[string]string{
			"CLICKHOUSE_DB":                        testDatabaseName,
			"CLICKHOUSE_USER":                      "default",
			"CLICKHOUSE_PASSWORD":                  "testpassword",
			"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1",
		},
		// Wait for ClickHouse HTTP port to be ready
		WaitingFor: wait.ForHTTP("/").
			WithPort(clickhouseHTTPPort).
			WithStartupTimeout(containerStartTimeout).
			WithResponseMatcher(func(body io.Reader) bool {
				// ClickHouse returns "Ok." for root path when ready
				buf, _ := io.ReadAll(body)
				return len(buf) > 0
			}),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "Failed to start ClickHouse container")

	t.Logf("ClickHouse container started successfully")
	return container
}

// CleanupTestData removes all test data from ClickHouse and Redis
// TASK 61.7: Test cleanup and isolation
func (ti *TestInfrastructure) CleanupTestData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Truncate events table if it exists
	query := fmt.Sprintf("TRUNCATE TABLE IF EXISTS %s.events", testDatabaseName)
	if err := ti.ClickHouse.Conn.Exec(ctx, query); err != nil {
		t.Logf("Warning: failed to truncate events table: %v", err)
	}

	// Truncate alerts table if it exists
	query = fmt.Sprintf("TRUNCATE TABLE IF EXISTS %s.alerts", testDatabaseName)
	if err := ti.ClickHouse.Conn.Exec(ctx, query); err != nil {
		t.Logf("Warning: failed to truncate alerts table: %v", err)
	}

	// Clear Redis cache
	ti.Redis.FlushAll()
}

// GetClickHouseAddr returns the ClickHouse address for the test container
func (ti *TestInfrastructure) GetClickHouseAddr() string {
	return ti.ClickHouseConfig.ClickHouse.Addr
}

// GetRedisAddr returns the Redis address (for miniredis)
func (ti *TestInfrastructure) GetRedisAddr() string {
	return ti.Redis.Addr()
}
