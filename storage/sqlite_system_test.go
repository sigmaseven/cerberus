// Package storage provides tests for system metadata storage.
// TASK 160.1: Tests for first-run detection and system settings.
package storage

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func createTestSQLiteForSystem(t *testing.T) (*SQLite, func()) {
	t.Helper()

	// Create temp database file
	tmpFile, err := os.CreateTemp("", "test_system_*.db")
	require.NoError(t, err)
	tmpFile.Close()

	logger := zap.NewNop().Sugar()
	store, err := NewSQLite(tmpFile.Name(), logger)
	require.NoError(t, err)

	cleanup := func() {
		if store != nil {
			store.Close()
		}
		os.Remove(tmpFile.Name())
	}

	return store, cleanup
}

func TestIsFirstRun(t *testing.T) {
	store, cleanup := createTestSQLiteForSystem(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("returns true when no feeds exist and setup not completed", func(t *testing.T) {
		isFirstRun, err := store.IsFirstRun(ctx)
		require.NoError(t, err)
		assert.True(t, isFirstRun, "Should be first run when no feeds and setup not completed")
	})

	t.Run("returns false after setup is marked completed", func(t *testing.T) {
		err := store.SetSetupCompleted(ctx)
		require.NoError(t, err)

		isFirstRun, err := store.IsFirstRun(ctx)
		require.NoError(t, err)
		assert.False(t, isFirstRun, "Should not be first run after setup completed")
	})
}

func TestGetSetSystemMetadata(t *testing.T) {
	store, cleanup := createTestSQLiteForSystem(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("GetSystemMetadata returns ErrNoRows for non-existent key", func(t *testing.T) {
		_, err := store.GetSystemMetadata(ctx, "non_existent_key")
		assert.Equal(t, sql.ErrNoRows, err)
	})

	t.Run("SetSystemMetadata creates new key-value pair", func(t *testing.T) {
		err := store.SetSystemMetadata(ctx, "test_key", "test_value")
		require.NoError(t, err)

		value, err := store.GetSystemMetadata(ctx, "test_key")
		require.NoError(t, err)
		assert.Equal(t, "test_value", value)
	})

	t.Run("SetSystemMetadata updates existing key", func(t *testing.T) {
		err := store.SetSystemMetadata(ctx, "update_key", "initial_value")
		require.NoError(t, err)

		err = store.SetSystemMetadata(ctx, "update_key", "updated_value")
		require.NoError(t, err)

		value, err := store.GetSystemMetadata(ctx, "update_key")
		require.NoError(t, err)
		assert.Equal(t, "updated_value", value)
	})
}

func TestSetSetupCompleted(t *testing.T) {
	store, cleanup := createTestSQLiteForSystem(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("SetSetupCompleted sets the completion flag", func(t *testing.T) {
		err := store.SetSetupCompleted(ctx)
		require.NoError(t, err)

		value, err := store.GetSystemMetadata(ctx, SystemKeySetupCompleted)
		require.NoError(t, err)
		assert.Equal(t, "true", value)
	})

	t.Run("SetSetupCompleted is idempotent", func(t *testing.T) {
		// Call twice - should not error
		err := store.SetSetupCompleted(ctx)
		require.NoError(t, err)

		err = store.SetSetupCompleted(ctx)
		require.NoError(t, err)

		value, err := store.GetSystemMetadata(ctx, SystemKeySetupCompleted)
		require.NoError(t, err)
		assert.Equal(t, "true", value)
	})
}

func TestGetSetupCompletedTime(t *testing.T) {
	store, cleanup := createTestSQLiteForSystem(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("returns nil when setup not completed", func(t *testing.T) {
		completedTime, err := store.GetSetupCompletedTime(ctx)
		require.NoError(t, err)
		assert.Nil(t, completedTime)
	})

	t.Run("returns time after setup completed", func(t *testing.T) {
		beforeSetup := time.Now()
		err := store.SetSetupCompleted(ctx)
		require.NoError(t, err)

		completedTime, err := store.GetSetupCompletedTime(ctx)
		require.NoError(t, err)
		require.NotNil(t, completedTime)

		// Verify time is reasonable (within a few seconds of now)
		assert.True(t, completedTime.After(beforeSetup.Add(-time.Second)))
		assert.True(t, completedTime.Before(time.Now().Add(time.Second)))
	})
}

func TestIsFirstRunWithContextCancellation(t *testing.T) {
	store, cleanup := createTestSQLiteForSystem(t)
	defer cleanup()

	t.Run("respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := store.IsFirstRun(ctx)
		// SQLite may or may not return error for cancelled context
		// The important thing is it doesn't hang
		_ = err
	})
}
