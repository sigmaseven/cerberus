package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// SQLiteDynamicListenerStorage handles dynamic listener CRUD operations in SQLite
type SQLiteDynamicListenerStorage struct {
	db     *SQLite
	logger *zap.SugaredLogger
}

// NewSQLiteDynamicListenerStorage creates a new SQLite dynamic listener storage handler
func NewSQLiteDynamicListenerStorage(db *SQLite, logger *zap.SugaredLogger) (*SQLiteDynamicListenerStorage, error) {
	storage := &SQLiteDynamicListenerStorage{
		db:     db,
		logger: logger,
	}

	// Ensure listeners table exists
	if err := storage.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure listeners table: %w", err)
	}

	return storage, nil
}

// ensureTable creates the dynamic_listeners table if it doesn't exist
func (sls *SQLiteDynamicListenerStorage) ensureTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS dynamic_listeners (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		type TEXT NOT NULL,
		protocol TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		tls BOOLEAN NOT NULL DEFAULT 0,
		cert_file TEXT,
		key_file TEXT,
		status TEXT NOT NULL DEFAULT 'stopped',
		tags TEXT,
		source TEXT,
		events_received INTEGER NOT NULL DEFAULT 0,
		error_count INTEGER NOT NULL DEFAULT 0,
		last_event DATETIME,
		created_at DATETIME NOT NULL,
		created_by TEXT,
		updated_at DATETIME NOT NULL,
		started_at DATETIME,
		stopped_at DATETIME,
		UNIQUE(host, port, protocol)
	);

	CREATE INDEX IF NOT EXISTS idx_listeners_status ON dynamic_listeners(status);
	CREATE INDEX IF NOT EXISTS idx_listeners_type ON dynamic_listeners(type);
	CREATE INDEX IF NOT EXISTS idx_listeners_port ON dynamic_listeners(port);
	`

	_, err := sls.db.DB.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create dynamic_listeners table: %w", err)
	}

	sls.logger.Info("Dynamic listeners table ensured in SQLite")
	return nil
}

// CreateListener creates a new dynamic listener
func (sls *SQLiteDynamicListenerStorage) CreateListener(listener *DynamicListener) error {
	// Serialize tags to JSON
	tagsJSON, _ := json.Marshal(listener.Tags)

	listener.CreatedAt = time.Now()
	listener.UpdatedAt = time.Now()

	query := `
		INSERT INTO dynamic_listeners (
			id, name, description, type, protocol, host, port,
			tls, cert_file, key_file, status, tags, source,
			events_received, error_count, last_event,
			created_at, created_by, updated_at, started_at, stopped_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := sls.db.DB.Exec(query,
		listener.ID,
		listener.Name,
		listener.Description,
		listener.Type,
		listener.Protocol,
		listener.Host,
		listener.Port,
		listener.TLS,
		listener.CertFile,
		listener.KeyFile,
		listener.Status,
		string(tagsJSON),
		listener.Source,
		listener.EventsReceived,
		listener.ErrorCount,
		listener.LastEvent,
		listener.CreatedAt,
		listener.CreatedBy,
		listener.UpdatedAt,
		listener.StartedAt,
		listener.StoppedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to insert listener: %w", err)
	}

	sls.logger.Infof("Created dynamic listener: %s (%s)", listener.Name, listener.ID)
	return nil
}

// GetListener retrieves a listener by ID
func (sls *SQLiteDynamicListenerStorage) GetListener(id string) (*DynamicListener, error) {
	query := `
		SELECT
			id, name, description, type, protocol, host, port,
			tls, cert_file, key_file, status, tags, source,
			events_received, error_count, last_event,
			created_at, created_by, updated_at, started_at, stopped_at
		FROM dynamic_listeners
		WHERE id = ?
	`

	var listener DynamicListener
	var tagsJSON string
	var lastEvent, startedAt, stoppedAt sql.NullTime
	var certFile, keyFile, description, source, createdBy sql.NullString

	err := sls.db.ReadDB.QueryRow(query, id).Scan(
		&listener.ID,
		&listener.Name,
		&description,
		&listener.Type,
		&listener.Protocol,
		&listener.Host,
		&listener.Port,
		&listener.TLS,
		&certFile,
		&keyFile,
		&listener.Status,
		&tagsJSON,
		&source,
		&listener.EventsReceived,
		&listener.ErrorCount,
		&lastEvent,
		&listener.CreatedAt,
		&createdBy,
		&listener.UpdatedAt,
		&startedAt,
		&stoppedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query listener: %w", err)
	}

	// Deserialize tags
	if tagsJSON != "" {
		json.Unmarshal([]byte(tagsJSON), &listener.Tags)
	}

	// Handle nullable fields
	if description.Valid {
		listener.Description = description.String
	}
	if certFile.Valid {
		listener.CertFile = certFile.String
	}
	if keyFile.Valid {
		listener.KeyFile = keyFile.String
	}
	if source.Valid {
		listener.Source = source.String
	}
	if createdBy.Valid {
		listener.CreatedBy = createdBy.String
	}
	if lastEvent.Valid {
		listener.LastEvent = lastEvent.Time
	}
	if startedAt.Valid {
		listener.StartedAt = startedAt.Time
	}
	if stoppedAt.Valid {
		listener.StoppedAt = stoppedAt.Time
	}

	return &listener, nil
}

// GetAllListeners retrieves all dynamic listeners
func (sls *SQLiteDynamicListenerStorage) GetAllListeners() ([]*DynamicListener, error) {
	query := `
		SELECT
			id, name, description, type, protocol, host, port,
			tls, cert_file, key_file, status, tags, source,
			events_received, error_count, last_event,
			created_at, created_by, updated_at, started_at, stopped_at
		FROM dynamic_listeners
		ORDER BY created_at DESC
	`

	rows, err := sls.db.ReadDB.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query listeners: %w", err)
	}
	defer rows.Close()

	listeners := make([]*DynamicListener, 0)
	for rows.Next() {
		var listener DynamicListener
		var tagsJSON string
		var lastEvent, startedAt, stoppedAt sql.NullTime
		var certFile, keyFile, description, source, createdBy sql.NullString

		err := rows.Scan(
			&listener.ID,
			&listener.Name,
			&description,
			&listener.Type,
			&listener.Protocol,
			&listener.Host,
			&listener.Port,
			&listener.TLS,
			&certFile,
			&keyFile,
			&listener.Status,
			&tagsJSON,
			&source,
			&listener.EventsReceived,
			&listener.ErrorCount,
			&lastEvent,
			&listener.CreatedAt,
			&createdBy,
			&listener.UpdatedAt,
			&startedAt,
			&stoppedAt,
		)
		if err != nil {
			sls.logger.Errorf("Failed to scan listener: %v", err)
			continue
		}

		// Deserialize tags
		if tagsJSON != "" {
			json.Unmarshal([]byte(tagsJSON), &listener.Tags)
		}

		// Handle nullable fields
		if description.Valid {
			listener.Description = description.String
		}
		if certFile.Valid {
			listener.CertFile = certFile.String
		}
		if keyFile.Valid {
			listener.KeyFile = keyFile.String
		}
		if source.Valid {
			listener.Source = source.String
		}
		if createdBy.Valid {
			listener.CreatedBy = createdBy.String
		}
		if lastEvent.Valid {
			listener.LastEvent = lastEvent.Time
		}
		if startedAt.Valid {
			listener.StartedAt = startedAt.Time
		}
		if stoppedAt.Valid {
			listener.StoppedAt = stoppedAt.Time
		}

		listeners = append(listeners, &listener)
	}

	return listeners, nil
}

// GetListenersByStatus retrieves listeners by status
func (sls *SQLiteDynamicListenerStorage) GetListenersByStatus(status string) ([]*DynamicListener, error) {
	query := `
		SELECT
			id, name, description, type, protocol, host, port,
			tls, cert_file, key_file, status, tags, source,
			events_received, error_count, last_event,
			created_at, created_by, updated_at, started_at, stopped_at
		FROM dynamic_listeners
		WHERE status = ?
		ORDER BY created_at DESC
	`

	rows, err := sls.db.ReadDB.Query(query, status)
	if err != nil {
		return nil, fmt.Errorf("failed to query listeners by status: %w", err)
	}
	defer rows.Close()

	listeners := make([]*DynamicListener, 0)
	for rows.Next() {
		var listener DynamicListener
		var tagsJSON string
		var lastEvent, startedAt, stoppedAt sql.NullTime
		var certFile, keyFile, description, source, createdBy sql.NullString

		err := rows.Scan(
			&listener.ID,
			&listener.Name,
			&description,
			&listener.Type,
			&listener.Protocol,
			&listener.Host,
			&listener.Port,
			&listener.TLS,
			&certFile,
			&keyFile,
			&listener.Status,
			&tagsJSON,
			&source,
			&listener.EventsReceived,
			&listener.ErrorCount,
			&lastEvent,
			&listener.CreatedAt,
			&createdBy,
			&listener.UpdatedAt,
			&startedAt,
			&stoppedAt,
		)
		if err != nil {
			sls.logger.Errorf("Failed to scan listener: %v", err)
			continue
		}

		// Deserialize tags
		if tagsJSON != "" {
			json.Unmarshal([]byte(tagsJSON), &listener.Tags)
		}

		// Handle nullable fields
		if description.Valid {
			listener.Description = description.String
		}
		if certFile.Valid {
			listener.CertFile = certFile.String
		}
		if keyFile.Valid {
			listener.KeyFile = keyFile.String
		}
		if source.Valid {
			listener.Source = source.String
		}
		if createdBy.Valid {
			listener.CreatedBy = createdBy.String
		}
		if lastEvent.Valid {
			listener.LastEvent = lastEvent.Time
		}
		if startedAt.Valid {
			listener.StartedAt = startedAt.Time
		}
		if stoppedAt.Valid {
			listener.StoppedAt = stoppedAt.Time
		}

		listeners = append(listeners, &listener)
	}

	return listeners, nil
}

// UpdateListener updates a listener
func (sls *SQLiteDynamicListenerStorage) UpdateListener(id string, listener *DynamicListener) error {
	listener.UpdatedAt = time.Now()

	// Serialize tags
	tagsJSON, _ := json.Marshal(listener.Tags)

	query := `
		UPDATE dynamic_listeners
		SET
			name = ?,
			description = ?,
			type = ?,
			protocol = ?,
			host = ?,
			port = ?,
			tls = ?,
			cert_file = ?,
			key_file = ?,
			status = ?,
			tags = ?,
			source = ?,
			events_received = ?,
			error_count = ?,
			last_event = ?,
			updated_at = ?,
			started_at = ?,
			stopped_at = ?
		WHERE id = ?
	`

	result, err := sls.db.DB.Exec(query,
		listener.Name,
		listener.Description,
		listener.Type,
		listener.Protocol,
		listener.Host,
		listener.Port,
		listener.TLS,
		listener.CertFile,
		listener.KeyFile,
		listener.Status,
		string(tagsJSON),
		listener.Source,
		listener.EventsReceived,
		listener.ErrorCount,
		listener.LastEvent,
		listener.UpdatedAt,
		listener.StartedAt,
		listener.StoppedAt,
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update listener: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("listener not found: %s", id)
	}

	sls.logger.Infof("Updated dynamic listener: %s", id)
	return nil
}

// UpdateListenerStatus updates just the status field
func (sls *SQLiteDynamicListenerStorage) UpdateListenerStatus(id string, status string) error {
	query := `
		UPDATE dynamic_listeners
		SET status = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := sls.db.DB.Exec(query, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update listener status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("listener not found: %s", id)
	}

	return nil
}

// UpdateStatistics updates listener statistics
func (sls *SQLiteDynamicListenerStorage) UpdateStatistics(id string, stats *ListenerStats) error {
	query := `
		UPDATE dynamic_listeners
		SET events_received = ?, error_count = ?, last_event = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := sls.db.DB.Exec(query,
		stats.EventsReceived,
		stats.ErrorCount,
		stats.LastEvent,
		time.Now(),
		id,
	)

	if err != nil {
		return fmt.Errorf("failed to update statistics: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("listener not found: %s", id)
	}

	return nil
}

// IncrementEventCount increments the event counter
func (sls *SQLiteDynamicListenerStorage) IncrementEventCount(id string) error {
	query := `
		UPDATE dynamic_listeners
		SET events_received = events_received + 1, last_event = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := sls.db.DB.Exec(query, time.Now(), time.Now(), id)
	return err
}

// IncrementErrorCount increments the error counter
func (sls *SQLiteDynamicListenerStorage) IncrementErrorCount(id string) error {
	query := `
		UPDATE dynamic_listeners
		SET error_count = error_count + 1, updated_at = ?
		WHERE id = ?
	`

	_, err := sls.db.DB.Exec(query, time.Now(), id)
	return err
}

// SetStartedAt sets the started timestamp
func (sls *SQLiteDynamicListenerStorage) SetStartedAt(id string, startedAt time.Time) error {
	query := `
		UPDATE dynamic_listeners
		SET started_at = ?, stopped_at = NULL, updated_at = ?
		WHERE id = ?
	`

	_, err := sls.db.DB.Exec(query, startedAt, time.Now(), id)
	return err
}

// SetStoppedAt sets the stopped timestamp
func (sls *SQLiteDynamicListenerStorage) SetStoppedAt(id string, stoppedAt time.Time) error {
	query := `
		UPDATE dynamic_listeners
		SET stopped_at = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := sls.db.DB.Exec(query, stoppedAt, time.Now(), id)
	return err
}

// DeleteListener deletes a listener
func (sls *SQLiteDynamicListenerStorage) DeleteListener(id string) error {
	query := "DELETE FROM dynamic_listeners WHERE id = ?"

	result, err := sls.db.DB.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete listener: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("listener not found: %s", id)
	}

	sls.logger.Infof("Deleted dynamic listener: %s", id)
	return nil
}

// CheckPortConflict checks if a port is already in use
func (sls *SQLiteDynamicListenerStorage) CheckPortConflict(host string, port int, protocol string, excludeID string) (bool, error) {
	query := "SELECT COUNT(*) FROM dynamic_listeners WHERE host = ? AND port = ? AND protocol = ?"
	args := []interface{}{host, port, protocol}

	// Exclude the listener being updated
	if excludeID != "" {
		query += " AND id != ?"
		args = append(args, excludeID)
	}

	var count int
	err := sls.db.ReadDB.QueryRow(query, args...).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check port conflict: %w", err)
	}

	return count > 0, nil
}
