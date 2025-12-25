//go:build ignore

package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	_ "modernc.org/sqlite"
)

func main() {
	fmt.Println("=== Clearing All Data ===")
	ctx := context.Background()

	// Clear ClickHouse data
	fmt.Println("\n[1/2] Clearing ClickHouse data...")
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{"127.0.0.1:9000"},
		Auth: clickhouse.Auth{
			Database: "cerberus",
			Username: "default",
			Password: "testpass123",
		},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		fmt.Printf("Failed to connect to ClickHouse: %v\n", err)
	} else {
		defer conn.Close()
		
		tables := []string{"events", "alerts", "alert_status_history", "soar_audit_log"}
		for _, table := range tables {
			if err := conn.Exec(ctx, fmt.Sprintf("TRUNCATE TABLE IF EXISTS %s", table)); err != nil {
				fmt.Printf("  Warning: Failed to truncate %s: %v\n", table, err)
			} else {
				fmt.Printf("  ✓ Truncated %s\n", table)
			}
		}
	}

	// Clear SQLite data
	fmt.Println("\n[2/2] Clearing SQLite data...")
	db, err := sql.Open("sqlite", "data/cerberus.db")
	if err != nil {
		fmt.Printf("Failed to open SQLite: %v\n", err)
		return
	}
	defer db.Close()

	sqliteTables := []string{"investigations", "investigation_alerts", "alert_links"}
	for _, table := range sqliteTables {
		if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			fmt.Printf("  Warning: Failed to clear %s: %v\n", table, err)
		} else {
			fmt.Printf("  ✓ Cleared %s\n", table)
		}
	}

	fmt.Println("\n=== All Data Cleared ===")
}
