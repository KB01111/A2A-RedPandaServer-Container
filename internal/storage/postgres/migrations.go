package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationTable = "a2a_schema_migrations"
	// Stable, application-specific advisory lock ID for schema migrations.
	migrationLockID int64 = 0x4132415f50475f4d
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	version  int64
	name     string
	contents string
	checksum [sha256.Size]byte
}

type appliedMigration struct {
	name     string
	checksum []byte
}

// CurrentSchemaVersion returns the highest embedded migration version.
func CurrentSchemaVersion() int64 {
	migrations, err := readMigrations()
	if err != nil || len(migrations) == 0 {
		return 0
	}
	return migrations[len(migrations)-1].version
}

// Migrate applies all pending forward-only migrations while holding a
// PostgreSQL session advisory lock. Applied migration checksums are immutable.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (resultErr error) {
	if pool == nil {
		return fmt.Errorf("PostgreSQL pool is required")
	}
	migrations, err := readMigrations()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		destroyMigrationConnection(conn)
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		if err := releaseMigrationLock(conn); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()

	if _, err := conn.Exec(ctx, `
CREATE TABLE IF NOT EXISTS a2a_schema_migrations (
    version bigint PRIMARY KEY,
    name text NOT NULL,
    checksum bytea NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	applied, err := loadAppliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	if err := verifyMigrationSet(migrations, applied, true); err != nil {
		return err
	}

	for _, item := range migrations {
		if _, ok := applied[item.version]; ok {
			continue
		}
		if err := applyMigration(ctx, conn, item); err != nil {
			return err
		}
	}
	return nil
}

// VerifySchema verifies that every embedded migration, and no unknown
// migration, is recorded with its original checksum.
func VerifySchema(ctx context.Context, pool *pgxpool.Pool) (resultErr error) {
	if pool == nil {
		return fmt.Errorf("PostgreSQL pool is required")
	}
	migrations, err := readMigrations()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire schema verification connection: %w", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		destroyMigrationConnection(conn)
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		if err := releaseMigrationLock(conn); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()

	var ledgerName *string
	if err := conn.QueryRow(ctx, "SELECT to_regclass(current_schema() || '.' || $1)::text", migrationTable).Scan(&ledgerName); err != nil {
		return fmt.Errorf("locate migration ledger: %w", err)
	}
	if ledgerName == nil {
		return fmt.Errorf("database schema is not initialized")
	}
	applied, err := loadAppliedMigrations(ctx, conn)
	if err != nil {
		return err
	}
	return verifyMigrationSet(migrations, applied, false)
}

func readMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	result := make([]migration, 0, len(entries))
	seen := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		separator := strings.IndexByte(entry.Name(), '_')
		if separator < 1 {
			return nil, fmt.Errorf("migration %q has no numeric version prefix", entry.Name())
		}
		version, err := strconv.ParseInt(entry.Name()[:separator], 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has an invalid version", entry.Name())
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf("migrations %q and %q use duplicate version %d", previous, entry.Name(), version)
		}
		contents, err := fs.ReadFile(migrationFiles, "migrations/"+entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		if len(bytes.TrimSpace(contents)) == 0 {
			return nil, fmt.Errorf("migration %q is empty", entry.Name())
		}
		seen[version] = entry.Name()
		result = append(result, migration{
			version:  version,
			name:     entry.Name(),
			contents: string(contents),
			checksum: sha256.Sum256(contents),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	if len(result) == 0 {
		return nil, fmt.Errorf("no embedded migrations found")
	}
	return result, nil
}

type migrationQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadAppliedMigrations(ctx context.Context, queryer migrationQuerier) (map[int64]appliedMigration, error) {
	rows, err := queryer.Query(ctx, "SELECT version, name, checksum FROM "+migrationTable+" ORDER BY version")
	if err != nil {
		return nil, fmt.Errorf("read migration ledger: %w", err)
	}
	defer rows.Close()

	applied := make(map[int64]appliedMigration)
	for rows.Next() {
		var version int64
		var item appliedMigration
		if err := rows.Scan(&version, &item.name, &item.checksum); err != nil {
			return nil, fmt.Errorf("scan migration ledger: %w", err)
		}
		applied[version] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration ledger: %w", err)
	}
	return applied, nil
}

func verifyMigrationSet(migrations []migration, applied map[int64]appliedMigration, allowPending bool) error {
	embedded := make(map[int64]migration, len(migrations))
	var maxApplied int64
	for _, item := range migrations {
		embedded[item.version] = item
	}
	for version, recorded := range applied {
		item, ok := embedded[version]
		if !ok {
			return fmt.Errorf("database contains unknown migration version %d", version)
		}
		if recorded.name != item.name {
			return fmt.Errorf("migration version %d name mismatch: database has %q, binary has %q", version, recorded.name, item.name)
		}
		if !bytes.Equal(recorded.checksum, item.checksum[:]) {
			return fmt.Errorf("migration %q checksum mismatch", item.name)
		}
		if version > maxApplied {
			maxApplied = version
		}
	}
	for _, item := range migrations {
		if _, ok := applied[item.version]; ok {
			continue
		}
		if item.version <= maxApplied {
			return fmt.Errorf("migration ledger has a gap at version %d", item.version)
		}
		if !allowPending {
			return fmt.Errorf("database schema is behind: migration %q is pending", item.name)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, conn *pgxpool.Conn, item migration) error {
	err := pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, item.contents); err != nil {
			return fmt.Errorf("execute migration %q: %w", item.name, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO "+migrationTable+" (version, name, checksum) VALUES ($1, $2, $3)",
			item.version, item.name, item.checksum[:],
		); err != nil {
			return fmt.Errorf("record migration %q: %w", item.name, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func releaseMigrationLock(conn *pgxpool.Conn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var unlocked bool
	if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID).Scan(&unlocked); err != nil {
		destroyMigrationConnection(conn)
		return fmt.Errorf("release migration advisory lock: %w", err)
	}
	if !unlocked {
		destroyMigrationConnection(conn)
		return fmt.Errorf("release migration advisory lock: lock was not held")
	}
	conn.Release()
	return nil
}

func destroyMigrationConnection(conn *pgxpool.Conn) {
	raw := conn.Hijack()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = raw.Close(ctx)
}
