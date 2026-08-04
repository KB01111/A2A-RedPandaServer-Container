package postgres

import (
	"testing"
)

func TestEmbeddedMigrationsAreOrderedAndChecksummed(t *testing.T) {
	migrations, err := readMigrations()
	if err != nil {
		t.Fatalf("readMigrations() error = %v", err)
	}
	if len(migrations) != 1 || migrations[0].version != 1 || CurrentSchemaVersion() != 1 {
		t.Fatalf("migrations = %#v, current = %d", migrations, CurrentSchemaVersion())
	}

	applied := map[int64]appliedMigration{
		migrations[0].version: {name: migrations[0].name, checksum: migrations[0].checksum[:]},
	}
	if err := verifyMigrationSet(migrations, applied, false); err != nil {
		t.Fatalf("verifyMigrationSet() error = %v", err)
	}
	if err := verifyMigrationSet(migrations, nil, true); err != nil {
		t.Fatalf("pending migration was rejected during migrate: %v", err)
	}
	if err := verifyMigrationSet(migrations, nil, false); err == nil {
		t.Fatal("pending migration passed schema verification")
	}

	applied[migrations[0].version] = appliedMigration{name: migrations[0].name, checksum: []byte("tampered")}
	if err := verifyMigrationSet(migrations, applied, false); err == nil {
		t.Fatal("tampered checksum passed verification")
	}
}
