package postgres

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreOrderedAndChecksummed(t *testing.T) {
	migrations, err := readMigrations()
	if err != nil {
		t.Fatalf("readMigrations() error = %v", err)
	}
	if len(migrations) != 2 || migrations[0].version != 1 || migrations[1].version != 2 || CurrentSchemaVersion() != 2 {
		t.Fatalf("migrations = %#v, current = %d", migrations, CurrentSchemaVersion())
	}

	applied := map[int64]appliedMigration{
		migrations[0].version: {name: migrations[0].name, checksum: migrations[0].checksum[:]},
		migrations[1].version: {name: migrations[1].name, checksum: migrations[1].checksum[:]},
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
	partial := map[int64]appliedMigration{
		migrations[0].version: {name: migrations[0].name, checksum: migrations[0].checksum[:]},
	}
	if err := verifyMigrationSet(migrations, partial, true); err != nil {
		t.Fatalf("forward pending migration was rejected during migrate: %v", err)
	}
	if err := verifyMigrationSet(migrations, partial, false); err == nil {
		t.Fatal("forward pending migration passed schema verification")
	}

	applied[migrations[0].version] = appliedMigration{name: migrations[0].name, checksum: []byte("tampered")}
	if err := verifyMigrationSet(migrations, applied, false); err == nil {
		t.Fatal("tampered checksum passed verification")
	}
}

func TestVerifyMigrationSetRejectsLedgerGap(t *testing.T) {
	firstChecksum := sha256.Sum256([]byte("first"))
	secondChecksum := sha256.Sum256([]byte("second"))
	migrations := []migration{
		{version: 1, name: "0001_first.sql", checksum: firstChecksum},
		{version: 2, name: "0002_second.sql", checksum: secondChecksum},
	}
	applied := map[int64]appliedMigration{
		2: {name: migrations[1].name, checksum: migrations[1].checksum[:]},
	}
	if err := verifyMigrationSet(migrations, applied, true); err == nil || !strings.Contains(err.Error(), "gap") {
		t.Fatalf("verifyMigrationSet() error = %v, want ledger gap", err)
	}
}
