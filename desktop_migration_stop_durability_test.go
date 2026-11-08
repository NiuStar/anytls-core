package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopMigrationStopAckDurableBeforeRead(t *testing.T) {
	m, _, c := migrationFixture(t)
	p, _ := m.inspect()
	read := m.stopRead
	m.stopRead = func(ctx context.Context, op *string) (st.ReadResponse, error) {
		files, _ := filepath.Glob(filepath.Join(m.home, ".anytls", ".desktop-migration-*", "stop-response.json"))
		if len(files) != 1 {
			t.Fatal("read occurred before durable ACK")
		}
		b, _, e := reloadCapture(files[0], m.uid)
		var a st.MutationResponse
		if e != nil || st.Decode(bytes.NewReader(b), &a) != nil || a.OperationID == nil || *a.OperationID != *op {
			t.Fatal("unbound durable ACK", e)
		}
		return read(ctx, op)
	}
	if _, e := m.commit(p.Plan); e != nil || *c != 1 {
		t.Fatal(e, *c)
	}
}
func TestDesktopMigrationStopEvidenceJournalFailure(t *testing.T) {
	m, _, c := migrationFixture(t)
	p, _ := m.inspect()
	m.journal = func(path string, b []byte, mode os.FileMode) error {
		var r desktopMigrationRecord
		if json.Unmarshal(b, &r) != nil {
			t.Fatal("record")
		}
		if r.StopResponseSHA256 != "" {
			return errors.New("fixture evidence fsync failure")
		}
		return controlInstallAtomic(path, b, mode)
	}
	if _, e := m.commit(p.Plan); e == nil || *c != 1 {
		t.Fatal("evidence journal fault ignored", e, *c)
	}
	if _, e := m.commit(p.Plan); e == nil || *c != 1 {
		t.Fatal("replayed uncertain stop", e, *c)
	}
	backups, _ := filepath.Glob(filepath.Join(m.home, ".anytls", ".desktop-migration-*", "old-binary"))
	if len(backups) != 0 {
		t.Fatal("backup before durable evidence")
	}
}
