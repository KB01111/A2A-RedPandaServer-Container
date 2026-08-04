package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestPageTokenRoundTrip(t *testing.T) {
	wantTime := time.Date(2026, 8, 4, 12, 13, 14, 123456000, time.FixedZone("test", 2*60*60))
	wantTaskID := a2a.TaskID("task_with_underscores")

	token := encodePageToken(wantTime, wantTaskID)
	gotTime, gotTaskID, err := decodePageToken(token)
	if err != nil {
		t.Fatalf("decodePageToken() error = %v", err)
	}
	if !gotTime.Equal(wantTime) {
		t.Fatalf("decoded time = %v, want %v", gotTime, wantTime)
	}
	if gotTaskID != wantTaskID {
		t.Fatalf("decoded task ID = %q, want %q", gotTaskID, wantTaskID)
	}
}

func TestPageTokenRejectsMalformedValues(t *testing.T) {
	tests := []string{
		"not-base64",
		"MjAyNi0wOC0wNFQxMjowMDowMFo=", // timestamp without task ID
		"bm90LWEtdGltZV90YXNr",         // malformed timestamp
	}
	for _, token := range tests {
		_, _, err := decodePageToken(token)
		if !errors.Is(err, a2a.ErrParseError) {
			t.Errorf("decodePageToken(%q) error = %v, want ErrParseError", token, err)
		}
	}
}

func TestShapeListedTask(t *testing.T) {
	history := make([]*a2a.Message, 105)
	for i := range history {
		history[i] = &a2a.Message{ID: string(rune('a' + i%26))}
	}
	artifact := &a2a.Artifact{ID: "artifact"}

	task := &a2a.Task{History: append([]*a2a.Message(nil), history...), Artifacts: []*a2a.Artifact{artifact}}
	shapeListedTask(task, &a2a.ListTasksRequest{})
	if len(task.History) != defaultHistoryLength || task.History[0] != history[5] {
		t.Fatalf("default history length = %d, want last %d", len(task.History), defaultHistoryLength)
	}
	if task.Artifacts != nil {
		t.Fatal("artifacts were not omitted")
	}

	zero := 0
	task = &a2a.Task{History: history}
	shapeListedTask(task, &a2a.ListTasksRequest{HistoryLength: &zero})
	if task.History == nil || len(task.History) != 0 {
		t.Fatalf("zero history = %#v, want non-nil empty slice", task.History)
	}

	negative := -1
	task = &a2a.Task{History: history, Artifacts: []*a2a.Artifact{artifact}}
	shapeListedTask(task, &a2a.ListTasksRequest{HistoryLength: &negative, IncludeArtifacts: true})
	if len(task.History) != len(history) || len(task.Artifacts) != 1 {
		t.Fatalf("unlimited shaping lost data: history=%d artifacts=%d", len(task.History), len(task.Artifacts))
	}
}
