package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	appauth "github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/config"
	"github.com/KB01111/A2A-RedPandaServer-Container/internal/orchestrator"
	appserver "github.com/KB01111/A2A-RedPandaServer-Container/internal/server"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresStoreCRUDIsolationAndCAS(t *testing.T) {
	store, _ := newIntegrationStore(t)
	alice := identityContext("tenant-a", "alice")
	bob := identityContext("tenant-a", "bob")
	otherTenant := identityContext("tenant-b", "alice")
	otherIssuer := identityContextWithIssuer("https://new-issuer.example.test", "tenant-a", "alice")
	task := &a2a.Task{
		ID:        "crud-task",
		ContextID: "context-1",
		Status:    a2a.TaskStatus{State: a2a.TaskStateSubmitted},
		History:   []*a2a.Message{a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("hello"))},
		Artifacts: []*a2a.Artifact{{ID: "artifact-1", Parts: []*a2a.Part{a2a.NewTextPart("result")}}},
	}

	version, err := store.Create(alice, task)
	if err != nil || version != 1 {
		t.Fatalf("Create() = %d, %v", version, err)
	}
	if _, err := store.Create(bob, task); !errors.Is(err, taskstore.ErrTaskAlreadyExists) {
		t.Fatalf("duplicate Create() error = %v", err)
	}
	for name, ctx := range map[string]context.Context{"different owner": bob, "different tenant": otherTenant, "different issuer": otherIssuer} {
		if _, err := store.Get(ctx, task.ID); !errors.Is(err, a2a.ErrTaskNotFound) {
			t.Errorf("%s Get() error = %v", name, err)
		}
		if _, err := store.Update(ctx, &taskstore.UpdateRequest{Task: task, PrevVersion: version}); !errors.Is(err, a2a.ErrTaskNotFound) {
			t.Errorf("%s Update() error = %v", name, err)
		}
		listed, err := store.List(ctx, &a2a.ListTasksRequest{})
		if err != nil || listed.TotalSize != 0 || len(listed.Tasks) != 0 {
			t.Errorf("%s List() = %#v, %v", name, listed, err)
		}
	}

	task.ContextID = "context-2"
	version, err = store.Update(alice, &taskstore.UpdateRequest{Task: task, PrevVersion: version})
	if err != nil || version != 2 {
		t.Fatalf("Update() = %d, %v", version, err)
	}
	if _, err := store.Update(alice, &taskstore.UpdateRequest{Task: task, PrevVersion: 1}); !errors.Is(err, taskstore.ErrConcurrentModification) {
		t.Fatalf("stale Update() error = %v", err)
	}
	stored, err := store.Get(alice, task.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	wantOwner := appauth.OwnerKey(appauth.Identity{Issuer: "https://issuer.example.test", Tenant: "tenant-a", Subject: "alice"})
	if stored.Version != 2 || stored.User != wantOwner || stored.Task.ContextID != "context-2" || len(stored.Task.Artifacts) != 1 {
		t.Fatalf("stored task = %#v", stored)
	}
}

func TestPostgresStoreListSemantics(t *testing.T) {
	store, pool := newIntegrationStore(t)
	ctx := identityContext("tenant-list", "owner")
	cutoff := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	old := cutoff.Add(-time.Minute)
	tasks := []*a2a.Task{
		{ID: "list-a", ContextID: "ctx", Status: a2a.TaskStatus{State: a2a.TaskStateWorking, Timestamp: &old}},
		{ID: "list-b", ContextID: "ctx", Status: a2a.TaskStatus{State: a2a.TaskStateWorking}, History: []*a2a.Message{{ID: "b1"}}, Artifacts: []*a2a.Artifact{{ID: "b-artifact"}}},
		{ID: "list-c", ContextID: "ctx", Status: a2a.TaskStatus{State: a2a.TaskStateWorking, Timestamp: &cutoff}, History: []*a2a.Message{{ID: "c1"}}, Artifacts: []*a2a.Artifact{{ID: "c-artifact"}}},
	}
	for _, task := range tasks {
		if _, err := store.Create(ctx, task); err != nil {
			t.Fatalf("Create(%s) error = %v", task.ID, err)
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE a2a_tasks SET updated_at = $1", cutoff); err != nil {
		t.Fatal(err)
	}

	zero := 0
	first, err := store.List(ctx, &a2a.ListTasksRequest{
		ContextID:            "ctx",
		Status:               a2a.TaskStateWorking,
		StatusTimestampAfter: &cutoff,
		PageSize:             1,
		HistoryLength:        &zero,
	})
	if err != nil {
		t.Fatalf("first List() error = %v", err)
	}
	if first.TotalSize != 2 || first.PageSize != 1 || len(first.Tasks) != 1 || first.Tasks[0].ID != "list-c" || first.NextPageToken == "" {
		t.Fatalf("first page = %#v", first)
	}
	if first.Tasks[0].History == nil || len(first.Tasks[0].History) != 0 || first.Tasks[0].Artifacts != nil {
		t.Fatalf("first task shaping = %#v", first.Tasks[0])
	}
	second, err := store.List(ctx, &a2a.ListTasksRequest{
		ContextID:            "ctx",
		Status:               a2a.TaskStateWorking,
		StatusTimestampAfter: &cutoff,
		PageSize:             1,
		PageToken:            first.NextPageToken,
	})
	if err != nil {
		t.Fatalf("second List() error = %v", err)
	}
	if second.TotalSize != 2 || len(second.Tasks) != 1 || second.Tasks[0].ID != "list-b" || second.NextPageToken != "" {
		t.Fatalf("second page = %#v", second)
	}

	unlimited := -1
	full, err := store.List(ctx, &a2a.ListTasksRequest{HistoryLength: &unlimited, IncludeArtifacts: true})
	if err != nil {
		t.Fatalf("full List() error = %v", err)
	}
	if full.TotalSize != 3 || len(full.Tasks) != 3 || len(full.Tasks[0].Artifacts) != 1 || len(full.Tasks[0].History) != 1 {
		t.Fatalf("full list = %#v", full)
	}
	if _, err := store.List(ctx, &a2a.ListTasksRequest{PageSize: 101}); !errors.Is(err, a2a.ErrInvalidRequest) {
		t.Fatalf("invalid page size error = %v", err)
	}
	if _, err := store.List(ctx, &a2a.ListTasksRequest{PageToken: "invalid"}); !errors.Is(err, a2a.ErrParseError) {
		t.Fatalf("invalid page token error = %v", err)
	}
}

func TestPostgresStoreConcurrentVersions(t *testing.T) {
	store, _ := newIntegrationStore(t)
	ctx := identityContext("tenant-concurrency", "owner")
	task := &a2a.Task{ID: "concurrent-task", ContextID: "ctx", Status: a2a.TaskStatus{State: a2a.TaskStateWorking}}
	version, err := store.Create(ctx, task)
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 12
	var wg sync.WaitGroup
	errorsOut := make(chan error, contenders)
	versions := make(chan taskstore.TaskVersion, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := *task
			candidate.ContextID = fmt.Sprintf("cas-%d", i)
			got, err := store.Update(ctx, &taskstore.UpdateRequest{Task: &candidate, PrevVersion: version})
			if err != nil {
				errorsOut <- err
				return
			}
			versions <- got
		}()
	}
	wg.Wait()
	close(errorsOut)
	close(versions)
	if len(versions) != 1 {
		t.Fatalf("CAS successes = %d, want 1", len(versions))
	}
	for err := range errorsOut {
		if !errors.Is(err, taskstore.ErrConcurrentModification) {
			t.Fatalf("CAS error = %v", err)
		}
	}

	const unconditional = 20
	versions = make(chan taskstore.TaskVersion, unconditional)
	for i := range unconditional {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := *task
			candidate.ContextID = fmt.Sprintf("unconditional-%d", i)
			got, err := store.Update(ctx, &taskstore.UpdateRequest{Task: &candidate})
			if err != nil {
				t.Errorf("unconditional Update() error = %v", err)
				return
			}
			versions <- got
		}()
	}
	wg.Wait()
	close(versions)
	gotVersions := make([]int, 0, unconditional)
	for got := range versions {
		gotVersions = append(gotVersions, int(got))
	}
	sort.Ints(gotVersions)
	if len(gotVersions) != unconditional || gotVersions[0] != 3 || gotVersions[len(gotVersions)-1] != 2+unconditional {
		t.Fatalf("unconditional versions = %v", gotVersions)
	}
}

func TestPostgresMigrationsAreIdempotentAndVerified(t *testing.T) {
	_, pool := newIntegrationStore(t)
	ctx := context.Background()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}
	if err := VerifySchema(ctx, pool); err != nil {
		t.Fatalf("VerifySchema() error = %v", err)
	}
	if _, err := pool.Exec(ctx, "UPDATE a2a_schema_migrations SET checksum = decode('00', 'hex') WHERE version = 1"); err != nil {
		t.Fatal(err)
	}
	if err := VerifySchema(ctx, pool); err == nil {
		t.Fatal("VerifySchema() accepted a modified checksum")
	}
}

func TestPostgresStoreA2AHTTPIdentityPropagation(t *testing.T) {
	store, _ := newIntegrationStore(t)
	authenticator, err := appauth.NewAuthenticator(httpTestVerifier{}, "https://issuer.example.test", []string{"a2a"})
	if err != nil {
		t.Fatal(err)
	}
	cardPath := filepath.Join(t.TempDir(), "agent-card.json")
	card := `{
  "capabilities":{"streaming":true},
  "defaultInputModes":["text/plain"],
  "defaultOutputModes":["text/plain"],
  "description":"integration agent",
  "name":"integration agent",
  "skills":[{"description":"test","id":"test","name":"test","tags":["test"]}],
  "supportedInterfaces":[{"url":"http://invalid.local","protocolBinding":"HTTP+JSON","protocolVersion":"1.0"}],
  "version":"test"
}`
	if err := os.WriteFile(cardPath, []byte(card), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := appserver.New(config.Config{
		Environment:     "test",
		PublicBaseURL:   "https://a2a.example.test",
		AgentCardPath:   cardPath,
		MaxRequestBytes: 1 << 20,
	}, appserver.Dependencies{
		Dispatcher:     orchestrator.LoopbackDispatcher{},
		TaskStore:      store,
		Authentication: authenticator,
	})
	if err != nil {
		t.Fatal(err)
	}
	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	payload, err := json.Marshal(a2a.SendMessageRequest{
		Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("persist me")),
	})
	if err != nil {
		t.Fatal(err)
	}
	sendRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, testServer.URL+"/message:send", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	sendRequest.Header.Set("Content-Type", "application/json")
	sendRequest.Header.Set(a2a.SvcParamVersion, string(a2a.Version))
	sendRequest.Header.Set("Authorization", "Bearer tenant-a-token")
	sendResponse, err := testServer.Client().Do(sendRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sendResponse.Body.Close() }()
	if sendResponse.StatusCode != http.StatusOK {
		t.Fatalf("send status = %d", sendResponse.StatusCode)
	}
	var result a2a.StreamResponse
	if err := json.NewDecoder(sendResponse.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	task, ok := result.Event.(*a2a.Task)
	if !ok || task.ID == "" {
		t.Fatalf("send result = %#v", result.Event)
	}

	for _, test := range []struct {
		token  string
		status int
	}{
		{token: "tenant-a-token", status: http.StatusOK},
		{token: "tenant-b-token", status: http.StatusNotFound},
	} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, testServer.URL+"/tasks/"+string(task.ID), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(a2a.SvcParamVersion, string(a2a.Version))
		request.Header.Set("Authorization", "Bearer "+test.token)
		response, err := testServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("GET with %s status = %d, want %d", test.token, response.StatusCode, test.status)
		}
	}
}

type httpTestVerifier struct{}

func (httpTestVerifier) Verify(_ context.Context, token string) (appauth.Identity, error) {
	var tenant string
	switch token {
	case "tenant-a-token":
		tenant = "tenant-a"
	case "tenant-b-token":
		tenant = "tenant-b"
	default:
		return appauth.Identity{}, appauth.ErrInvalidToken
	}
	return appauth.Identity{
		Issuer:  "https://issuer.example.test",
		Subject: "same-subject",
		Tenant:  tenant,
		Scopes:  []string{"a2a"},
	}, nil
}

func newIntegrationStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open integration database: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping integration database: %v", err)
	}

	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "a2a_it_" + hex.EncodeToString(random)
	if _, err := admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		admin.Close()
		t.Fatalf("create integration schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if len(schema) == len("a2a_it_")+16 {
			_, _ = admin.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
		}
		admin.Close()
	})

	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := VerifySchema(ctx, pool); err != nil {
		t.Fatalf("VerifySchema() error = %v", err)
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}

func identityContext(tenant, subject string) context.Context {
	return identityContextWithIssuer("https://issuer.example.test", tenant, subject)
}

func identityContextWithIssuer(issuer, tenant, subject string) context.Context {
	return appauth.WithIdentity(context.Background(), appauth.Identity{
		Issuer:  issuer,
		Tenant:  tenant,
		Subject: subject,
	})
}
