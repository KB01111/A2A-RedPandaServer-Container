package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appauth "github.com/KB01111/A2A-RedPandaServer-Container/internal/auth"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultPageSize      = 50
	maximumPageSize      = 100
	defaultHistoryLength = 100
)

// Store is a PostgreSQL-backed A2A task store. All access is scoped to the
// verified tenant and subject carried by auth.Identity in the request context.
type Store struct {
	pool *pgxpool.Pool
}

var _ taskstore.Store = (*Store)(nil)

// NewStore creates a PostgreSQL task store.
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &Store{pool: pool}, nil
}

// Create persists a new task at version 1.
func (s *Store) Create(ctx context.Context, task *a2a.Task) (taskstore.TaskVersion, error) {
	if task == nil || task.ID == "" {
		return taskstore.TaskVersionMissing, fmt.Errorf("task and task ID are required: %w", a2a.ErrInvalidParams)
	}
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return taskstore.TaskVersionMissing, err
	}
	payload, err := marshalTask(task)
	if err != nil {
		return taskstore.TaskVersionMissing, err
	}

	var version int64
	err = s.pool.QueryRow(ctx, `
INSERT INTO a2a_tasks (
    task_id, tenant_id, owner_subject, context_id, state,
    status_timestamp, task_json, version
)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, 1)
ON CONFLICT (task_id) DO NOTHING
RETURNING version`,
		string(task.ID), identity.Tenant, identity.Subject, task.ContextID,
		string(task.Status.State), task.Status.Timestamp, string(payload),
	).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return taskstore.TaskVersionMissing, taskstore.ErrTaskAlreadyExists
	}
	if err != nil {
		return taskstore.TaskVersionMissing, fmt.Errorf("create task: %w", err)
	}
	return taskstore.TaskVersion(version), nil
}

// Update atomically replaces a task and increments its store version.
func (s *Store) Update(ctx context.Context, request *taskstore.UpdateRequest) (taskstore.TaskVersion, error) {
	if request == nil || request.Task == nil || request.Task.ID == "" {
		return taskstore.TaskVersionMissing, fmt.Errorf("task update and task ID are required: %w", a2a.ErrInvalidParams)
	}
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return taskstore.TaskVersionMissing, err
	}
	payload, err := marshalTask(request.Task)
	if err != nil {
		return taskstore.TaskVersionMissing, err
	}

	var updatedVersion taskstore.TaskVersion
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		var storedVersion int64
		err := tx.QueryRow(ctx, `
SELECT version
FROM a2a_tasks
WHERE task_id = $1 AND tenant_id = $2 AND owner_subject = $3
FOR UPDATE`, string(request.Task.ID), identity.Tenant, identity.Subject).Scan(&storedVersion)
		if errors.Is(err, pgx.ErrNoRows) {
			return a2a.ErrTaskNotFound
		}
		if err != nil {
			return fmt.Errorf("lock task for update: %w", err)
		}
		if request.PrevVersion != taskstore.TaskVersionMissing && int64(request.PrevVersion) != storedVersion {
			return taskstore.ErrConcurrentModification
		}

		var version int64
		if err := tx.QueryRow(ctx, `
UPDATE a2a_tasks
SET context_id = $4,
    state = $5,
    status_timestamp = $6,
    task_json = $7::jsonb,
    version = version + 1,
    updated_at = clock_timestamp()
WHERE task_id = $1 AND tenant_id = $2 AND owner_subject = $3
RETURNING version`,
			string(request.Task.ID), identity.Tenant, identity.Subject,
			request.Task.ContextID, string(request.Task.Status.State),
			request.Task.Status.Timestamp, string(payload),
		).Scan(&version); err != nil {
			return fmt.Errorf("update task: %w", err)
		}
		updatedVersion = taskstore.TaskVersion(version)
		return nil
	})
	if err != nil {
		return taskstore.TaskVersionMissing, err
	}
	return updatedVersion, nil
}

// Get returns the full stored task and its current version.
func (s *Store) Get(ctx context.Context, taskID a2a.TaskID) (*taskstore.StoredTask, error) {
	if taskID == "" {
		return nil, a2a.ErrTaskNotFound
	}
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return nil, err
	}

	var payload []byte
	var version int64
	var owner string
	err = s.pool.QueryRow(ctx, `
SELECT task_json, version, owner_subject
FROM a2a_tasks
WHERE task_id = $1 AND tenant_id = $2 AND owner_subject = $3`,
		string(taskID), identity.Tenant, identity.Subject,
	).Scan(&payload, &version, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, a2a.ErrTaskNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get task: %w", err)
	}
	task, err := unmarshalTask(payload)
	if err != nil {
		return nil, fmt.Errorf("decode stored task %q: %w", taskID, err)
	}
	return &taskstore.StoredTask{
		Task:    task,
		Version: taskstore.TaskVersion(version),
		User:    owner,
	}, nil
}

// List returns tasks ordered by most recent store update and scoped to the
// verified tenant and subject.
func (s *Store) List(ctx context.Context, request *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	if request == nil {
		return nil, fmt.Errorf("list request is required: %w", a2a.ErrInvalidRequest)
	}
	identity, err := verifiedIdentity(ctx)
	if err != nil {
		return nil, err
	}
	pageSize := request.PageSize
	if pageSize == 0 {
		pageSize = defaultPageSize
	} else if pageSize < 1 || pageSize > maximumPageSize {
		return nil, fmt.Errorf("page size must be between 1 and 100 inclusive, got %d: %w", pageSize, a2a.ErrInvalidRequest)
	}

	var cursorTime time.Time
	var cursorTaskID a2a.TaskID
	if request.PageToken != "" {
		cursorTime, cursorTaskID, err = decodePageToken(request.PageToken)
		if err != nil {
			return nil, err
		}
	}

	response := &a2a.ListTasksResponse{
		Tasks:    make([]*a2a.Task, 0, pageSize),
		PageSize: pageSize,
	}
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		where, args := listFilter(identity, request)
		var totalSize int64
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM a2a_tasks "+where, args...).Scan(&totalSize); err != nil {
			return fmt.Errorf("count tasks: %w", err)
		}
		if uint64(totalSize) > uint64(^uint(0)>>1) {
			return fmt.Errorf("task count %d exceeds platform integer capacity", totalSize)
		}
		response.TotalSize = int(totalSize)

		pageWhere, pageArgs := where, append([]any(nil), args...)
		if request.PageToken != "" {
			pageArgs = append(pageArgs, cursorTime, string(cursorTaskID))
			pageWhere += fmt.Sprintf(" AND (updated_at, task_id) < ($%d, $%d)", len(pageArgs)-1, len(pageArgs))
		}
		pageArgs = append(pageArgs, pageSize+1)
		query := `
SELECT task_id, task_json, updated_at
FROM a2a_tasks ` + pageWhere + fmt.Sprintf(`
ORDER BY updated_at DESC, task_id DESC
LIMIT $%d`, len(pageArgs))
		rows, err := tx.Query(ctx, query, pageArgs...)
		if err != nil {
			return fmt.Errorf("list tasks: %w", err)
		}
		defer rows.Close()

		type listedTask struct {
			task      *a2a.Task
			taskID    a2a.TaskID
			updatedAt time.Time
		}
		listed := make([]listedTask, 0, pageSize+1)
		for rows.Next() {
			var taskID string
			var payload []byte
			var updatedAt time.Time
			if err := rows.Scan(&taskID, &payload, &updatedAt); err != nil {
				return fmt.Errorf("scan listed task: %w", err)
			}
			task, err := unmarshalTask(payload)
			if err != nil {
				return fmt.Errorf("decode listed task %q: %w", taskID, err)
			}
			shapeListedTask(task, request)
			listed = append(listed, listedTask{task: task, taskID: a2a.TaskID(taskID), updatedAt: updatedAt})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate listed tasks: %w", err)
		}

		hasNextPage := len(listed) > pageSize
		if hasNextPage {
			listed = listed[:pageSize]
		}
		for _, item := range listed {
			response.Tasks = append(response.Tasks, item.task)
		}
		if hasNextPage {
			last := listed[len(listed)-1]
			response.NextPageToken = encodePageToken(last.updatedAt, last.taskID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func verifiedIdentity(ctx context.Context) (appauth.Identity, error) {
	identity, ok := appauth.IdentityFromContext(ctx)
	if !ok || strings.TrimSpace(identity.Tenant) == "" || strings.TrimSpace(identity.Subject) == "" {
		return appauth.Identity{}, a2a.ErrUnauthenticated
	}
	return identity, nil
}

func marshalTask(task *a2a.Task) ([]byte, error) {
	payload, err := json.Marshal(task)
	if err != nil {
		return nil, fmt.Errorf("encode task: %w", err)
	}
	return payload, nil
}

func unmarshalTask(payload []byte) (*a2a.Task, error) {
	var task a2a.Task
	if err := json.Unmarshal(payload, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

func listFilter(identity appauth.Identity, request *a2a.ListTasksRequest) (string, []any) {
	var builder strings.Builder
	builder.WriteString("WHERE tenant_id = $1 AND owner_subject = $2")
	args := []any{identity.Tenant, identity.Subject}
	if request.ContextID != "" {
		args = append(args, request.ContextID)
		fmt.Fprintf(&builder, " AND context_id = $%d", len(args))
	}
	if request.Status != a2a.TaskStateUnspecified {
		args = append(args, string(request.Status))
		fmt.Fprintf(&builder, " AND state = $%d", len(args))
	}
	if request.StatusTimestampAfter != nil {
		args = append(args, *request.StatusTimestampAfter)
		fmt.Fprintf(&builder, " AND (status_timestamp IS NULL OR status_timestamp >= $%d)", len(args))
	}
	return builder.String(), args
}

func shapeListedTask(task *a2a.Task, request *a2a.ListTasksRequest) {
	historyLength := defaultHistoryLength
	if request.HistoryLength != nil {
		historyLength = *request.HistoryLength
	}
	if historyLength == 0 {
		task.History = []*a2a.Message{}
	} else if historyLength > 0 && len(task.History) > historyLength {
		task.History = task.History[len(task.History)-historyLength:]
	}
	if !request.IncludeArtifacts {
		task.Artifacts = nil
	}
}
