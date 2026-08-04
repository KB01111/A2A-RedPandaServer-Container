// Package webhook implements durable A2A push-notification delivery.
package webhook

import (
	"context"
	"errors"
	"time"
)

// DeliveryID is an immutable, externally visible delivery identifier. The
// same value is reused for every retry so receivers can de-duplicate safely.
type DeliveryID string

// FailureKind is a low-cardinality, secret-free delivery failure category.
type FailureKind string

const (
	FailureNetwork            FailureKind = "network"
	FailureTimeout            FailureKind = "timeout"
	FailureResponseStatus     FailureKind = "response_status"
	FailureRedirect           FailureKind = "redirect"
	FailureInvalidTarget      FailureKind = "invalid_target"
	FailureInvalidCredentials FailureKind = "invalid_credentials"
	FailureInvalidDelivery    FailureKind = "invalid_delivery"
)

// NewDelivery contains the immutable fields written when a notification is
// enqueued. Repository implementations must reject an existing ID and must
// never update these fields after insertion.
type NewDelivery struct {
	ID                   DeliveryID
	Tenant               string
	TaskID               string
	ConfigID             string
	TargetURL            string
	Payload              []byte
	EncryptedCredentials []byte
	CreatedAt            time.Time
	AvailableAt          time.Time
}

// Delivery is a delivery leased by a worker. Attempts is the number of
// completed attempts before this lease was acquired.
type Delivery struct {
	NewDelivery
	Attempts   int
	LeaseToken string
	LeaseUntil time.Time
}

// ClaimRequest asks the repository to atomically lease ready deliveries.
// ClaimReady must commit its leasing transaction before it returns; webhook
// HTTP requests are deliberately performed only after this method returns.
type ClaimRequest struct {
	WorkerID      string
	LeaseToken    string
	Now           time.Time
	LeaseDuration time.Duration
	Limit         int
}

// DeliverySuccess completes a leased delivery.
type DeliverySuccess struct {
	Tenant     string
	ID         DeliveryID
	LeaseToken string
	Attempt    int
	HTTPStatus int
	FinishedAt time.Time
}

// DeliveryRetry returns a leased delivery to the ready queue at NextAttempt.
type DeliveryRetry struct {
	Tenant      string
	ID          DeliveryID
	LeaseToken  string
	Attempt     int
	HTTPStatus  int
	Failure     FailureKind
	NextAttempt time.Time
	FinishedAt  time.Time
}

// DeliveryDead permanently completes a delivery that cannot or must not be
// retried.
type DeliveryDead struct {
	Tenant     string
	ID         DeliveryID
	LeaseToken string
	Attempt    int
	HTTPStatus int
	Failure    FailureKind
	FinishedAt time.Time
}

// Repository is the complete persistence surface required by this package.
// All methods must scope rows by Tenant and ID. Completion methods must use
// LeaseToken as a compare-and-swap guard and return ErrLeaseLost when it no
// longer owns the row.
type Repository interface {
	EnqueueDelivery(context.Context, NewDelivery) error
	ClaimReady(context.Context, ClaimRequest) ([]Delivery, error)
	MarkSucceeded(context.Context, DeliverySuccess) error
	MarkRetry(context.Context, DeliveryRetry) error
	MarkDead(context.Context, DeliveryDead) error
}

// ErrLeaseLost indicates that another worker reclaimed a delivery before the
// current worker could complete it.
var ErrLeaseLost = errors.New("webhook delivery lease lost")
