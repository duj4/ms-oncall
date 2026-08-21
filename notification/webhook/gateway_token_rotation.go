package webhook

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

const (
	gatewayDestinationTokenRotationMaxHandleBytes = 4096
	gatewayDestinationTokenRotationBeginLimit     = 5 * time.Second
	gatewayDestinationTokenRotationCASLimit       = 5 * time.Second
	gatewayDestinationTokenRotationDiscardLimit   = 5 * time.Second
	gatewayDestinationTokenRotationRecoveryLimit  = 5 * time.Second
	gatewayDestinationTokenRotationReleaseLimit   = 5 * time.Second
	gatewayDestinationTokenRotationMaxOverlap     = 24 * time.Hour
)

var (
	ErrGatewayDestinationTokenRotationInvalid                = errors.New("gateway destination token rotation invalid")
	ErrGatewayDestinationTokenRotationPermissionDenied       = errors.New("gateway destination token rotation permission denied")
	ErrGatewayDestinationTokenRotationConflict               = errors.New("gateway destination token rotation conflict")
	ErrGatewayDestinationTokenRotationUnavailable            = errors.New("gateway destination token rotation unavailable")
	ErrGatewayDestinationTokenRotationOutcomeUnknown         = errors.New("gateway destination token rotation outcome unknown")
	ErrGatewayDestinationTokenRotationReconciliationRequired = errors.New("gateway destination token rotation reconciliation required")
	ErrGatewayDestinationTokenRotationCanceled               = errors.New("gateway destination token rotation canceled")
	ErrGatewayDestinationTokenRotationDeadlineExceeded       = errors.New("gateway destination token rotation deadline exceeded")
	ErrGatewayDestinationTokenRotationTooEarly               = errors.New("gateway destination token rotation too early")
	errGatewayDestinationTokenRotationSerializationUncertain = errors.New("gateway destination token rotation serialization domain uncertain")
	errGatewayDestinationTokenRotationQuarantineUnconfirmed  = errors.New("gateway destination token rotation physical quarantine unconfirmed")
)

// GatewayDestinationID is the canonical Gateway destination binding used by
// the transport-independent rotation participant port. It always formats as
// redacted.
type GatewayDestinationID struct {
	redactedValue
	value string
}

// NewGatewayDestinationID validates a non-zero canonical Gateway destination
// UUID without performing a Gateway lookup.
func NewGatewayDestinationID(value string) (GatewayDestinationID, error) {
	parsed, ok := parseCanonicalUUID(value, false)
	if !ok || parsed == uuid.Nil {
		return GatewayDestinationID{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return GatewayDestinationID{value: value}, nil
}

// GatewayDestinationTokenRotationStartRequest is the opaque, sensitive input
// for one rotation attempt. Validation occurs in Start.
type GatewayDestinationTokenRotationStartRequest struct {
	redactedValue
	contactMethodID uuid.UUID
	expectedURL     string
	audience        string
	destination     string
}

// NewGatewayDestinationTokenRotationStartRequest constructs an opaque start
// request from the complete expected Core destination and Gateway binding.
func NewGatewayDestinationTokenRotationStartRequest(
	contactMethodID uuid.UUID,
	expectedURL string,
	audience string,
	destination string,
) GatewayDestinationTokenRotationStartRequest {
	return GatewayDestinationTokenRotationStartRequest{
		contactMethodID: contactMethodID,
		expectedURL:     strings.Clone(expectedURL),
		audience:        strings.Clone(audience),
		destination:     strings.Clone(destination),
	}
}

// GatewayDestinationTokenRotationParticipantHandle is an opaque exact-attempt
// handle understood only by the trusted Gateway participant adapter.
type GatewayDestinationTokenRotationParticipantHandle struct {
	redactedValue
	value []byte
}

// NewGatewayDestinationTokenRotationParticipantHandle defensively copies a
// bounded non-empty participant handle.
func NewGatewayDestinationTokenRotationParticipantHandle(value []byte) (GatewayDestinationTokenRotationParticipantHandle, error) {
	if len(value) == 0 || len(value) > gatewayDestinationTokenRotationMaxHandleBytes {
		return GatewayDestinationTokenRotationParticipantHandle{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return GatewayDestinationTokenRotationParticipantHandle{value: append([]byte(nil), value...)}, nil
}

func (value GatewayDestinationTokenRotationParticipantHandle) valid() bool {
	return len(value.value) > 0 && len(value.value) <= gatewayDestinationTokenRotationMaxHandleBytes
}

// Bytes returns a defensive copy for the trusted participant adapter. The
// outer coordinator result deliberately does not expose this method's value.
func (value GatewayDestinationTokenRotationParticipantHandle) Bytes() []byte {
	return append([]byte(nil), value.value...)
}

func (value GatewayDestinationTokenRotationParticipantHandle) clone() GatewayDestinationTokenRotationParticipantHandle {
	return GatewayDestinationTokenRotationParticipantHandle{value: append([]byte(nil), value.value...)}
}

// GatewayDestinationTokenRotationBeginRequest carries the already-validated
// current token and binding across the trusted participant port. It must never
// be logged, traced, or used as a metric label.
type GatewayDestinationTokenRotationBeginRequest struct {
	redactedValue
	audience     GatewayAudienceID
	destination  GatewayDestinationID
	currentToken string
}

// Audience returns the canonical audience for the trusted participant adapter.
func (request GatewayDestinationTokenRotationBeginRequest) Audience() string {
	return strings.Clone(request.audience.value)
}

// Destination returns the canonical destination for the trusted participant adapter.
func (request GatewayDestinationTokenRotationBeginRequest) Destination() string {
	return strings.Clone(request.destination.value)
}

// CurrentToken returns the sensitive current token only to the trusted
// participant adapter.
func (request GatewayDestinationTokenRotationBeginRequest) CurrentToken() string {
	return strings.Clone(request.currentToken)
}

// GatewayDestinationTokenRotationParticipantAttempt is returned only after
// Gateway has confirmed activation of the exact new-active/old-retiring pair.
// The new token is consumed internally by Core exactly once.
type GatewayDestinationTokenRotationParticipantAttempt struct {
	redactedValue
	handle             GatewayDestinationTokenRotationParticipantHandle
	newToken           string
	activatedAt        time.Time
	retirementDeadline time.Time
}

// NewGatewayDestinationTokenRotationParticipantAttempt constructs a redacted
// participant response. The coordinator independently checks that the token is
// canonical and differs from the expected old token.
func NewGatewayDestinationTokenRotationParticipantAttempt(
	handle GatewayDestinationTokenRotationParticipantHandle,
	newToken string,
	activatedAt time.Time,
	retirementDeadline time.Time,
) (GatewayDestinationTokenRotationParticipantAttempt, error) {
	if !handle.valid() || !validGatewayToken(newToken) || activatedAt.IsZero() ||
		retirementDeadline.IsZero() || !activatedAt.Before(retirementDeadline) ||
		retirementDeadline.Sub(activatedAt) > gatewayDestinationTokenRotationMaxOverlap {
		return GatewayDestinationTokenRotationParticipantAttempt{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return GatewayDestinationTokenRotationParticipantAttempt{
		handle:             handle.clone(),
		newToken:           strings.Clone(newToken),
		activatedAt:        activatedAt,
		retirementDeadline: retirementDeadline,
	}, nil
}

// ActivatedAt returns the non-sensitive authoritative activation snapshot for
// the exact Gateway attempt. Core uses only G-A, never either wall-clock value
// directly, to derive its conservative local overlap deadline.
func (attempt GatewayDestinationTokenRotationParticipantAttempt) ActivatedAt() time.Time {
	return attempt.activatedAt
}

// RetirementDeadline returns the non-sensitive authoritative overlap deadline
// for the trusted participant adapter. A confirmed Begin result must obtain this
// value from the exact activated attempt; it is not caller supplied.
func (attempt GatewayDestinationTokenRotationParticipantAttempt) RetirementDeadline() time.Time {
	return attempt.retirementDeadline
}

// NewGatewayDestinationTokenRotationParticipantReconciliationAttempt creates
// a handle-only result for a Begin whose Gateway mutation outcome requires
// reconciliation. It intentionally carries no raw token.
func NewGatewayDestinationTokenRotationParticipantReconciliationAttempt(
	handle GatewayDestinationTokenRotationParticipantHandle,
) (GatewayDestinationTokenRotationParticipantAttempt, error) {
	if !handle.valid() {
		return GatewayDestinationTokenRotationParticipantAttempt{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return GatewayDestinationTokenRotationParticipantAttempt{handle: handle.clone()}, nil
}

func (attempt GatewayDestinationTokenRotationParticipantAttempt) valid() bool {
	return attempt.handle.valid() && validGatewayToken(attempt.newToken) &&
		gatewayDestinationTokenRotationValidInterval(attempt.activatedAt, attempt.retirementDeadline)
}

// GatewayDestinationTokenRotationParticipantState is the bounded exact-attempt
// lifecycle state reported by Gateway inspection.
type GatewayDestinationTokenRotationParticipantState uint8

const (
	GatewayDestinationTokenRotationParticipantActiveWithRetiring GatewayDestinationTokenRotationParticipantState = iota + 1
	GatewayDestinationTokenRotationParticipantRolledBack
	GatewayDestinationTokenRotationParticipantCompleted
)

// GatewayDestinationTokenRotationTokenIdentity identifies the candidate Core
// URL token relative to the exact Gateway attempt without exposing either raw
// attempt token. Cross-repository adapters must map these named values
// explicitly even though their reviewed ordinals match Gateway V1.
type GatewayDestinationTokenRotationTokenIdentity uint8

const (
	GatewayDestinationTokenRotationTokenNew     GatewayDestinationTokenRotationTokenIdentity = 1
	GatewayDestinationTokenRotationTokenOld     GatewayDestinationTokenRotationTokenIdentity = 2
	GatewayDestinationTokenRotationTokenNeither GatewayDestinationTokenRotationTokenIdentity = 3
)

// GatewayDestinationTokenRotationObservation is one bounded, authoritative
// Gateway snapshot and token classification for the exact attempt. The
// participant must identify the token against the exact records before reading
// the latest attempt-specific lifecycle state.
type GatewayDestinationTokenRotationObservation struct {
	redactedValue
	state              GatewayDestinationTokenRotationParticipantState
	identity           GatewayDestinationTokenRotationTokenIdentity
	observedAt         time.Time
	retirementDeadline time.Time
}

// NewGatewayDestinationTokenRotationObservation constructs a typed participant
// observation. Active overlap requires a non-zero retirement deadline; stable
// states do not carry one.
func NewGatewayDestinationTokenRotationObservation(
	state GatewayDestinationTokenRotationParticipantState,
	identity GatewayDestinationTokenRotationTokenIdentity,
	observedAt time.Time,
	retirementDeadline time.Time,
) (GatewayDestinationTokenRotationObservation, error) {
	observation := GatewayDestinationTokenRotationObservation{
		state:              state,
		identity:           identity,
		observedAt:         observedAt,
		retirementDeadline: retirementDeadline,
	}
	if !observation.valid() {
		return GatewayDestinationTokenRotationObservation{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return observation, nil
}

func (observation GatewayDestinationTokenRotationObservation) valid() bool {
	if observation.identity < GatewayDestinationTokenRotationTokenNew ||
		observation.identity > GatewayDestinationTokenRotationTokenNeither {
		return false
	}
	switch observation.state {
	case GatewayDestinationTokenRotationParticipantActiveWithRetiring:
		return !observation.observedAt.IsZero() && !observation.retirementDeadline.IsZero()
	case GatewayDestinationTokenRotationParticipantRolledBack,
		GatewayDestinationTokenRotationParticipantCompleted:
		return observation.observedAt.IsZero() && observation.retirementDeadline.IsZero()
	default:
		return false
	}
}

// ObservedAt returns Gateway's clock snapshot from the same authoritative
// Observe operation as RetirementDeadline. It is non-zero only for an active
// pair and is used solely to calculate the remaining duration G-O.
func (observation GatewayDestinationTokenRotationObservation) ObservedAt() time.Time {
	return observation.observedAt
}

// RetirementDeadline returns Gateway's authoritative immutable deadline for
// the exact active attempt. Terminal observations carry a zero value.
func (observation GatewayDestinationTokenRotationObservation) RetirementDeadline() time.Time {
	return observation.retirementDeadline
}

// GatewayDestinationTokenRotationObserveRequest asks Gateway to atomically
// inspect one exact attempt and classify the current authoritative Core token.
type GatewayDestinationTokenRotationObserveRequest struct {
	redactedValue
	handle GatewayDestinationTokenRotationParticipantHandle
	token  string
}

// ParticipantHandle returns a defensive copy to the trusted participant adapter.
func (request GatewayDestinationTokenRotationObserveRequest) ParticipantHandle() GatewayDestinationTokenRotationParticipantHandle {
	return request.handle.clone()
}

// CandidateToken returns the sensitive authoritative Core token only to the
// trusted participant adapter.
func (request GatewayDestinationTokenRotationObserveRequest) CandidateToken() string {
	return strings.Clone(request.token)
}

// GatewayDestinationTokenRotationFinalizeReason is intentionally limited to
// the only proof available in V1.
type GatewayDestinationTokenRotationFinalizeReason uint8

// GatewayDestinationTokenRotationFinalizeDeadlineElapsed intentionally has the
// same value as Gateway's accepted lifecycle deadline-elapsed reason. A future
// adapter must nevertheless map the named symbols explicitly rather than cast
// an untrusted wire or cross-repository numeric value.
const GatewayDestinationTokenRotationFinalizeDeadlineElapsed GatewayDestinationTokenRotationFinalizeReason = 2

// GatewayDestinationTokenRotationFinalizeRequest asks Gateway to finalize one
// exact pair for the fixed deadline-elapsed reason.
type GatewayDestinationTokenRotationFinalizeRequest struct {
	redactedValue
	handle GatewayDestinationTokenRotationParticipantHandle
	reason GatewayDestinationTokenRotationFinalizeReason
}

// ParticipantHandle returns a defensive copy to the trusted participant adapter.
func (request GatewayDestinationTokenRotationFinalizeRequest) ParticipantHandle() GatewayDestinationTokenRotationParticipantHandle {
	return request.handle.clone()
}

// Reason returns the fixed non-sensitive finalization reason.
func (request GatewayDestinationTokenRotationFinalizeRequest) Reason() GatewayDestinationTokenRotationFinalizeReason {
	return request.reason
}

// GatewayDestinationTokenRotationParticipant is the narrow transport-
// independent Gateway port. Implementations must serialize by destination,
// validate exact attempt binding, never retry, and return only fixed errors.
type GatewayDestinationTokenRotationParticipant interface {
	BeginRotation(context.Context, GatewayDestinationTokenRotationBeginRequest) (GatewayDestinationTokenRotationParticipantAttempt, error)
	ObserveRotation(context.Context, GatewayDestinationTokenRotationObserveRequest) (GatewayDestinationTokenRotationObservation, error)
	RollbackRotation(context.Context, GatewayDestinationTokenRotationParticipantHandle) error
	FinalizeRotation(context.Context, GatewayDestinationTokenRotationFinalizeRequest) error
}

// gatewayDestinationTokenRotationCAS is a sealed coordinator seam. Production
// construction always supplies a fenced implementation that locks the Core row
// before the conditional update can become ambiguous. Tests may replace it only
// to exercise the coordinator state machine. The trusted caller must never
// replay or bypass this exactly-once seam with the attempt's one-time token.
type gatewayDestinationTokenRotationCAS interface {
	CompareAndSwap(context.Context, GatewayDestinationTokenURLCASRequest) error
}

type gatewayDestinationTokenRotationFencedStore interface {
	compareAndSwapWithFence(context.Context, uuid.UUID, gadb.DestV1, gadb.DestV1) error
}

type gatewayDestinationTokenRotationFencedCAS struct {
	preparer *GatewayDestinationTokenURLCAS
	store    gatewayDestinationTokenRotationFencedStore
}

func (operation *gatewayDestinationTokenRotationFencedCAS) CompareAndSwap(
	ctx context.Context,
	request GatewayDestinationTokenURLCASRequest,
) error {
	if operation == nil || operation.preparer == nil || operation.store == nil || ctx == nil {
		return ErrGatewayDestinationTokenURLCASInvalid
	}
	if !permission.System(ctx) {
		return ErrGatewayDestinationTokenURLCASPermissionDenied
	}
	if err := gatewayDestinationTokenURLCASContextError(ctx); err != nil {
		return err
	}
	expected, replacement, err := operation.preparer.prepare(request)
	if err != nil {
		return ErrGatewayDestinationTokenURLCASInvalid
	}
	err = operation.store.compareAndSwapWithFence(ctx, request.contactMethodID, expected, replacement)
	switch err {
	case nil,
		ErrGatewayDestinationTokenURLCASConflict,
		ErrGatewayDestinationTokenURLCASUnavailable,
		ErrGatewayDestinationTokenURLCASOutcomeUnknown,
		ErrGatewayDestinationTokenURLCASCanceled,
		ErrGatewayDestinationTokenURLCASDeadlineExceeded,
		errGatewayDestinationTokenRotationQuarantineUnconfirmed:
		return err
	default:
		return errGatewayDestinationTokenRotationQuarantineUnconfirmed
	}
}

// GatewayDestinationTokenRotationAuthoritativeDestination contains the
// complete Core destination only inside the locked read callback. Formatting is
// always redacted and there is no public destination accessor.
type GatewayDestinationTokenRotationAuthoritativeDestination struct {
	redactedValue
	destination gadb.DestV1
}

// NewGatewayDestinationTokenRotationAuthoritativeDestination defensively
// copies a destination returned by a trusted Core persistence adapter.
func NewGatewayDestinationTokenRotationAuthoritativeDestination(destination gadb.DestV1) GatewayDestinationTokenRotationAuthoritativeDestination {
	copyValue := gadb.DestV1{Type: strings.Clone(destination.Type)}
	if destination.Args != nil {
		copyValue.Args = make(map[string]string, len(destination.Args))
		for key, value := range destination.Args {
			copyValue.Args[strings.Clone(key)] = strings.Clone(value)
		}
	}
	return GatewayDestinationTokenRotationAuthoritativeDestination{destination: copyValue}
}

// GatewayDestinationTokenRotationAuthoritativeStore exposes the logically
// read-only serialized Core inspection used by reconciliation and finalization.
// The built-in SQL implementation also supplies the sealed pre-mutation CAS
// fence required by production coordinator construction. The callback must run
// exactly once while the Contact Method row lock is held. The callback receives
// a store-derived, System-bearing lock context with an absolute deadline no
// more than the five-second operation limit; it must use only that context for
// query-adjacent participant work. Every connection used by this seam and the
// fenced CAS must route to the same linearizable writable PostgreSQL primary.
type GatewayDestinationTokenRotationAuthoritativeStore interface {
	WithLockedGatewayDestination(
		context.Context,
		uuid.UUID,
		func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination),
	) error
}

type gatewayDestinationTokenRotationSQLAuthoritativeStore struct {
	// acquire must return connections in one linearizable writable PostgreSQL
	// serialization domain. It must fail rather than route to a replica,
	// multi-primary peer, or uncertain failover target.
	acquire func(context.Context) (gatewayDestinationTokenRotationAuthoritativeConnection, error)
}

type gatewayDestinationTokenRotationAuthoritativeConnection interface {
	BeginTx(context.Context, *sql.TxOptions) (gatewayDestinationTokenRotationAuthoritativeTransaction, error)
	Close() error
	DiscardBefore(time.Time) bool
}

type gatewayDestinationTokenRotationAuthoritativeTransaction interface {
	gadb.DBTX
	Commit() error
	Rollback() error
}

type gatewayDestinationTokenRotationSQLConnection struct {
	conn *sql.Conn
}

func (connection *gatewayDestinationTokenRotationSQLConnection) BeginTx(
	ctx context.Context,
	options *sql.TxOptions,
) (gatewayDestinationTokenRotationAuthoritativeTransaction, error) {
	return connection.conn.BeginTx(ctx, options)
}

func (connection *gatewayDestinationTokenRotationSQLConnection) Close() error {
	return connection.conn.Close()
}

func (connection *gatewayDestinationTokenRotationSQLConnection) DiscardBefore(notAfter time.Time) bool {
	return discardGatewayDestinationTokenRotationConnectionBefore(connection.conn, notAfter)
}

func discardGatewayDestinationTokenRotationConnectionBefore(conn *sql.Conn, notAfter time.Time) bool {
	if conn == nil || notAfter.IsZero() || !time.Now().Before(notAfter) {
		return false
	}
	closeCtx, cancel := context.WithDeadline(context.Background(), notAfter)
	defer cancel()
	var (
		found    bool
		closeErr error
	)
	rawErr := conn.Raw(func(driverConnection any) error {
		physicalConnection := gatewayDestinationTokenURLCASPhysicalConnection(driverConnection)
		if physicalConnection == nil {
			return driver.ErrBadConn
		}
		found = true
		closeErr = physicalConnection.Close(closeCtx)
		return driver.ErrBadConn
	})
	return found && closeErr == nil &&
		(rawErr == nil || rawErr == driver.ErrBadConn) && !time.Now().After(notAfter)
}

// NewGatewayDestinationTokenRotationAuthoritativeStore constructs the Core SQL
// locking-read and fenced-CAS adapter. It adds no query or schema: it reuses the
// generated ContactMethodFindOneUpdate SELECT ... FOR UPDATE query and the
// accepted conditional destination UPDATE. db must route every acquired
// connection to the same linearizable writable PostgreSQL primary; replica,
// multi-primary, or topology-uncertain routing violates this constructor's
// safety contract.
func NewGatewayDestinationTokenRotationAuthoritativeStore(db *sql.DB) (GatewayDestinationTokenRotationAuthoritativeStore, error) {
	if db == nil {
		return nil, ErrGatewayDestinationTokenRotationInvalid
	}
	return newGatewayDestinationTokenRotationAuthoritativeStore(func(ctx context.Context) (gatewayDestinationTokenRotationAuthoritativeConnection, error) {
		conn, err := db.Conn(ctx)
		if err != nil || conn == nil {
			return nil, err
		}
		return &gatewayDestinationTokenRotationSQLConnection{conn: conn}, nil
	})
}

func newGatewayDestinationTokenRotationAuthoritativeStore(
	acquire func(context.Context) (gatewayDestinationTokenRotationAuthoritativeConnection, error),
) (*gatewayDestinationTokenRotationSQLAuthoritativeStore, error) {
	if acquire == nil {
		return nil, ErrGatewayDestinationTokenRotationInvalid
	}
	return &gatewayDestinationTokenRotationSQLAuthoritativeStore{acquire: acquire}, nil
}

func (store *gatewayDestinationTokenRotationSQLAuthoritativeStore) WithLockedGatewayDestination(
	ctx context.Context,
	contactMethodID uuid.UUID,
	inspect func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination),
) (returnErr error) {
	if store == nil || store.acquire == nil || ctx == nil || contactMethodID == uuid.Nil || inspect == nil {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	if !permission.System(ctx) {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}

	operationCtx, operationCancel, operationDeadline, ok := gatewayDestinationTokenRotationOperationContext(ctx)
	if !ok {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	defer operationCancel()
	txDeadline := operationDeadline.Add(gatewayDestinationTokenRotationReleaseLimit)
	txCtx, txCancel := context.WithDeadline(context.WithoutCancel(operationCtx), txDeadline)
	defer txCancel()

	conn, err := store.acquire(operationCtx)
	if err != nil || nilGatewayDestinationTokenRotationDependency(conn) {
		if !nilGatewayDestinationTokenRotationDependency(conn) {
			_ = conn.DiscardBefore(txDeadline)
			_ = conn.Close()
		}
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	defer func() { _ = conn.Close() }()

	// Keep transaction lifetime independent from caller cancellation while
	// bounding it beyond the operation deadline by a fixed release reserve. All
	// lock/query and participant work still receives the shorter operation ctx;
	// pgx commit/rollback uses this transaction context.
	tx, err := conn.BeginTx(txCtx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil || nilGatewayDestinationTokenRotationDependency(tx) {
		_ = conn.DiscardBefore(txDeadline)
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		if err := tx.Rollback(); err != nil || gatewayDestinationTokenRotationContextError(operationCtx) != nil {
			_ = conn.DiscardBefore(txDeadline)
			returnErr = ErrGatewayDestinationTokenRotationReconciliationRequired
		}
	}()

	row, err := gadb.New(tx).ContactMethodFindOneUpdate(operationCtx, contactMethodID)
	if err != nil {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	inspect(operationCtx, NewGatewayDestinationTokenRotationAuthoritativeDestination(row.Dest.DestV1))

	err = tx.Rollback()
	finished = true
	if err != nil {
		_ = conn.DiscardBefore(txDeadline)
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	if gatewayDestinationTokenRotationContextError(operationCtx) != nil {
		_ = conn.DiscardBefore(txDeadline)
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	return nil
}

// compareAndSwapWithFence establishes the Core serialization fence before the
// single conditional UPDATE can become ambiguous. The row lock and UPDATE use
// one READ COMMITTED transaction and one physical connection. Consequently, a
// later authoritative SELECT FOR UPDATE cannot observe the pre-CAS value and
// then be overtaken by a delayed commit from this attempt.
func (store *gatewayDestinationTokenRotationSQLAuthoritativeStore) compareAndSwapWithFence(
	ctx context.Context,
	contactMethodID uuid.UUID,
	expected gadb.DestV1,
	replacement gadb.DestV1,
) (returnErr error) {
	if store == nil || store.acquire == nil || ctx == nil || contactMethodID == uuid.Nil {
		return ErrGatewayDestinationTokenURLCASInvalid
	}
	if !permission.System(ctx) {
		return ErrGatewayDestinationTokenURLCASPermissionDenied
	}
	if err := gatewayDestinationTokenURLCASContextError(ctx); err != nil {
		return err
	}
	casDeadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(casDeadline) {
		return ErrGatewayDestinationTokenURLCASDeadlineExceeded
	}
	discardDeadline := casDeadline.Add(gatewayDestinationTokenRotationDiscardLimit)

	conn, err := store.acquire(ctx)
	if err != nil || nilGatewayDestinationTokenRotationDependency(conn) {
		if !nilGatewayDestinationTokenRotationDependency(conn) {
			discarded := conn.DiscardBefore(discardDeadline)
			_ = conn.Close()
			if !discarded {
				return errGatewayDestinationTokenRotationQuarantineUnconfirmed
			}
		}
		if contextErr := gatewayDestinationTokenURLCASContextError(ctx); contextErr != nil {
			return contextErr
		}
		if directGatewayDestinationTokenRotationError(err, errGatewayDestinationTokenRotationSerializationUncertain) {
			return errGatewayDestinationTokenRotationQuarantineUnconfirmed
		}
		return ErrGatewayDestinationTokenURLCASUnavailable
	}
	defer func() { _ = conn.Close() }()
	quarantineUnknown := func() error {
		if conn.DiscardBefore(discardDeadline) {
			return ErrGatewayDestinationTokenURLCASOutcomeUnknown
		}
		return errGatewayDestinationTokenRotationQuarantineUnconfirmed
	}

	// Fenced CAS has no external callback. Its transaction inherits the bounded
	// CAS context so pgx can resolve it automatically on cancellation; any such
	// race remains outcome-unknown and later recovery is ordered by the row lock.
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil || nilGatewayDestinationTokenRotationDependency(tx) {
		discarded := conn.DiscardBefore(discardDeadline)
		if !discarded {
			return errGatewayDestinationTokenRotationQuarantineUnconfirmed
		}
		if contextErr := gatewayDestinationTokenURLCASContextError(ctx); contextErr != nil {
			return contextErr
		}
		if directGatewayDestinationTokenRotationError(err, errGatewayDestinationTokenRotationSerializationUncertain) {
			return errGatewayDestinationTokenRotationQuarantineUnconfirmed
		}
		return ErrGatewayDestinationTokenURLCASUnavailable
	}
	finished := false
	defer func() {
		if !finished {
			if tx.Rollback() != nil || gatewayDestinationTokenURLCASContextError(ctx) != nil {
				returnErr = quarantineUnknown()
			}
		}
	}()
	rollback := func(safeErr error) error {
		err := tx.Rollback()
		finished = true
		if err != nil || gatewayDestinationTokenURLCASContextError(ctx) != nil {
			return quarantineUnknown()
		}
		return safeErr
	}
	rollbackUncertainTopology := func() error {
		_ = tx.Rollback()
		finished = true
		_ = conn.DiscardBefore(discardDeadline)
		return errGatewayDestinationTokenRotationQuarantineUnconfirmed
	}

	_, err = gadb.New(tx).ContactMethodFindOneUpdate(ctx, contactMethodID)
	if err != nil {
		if gatewayDestinationTokenURLCASSingleCauseMatches(err, sql.ErrNoRows) {
			return rollback(ErrGatewayDestinationTokenURLCASConflict)
		}
		if directGatewayDestinationTokenRotationError(err, errGatewayDestinationTokenRotationSerializationUncertain) {
			return rollbackUncertainTopology()
		}
		if contextErr := gatewayDestinationTokenURLCASContextError(ctx); contextErr != nil {
			return rollback(contextErr)
		}
		return rollback(ErrGatewayDestinationTokenURLCASUnavailable)
	}

	result, err := gadb.New(tx).ContactMethodCompareAndSwapGatewayDest(ctx, gadb.ContactMethodCompareAndSwapGatewayDestParams{
		ID:              contactMethodID,
		ReplacementDest: gadb.NullDestV1{Valid: true, DestV1: replacement},
		ExpectedDest:    gadb.NullDestV1{Valid: true, DestV1: expected},
	})
	if err != nil {
		if directGatewayDestinationTokenRotationError(err, errGatewayDestinationTokenRotationSerializationUncertain) {
			return rollbackUncertainTopology()
		}
		classified := classifyGatewayDestinationTokenURLCASExecutionError(err)
		if contextErr := gatewayDestinationTokenURLCASContextError(ctx); contextErr != nil {
			classified = contextErr
		} else if classified == ErrGatewayDestinationTokenURLCASOutcomeUnknown {
			// A confirmed transaction rollback proves that no Core mutation
			// committed even when statement execution itself was ambiguous.
			classified = ErrGatewayDestinationTokenURLCASUnavailable
		}
		return rollback(classified)
	}
	rowsAffected, valid := gatewayDestinationTokenURLCASRowsAffected(result)
	if !valid {
		return rollback(ErrGatewayDestinationTokenURLCASUnavailable)
	}
	switch rowsAffected {
	case 0:
		return rollback(ErrGatewayDestinationTokenURLCASConflict)
	case 1:
		// Continue to the only commit attempt below.
	default:
		return rollback(ErrGatewayDestinationTokenURLCASUnavailable)
	}

	err = tx.Commit()
	finished = true
	if err != nil {
		// Commit errors are outcome-unknown. Destroying the physical
		// connection forces PostgreSQL to resolve the transaction while the row
		// lock still orders any later authoritative locking read.
		return quarantineUnknown()
	}
	if gatewayDestinationTokenURLCASContextError(ctx) != nil {
		// A driver that reports a late successful commit is fail-closed. Core
		// does not claim the overlap is still live or report pending success.
		return quarantineUnknown()
	}
	return nil
}

// GatewayDestinationTokenRotationStatus is a safe, bounded outer-coordinator
// state. It contains no URL or token material.
type GatewayDestinationTokenRotationStatus uint8

const (
	GatewayDestinationTokenRotationPendingFinalization GatewayDestinationTokenRotationStatus = iota + 1
	GatewayDestinationTokenRotationRolledBack
	GatewayDestinationTokenRotationCompleted
	GatewayDestinationTokenRotationNeedsReconciliation
)

// GatewayDestinationTokenRotationHandle is the opaque input for explicit
// reconciliation and finalization. It never contains either raw token or a
// complete destination URL.
type GatewayDestinationTokenRotationHandle struct {
	redactedValue
	contactMethodID uuid.UUID
	participant     GatewayDestinationTokenRotationParticipantHandle
}

func (handle GatewayDestinationTokenRotationHandle) valid() bool {
	return handle.contactMethodID != uuid.Nil && handle.participant.valid()
}

func (handle GatewayDestinationTokenRotationHandle) clone() GatewayDestinationTokenRotationHandle {
	return GatewayDestinationTokenRotationHandle{
		contactMethodID: handle.contactMethodID,
		participant:     handle.participant.clone(),
	}
}

// GatewayDestinationTokenRotationResult is a redacted stable result and its
// opaque continuation handle.
type GatewayDestinationTokenRotationResult struct {
	redactedValue
	status GatewayDestinationTokenRotationStatus
	handle GatewayDestinationTokenRotationHandle
}

// Status returns the bounded non-sensitive coordinator state.
func (result GatewayDestinationTokenRotationResult) Status() GatewayDestinationTokenRotationStatus {
	return result.status
}

// Handle returns a defensive copy without exposing a URL or raw token.
func (result GatewayDestinationTokenRotationResult) Handle() GatewayDestinationTokenRotationHandle {
	return result.handle.clone()
}

// GatewayDestinationTokenRotationCoordinator is the System-only Core outer
// coordinator. It has no transport or runtime wiring.
type GatewayDestinationTokenRotationCoordinator struct {
	redactedValue
	matcher      *GatewayTargetMatcher
	cas          gatewayDestinationTokenRotationCAS
	store        GatewayDestinationTokenRotationAuthoritativeStore
	participant  GatewayDestinationTokenRotationParticipant
	monotonicNow func() time.Time
}

// NewGatewayDestinationTokenRotationCoordinator constructs the outer
// coordinator from narrow Core and Gateway ports.
func NewGatewayDestinationTokenRotationCoordinator(
	matcher *GatewayTargetMatcher,
	cas *GatewayDestinationTokenURLCAS,
	store GatewayDestinationTokenRotationAuthoritativeStore,
	participant GatewayDestinationTokenRotationParticipant,
) (*GatewayDestinationTokenRotationCoordinator, error) {
	if matcher == nil || !matcher.valid() || cas == nil || cas.matcher != matcher ||
		nilGatewayDestinationTokenURLCASRepository(cas.repository) {
		return nil, ErrGatewayDestinationTokenRotationInvalid
	}
	fencedStore, ok := store.(gatewayDestinationTokenRotationFencedStore)
	if !ok || nilGatewayDestinationTokenRotationDependency(fencedStore) {
		return nil, ErrGatewayDestinationTokenRotationInvalid
	}
	return newGatewayDestinationTokenRotationCoordinator(
		matcher,
		&gatewayDestinationTokenRotationFencedCAS{preparer: cas, store: fencedStore},
		store,
		participant,
		time.Now,
	)
}

func newGatewayDestinationTokenRotationCoordinator(
	matcher *GatewayTargetMatcher,
	cas gatewayDestinationTokenRotationCAS,
	store GatewayDestinationTokenRotationAuthoritativeStore,
	participant GatewayDestinationTokenRotationParticipant,
	now func() time.Time,
) (*GatewayDestinationTokenRotationCoordinator, error) {
	if matcher == nil || !matcher.valid() || nilGatewayDestinationTokenRotationDependency(cas) ||
		nilGatewayDestinationTokenRotationDependency(store) ||
		nilGatewayDestinationTokenRotationDependency(participant) || now == nil {
		return nil, ErrGatewayDestinationTokenRotationInvalid
	}
	return &GatewayDestinationTokenRotationCoordinator{
		matcher: matcher, cas: cas, store: store, participant: participant, monotonicNow: now,
	}, nil
}

// Start performs Gateway Begin before one and only one Core CAS. It returns no
// URL or token material.
func (coordinator *GatewayDestinationTokenRotationCoordinator) Start(
	ctx context.Context,
	request GatewayDestinationTokenRotationStartRequest,
) (GatewayDestinationTokenRotationResult, error) {
	if err := coordinator.operationContext(ctx); err != nil {
		return GatewayDestinationTokenRotationResult{}, err
	}

	audience, destination, oldToken, err := coordinator.prepareStart(request)
	if err != nil {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationInvalid
	}

	// Sample immediately before Begin. Production construction supplies
	// time.Now, whose monotonic component is independent of Gateway wall-clock
	// values A and G and consumes time spent inside Begin.
	beginAnchor := coordinator.monotonicNow()
	if beginAnchor.IsZero() {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationInvalid
	}
	beginCtx, beginCancel, ok := gatewayDestinationTokenRotationBoundedContext(
		ctx,
		beginAnchor.Add(gatewayDestinationTokenRotationBeginLimit),
	)
	if !ok {
		if callerErr := gatewayDestinationTokenRotationContextError(ctx); callerErr != nil {
			return GatewayDestinationTokenRotationResult{}, callerErr
		}
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationUnavailable
	}
	attempt, err := coordinator.participant.BeginRotation(beginCtx, GatewayDestinationTokenRotationBeginRequest{
		audience: audience, destination: destination, currentToken: strings.Clone(oldToken),
	})
	beginContextErr := gatewayDestinationTokenRotationContextError(beginCtx)
	beginCancel()
	if err != nil {
		if attempt.handle.valid() {
			handle := GatewayDestinationTokenRotationHandle{
				contactMethodID: request.contactMethodID,
				participant:     attempt.handle.clone(),
			}
			return gatewayDestinationTokenRotationReconciliationResult(handle)
		}
		return GatewayDestinationTokenRotationResult{}, gatewayDestinationTokenRotationBeginError(err)
	}
	if !attempt.valid() || attempt.newToken == oldToken {
		if attempt.handle.valid() {
			handle := GatewayDestinationTokenRotationHandle{
				contactMethodID: request.contactMethodID,
				participant:     attempt.handle.clone(),
			}
			return gatewayDestinationTokenRotationReconciliationResult(handle)
		}
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
	}

	handle := GatewayDestinationTokenRotationHandle{
		contactMethodID: request.contactMethodID,
		participant:     attempt.handle.clone(),
	}
	localDeadline, ok := gatewayDestinationTokenRotationLocalDeadline(
		beginAnchor,
		attempt.activatedAt,
		attempt.retirementDeadline,
	)
	if !ok {
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	callerErr := beginContextErr
	if callerErr == nil {
		callerErr = gatewayDestinationTokenRotationContextError(ctx)
	}
	if callerErr != nil {
		if coordinator.rollbackBeforeLocalDeadline(context.WithoutCancel(ctx), handle.participant, localDeadline) == nil {
			return GatewayDestinationTokenRotationResult{}, callerErr
		}
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	now := coordinator.monotonicNow()
	if now.IsZero() || localDeadline.Sub(now) <= gatewayDestinationTokenRotationCASLimit+
		gatewayDestinationTokenRotationDiscardLimit+gatewayDestinationTokenRotationRecoveryLimit {
		if coordinator.rollbackBeforeLocalDeadline(context.WithoutCancel(ctx), handle.participant, localDeadline) == nil {
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationUnavailable
		}
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	casDeadline := gatewayDestinationTokenRotationEarliestDeadline(
		now.Add(gatewayDestinationTokenRotationCASLimit),
		localDeadline.Add(-gatewayDestinationTokenRotationDiscardLimit-gatewayDestinationTokenRotationRecoveryLimit),
	)
	if callerDeadline, bounded := ctx.Deadline(); bounded {
		casDeadline = gatewayDestinationTokenRotationEarliestDeadline(casDeadline, callerDeadline)
	}
	casCtx, cancel, ok := gatewayDestinationTokenRotationBoundedContext(ctx, casDeadline)
	if !ok {
		if coordinator.rollbackBeforeLocalDeadline(context.WithoutCancel(ctx), handle.participant, localDeadline) == nil {
			if callerErr := gatewayDestinationTokenRotationContextError(ctx); callerErr != nil {
				return GatewayDestinationTokenRotationResult{}, callerErr
			}
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationUnavailable
		}
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	casErr := coordinator.cas.CompareAndSwap(casCtx, NewGatewayDestinationTokenURLCASRequest(
		request.contactMethodID,
		request.expectedURL,
		attempt.newToken,
	))
	casContextErr := gatewayDestinationTokenRotationContextError(casCtx)
	cancel()
	if casErr == nil && casContextErr == nil {
		return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationPendingFinalization, handle), nil
	}
	if casErr == nil {
		// No production physical-quarantine proof accompanies a late nil from a
		// substituted seam. Do not enter authoritative callback recovery.
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}

	if safeErr, safe := gatewayDestinationTokenRotationSafeCASError(casErr); safe {
		if coordinator.rollbackBeforeLocalDeadline(context.WithoutCancel(ctx), handle.participant, localDeadline) == nil {
			return GatewayDestinationTokenRotationResult{}, safeErr
		}
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	if directGatewayDestinationTokenRotationError(casErr, ErrGatewayDestinationTokenURLCASOutcomeUnknown) {
		return coordinator.recoverUnknownCAS(ctx, handle, localDeadline, attempt.retirementDeadline)
	}
	return gatewayDestinationTokenRotationReconciliationResult(handle)
}

// Reconcile performs an explicit serialized authoritative read and reports only
// a proven stable state. The exact old/pair case performs at most one rollback.
func (coordinator *GatewayDestinationTokenRotationCoordinator) Reconcile(
	ctx context.Context,
	handle GatewayDestinationTokenRotationHandle,
) (GatewayDestinationTokenRotationResult, error) {
	if err := coordinator.operationContext(ctx); err != nil {
		return GatewayDestinationTokenRotationResult{}, err
	}
	if !handle.valid() {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return coordinator.inspectLocked(
		ctx,
		handle,
		gatewayDestinationTokenRotationInspectReconcile,
		time.Time{},
		time.Time{},
	)
}

// Finalize proves the exact Core/Gateway state under the Core row lock and
// permits only deadline-elapsed finalization. It does not schedule future work.
func (coordinator *GatewayDestinationTokenRotationCoordinator) Finalize(
	ctx context.Context,
	handle GatewayDestinationTokenRotationHandle,
) (GatewayDestinationTokenRotationResult, error) {
	if err := coordinator.operationContext(ctx); err != nil {
		return GatewayDestinationTokenRotationResult{}, err
	}
	if !handle.valid() {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationInvalid
	}
	return coordinator.inspectLocked(
		ctx,
		handle,
		gatewayDestinationTokenRotationInspectFinalize,
		time.Time{},
		time.Time{},
	)
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) operationContext(ctx context.Context) error {
	if ctx == nil {
		return ErrGatewayDestinationTokenRotationInvalid
	}
	if !permission.System(ctx) {
		return ErrGatewayDestinationTokenRotationPermissionDenied
	}
	if coordinator == nil || coordinator.matcher == nil || !coordinator.matcher.valid() ||
		nilGatewayDestinationTokenRotationDependency(coordinator.cas) ||
		nilGatewayDestinationTokenRotationDependency(coordinator.store) ||
		nilGatewayDestinationTokenRotationDependency(coordinator.participant) || coordinator.monotonicNow == nil {
		return ErrGatewayDestinationTokenRotationInvalid
	}
	switch ctx.Err() {
	case context.Canceled:
		return ErrGatewayDestinationTokenRotationCanceled
	case context.DeadlineExceeded:
		return ErrGatewayDestinationTokenRotationDeadlineExceeded
	default:
		return nil
	}
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) prepareStart(
	request GatewayDestinationTokenRotationStartRequest,
) (GatewayAudienceID, GatewayDestinationID, string, error) {
	if request.contactMethodID == uuid.Nil || request.expectedURL == "" || request.audience == "" || request.destination == "" {
		return GatewayAudienceID{}, GatewayDestinationID{}, "", ErrGatewayDestinationTokenRotationInvalid
	}
	target, err := url.Parse(request.expectedURL)
	if err != nil || target.String() != request.expectedURL {
		return GatewayAudienceID{}, GatewayDestinationID{}, "", ErrGatewayDestinationTokenRotationInvalid
	}
	path, matched := coordinator.matcher.Match(target)
	if !matched {
		return GatewayAudienceID{}, GatewayDestinationID{}, "", ErrGatewayDestinationTokenRotationInvalid
	}
	oldToken := strings.TrimPrefix(path, gatewayContactMethodPathPrefix)
	if !validGatewayToken(oldToken) || !strings.HasSuffix(request.expectedURL, oldToken) {
		return GatewayAudienceID{}, GatewayDestinationID{}, "", ErrGatewayDestinationTokenRotationInvalid
	}
	audience, err := NewGatewayAudienceID(request.audience)
	if err != nil {
		return GatewayAudienceID{}, GatewayDestinationID{}, "", ErrGatewayDestinationTokenRotationInvalid
	}
	destination, err := NewGatewayDestinationID(request.destination)
	if err != nil {
		return GatewayAudienceID{}, GatewayDestinationID{}, "", ErrGatewayDestinationTokenRotationInvalid
	}
	return audience, destination, oldToken, nil
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) recoverUnknownCAS(
	ctx context.Context,
	handle GatewayDestinationTokenRotationHandle,
	localDeadline time.Time,
	expectedGatewayDeadline time.Time,
) (GatewayDestinationTokenRotationResult, error) {
	recoveryCtx, cancel, ok := coordinator.detachedRecoveryContext(ctx, localDeadline)
	if !ok {
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	defer cancel()
	return coordinator.inspectLocked(
		recoveryCtx,
		handle,
		gatewayDestinationTokenRotationInspectUnknownCAS,
		localDeadline,
		expectedGatewayDeadline,
	)
}

type gatewayDestinationTokenRotationInspectPurpose uint8

const (
	gatewayDestinationTokenRotationInspectUnknownCAS gatewayDestinationTokenRotationInspectPurpose = iota + 1
	gatewayDestinationTokenRotationInspectReconcile
	gatewayDestinationTokenRotationInspectFinalize
)

func (coordinator *GatewayDestinationTokenRotationCoordinator) inspectLocked(
	ctx context.Context,
	handle GatewayDestinationTokenRotationHandle,
	purpose gatewayDestinationTokenRotationInspectPurpose,
	unknownLocalDeadline time.Time,
	expectedGatewayDeadline time.Time,
) (GatewayDestinationTokenRotationResult, error) {
	var (
		callbackMu    sync.Mutex
		callbackCalls atomic.Int32
		result        GatewayDestinationTokenRotationResult
		operationErr  = ErrGatewayDestinationTokenRotationReconciliationRequired
	)

	storeErr := coordinator.store.WithLockedGatewayDestination(ctx, handle.contactMethodID, func(
		lockCtx context.Context,
		authoritative GatewayDestinationTokenRotationAuthoritativeDestination,
	) {
		callbackMu.Lock()
		defer callbackMu.Unlock()
		if callbackCalls.Add(1) != 1 {
			operationErr = ErrGatewayDestinationTokenRotationReconciliationRequired
			return
		}
		if !gatewayDestinationTokenRotationValidLockContext(lockCtx) {
			operationErr = ErrGatewayDestinationTokenRotationReconciliationRequired
			return
		}
		token, ok := coordinator.tokenFromAuthoritativeDestination(authoritative)
		if !ok {
			operationErr = ErrGatewayDestinationTokenRotationReconciliationRequired
			return
		}
		observeAnchor := coordinator.monotonicNow()
		observation, err := coordinator.participant.ObserveRotation(lockCtx, GatewayDestinationTokenRotationObserveRequest{
			handle: handle.participant.clone(), token: token,
		})
		if err != nil || !observation.valid() {
			operationErr = ErrGatewayDestinationTokenRotationReconciliationRequired
			return
		}
		localDeadline, deadlineOK := coordinator.observationLocalDeadline(
			observation,
			purpose,
			observeAnchor,
			unknownLocalDeadline,
			expectedGatewayDeadline,
		)
		if !deadlineOK {
			operationErr = ErrGatewayDestinationTokenRotationReconciliationRequired
			return
		}

		switch purpose {
		case gatewayDestinationTokenRotationInspectFinalize:
			result, operationErr = coordinator.finalizeLocked(lockCtx, handle, observation, localDeadline)
		case gatewayDestinationTokenRotationInspectUnknownCAS,
			gatewayDestinationTokenRotationInspectReconcile:
			result, operationErr = coordinator.reconcileLocked(lockCtx, handle, observation, purpose, localDeadline)
		default:
			operationErr = ErrGatewayDestinationTokenRotationReconciliationRequired
		}
	})
	if storeErr != nil || callbackCalls.Load() != 1 {
		return gatewayDestinationTokenRotationReconciliationResult(handle)
	}
	if operationErr != nil {
		if operationErr == ErrGatewayDestinationTokenRotationReconciliationRequired {
			return gatewayDestinationTokenRotationReconciliationResult(handle)
		}
		return GatewayDestinationTokenRotationResult{}, operationErr
	}
	return result, nil
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) reconcileLocked(
	ctx context.Context,
	handle GatewayDestinationTokenRotationHandle,
	observation GatewayDestinationTokenRotationObservation,
	purpose gatewayDestinationTokenRotationInspectPurpose,
	localDeadline time.Time,
) (GatewayDestinationTokenRotationResult, error) {
	switch observation.state {
	case GatewayDestinationTokenRotationParticipantActiveWithRetiring:
		if localDeadline.IsZero() {
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
		}
		switch observation.identity {
		case GatewayDestinationTokenRotationTokenNew:
			return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationPendingFinalization, handle), nil
		case GatewayDestinationTokenRotationTokenOld:
			if coordinator.rollbackBeforeLocalDeadline(ctx, handle.participant, localDeadline) != nil {
				return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
			}
			if purpose == gatewayDestinationTokenRotationInspectUnknownCAS {
				return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationUnavailable
			}
			return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationRolledBack, handle), nil
		default:
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
		}
	case GatewayDestinationTokenRotationParticipantRolledBack:
		if observation.identity == GatewayDestinationTokenRotationTokenOld && purpose == gatewayDestinationTokenRotationInspectReconcile {
			return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationRolledBack, handle), nil
		}
	case GatewayDestinationTokenRotationParticipantCompleted:
		if observation.identity == GatewayDestinationTokenRotationTokenNew && purpose == gatewayDestinationTokenRotationInspectReconcile {
			return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationCompleted, handle), nil
		}
	}
	return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) finalizeLocked(
	ctx context.Context,
	handle GatewayDestinationTokenRotationHandle,
	observation GatewayDestinationTokenRotationObservation,
	localDeadline time.Time,
) (GatewayDestinationTokenRotationResult, error) {
	if observation.state != GatewayDestinationTokenRotationParticipantActiveWithRetiring ||
		observation.identity != GatewayDestinationTokenRotationTokenNew {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	now := coordinator.monotonicNow()
	if now.IsZero() || localDeadline.IsZero() {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	if now.Before(localDeadline) {
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationTooEarly
	}
	if err := gatewayDestinationTokenRotationContextError(ctx); err != nil {
		return GatewayDestinationTokenRotationResult{}, err
	}
	err := coordinator.participant.FinalizeRotation(ctx, GatewayDestinationTokenRotationFinalizeRequest{
		handle: handle.participant.clone(),
		reason: GatewayDestinationTokenRotationFinalizeDeadlineElapsed,
	})
	if err != nil {
		if directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationCanceled) {
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationCanceled
		}
		if directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationDeadlineExceeded) {
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationDeadlineExceeded
		}
		if directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationUnavailable) {
			return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationUnavailable
		}
		return GatewayDestinationTokenRotationResult{}, ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationCompleted, handle), nil
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) tokenFromAuthoritativeDestination(
	authoritative GatewayDestinationTokenRotationAuthoritativeDestination,
) (string, bool) {
	destination := authoritative.destination
	if destination.Type != DestTypeWebhook || len(destination.Args) != 1 {
		return "", false
	}
	completeURL := destination.Arg(FieldWebhookURL)
	target, err := url.Parse(completeURL)
	if err != nil || target.String() != completeURL {
		return "", false
	}
	path, matched := coordinator.matcher.Match(target)
	if !matched {
		return "", false
	}
	token := strings.TrimPrefix(path, gatewayContactMethodPathPrefix)
	return strings.Clone(token), validGatewayToken(token)
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) observationLocalDeadline(
	observation GatewayDestinationTokenRotationObservation,
	purpose gatewayDestinationTokenRotationInspectPurpose,
	observeAnchor time.Time,
	unknownLocalDeadline time.Time,
	expectedGatewayDeadline time.Time,
) (time.Time, bool) {
	if observation.state != GatewayDestinationTokenRotationParticipantActiveWithRetiring {
		return time.Time{}, true
	}
	remaining := observation.retirementDeadline.Sub(observation.observedAt)
	if observeAnchor.IsZero() || remaining > gatewayDestinationTokenRotationMaxOverlap {
		return time.Time{}, false
	}
	if purpose == gatewayDestinationTokenRotationInspectUnknownCAS {
		if unknownLocalDeadline.IsZero() || expectedGatewayDeadline.IsZero() ||
			!observation.retirementDeadline.Equal(expectedGatewayDeadline) {
			return time.Time{}, false
		}
		return unknownLocalDeadline, true
	}
	return observeAnchor.Add(remaining), true
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) rollbackBeforeLocalDeadline(
	ctx context.Context,
	handle GatewayDestinationTokenRotationParticipantHandle,
	localDeadline time.Time,
) error {
	now := coordinator.monotonicNow()
	if ctx == nil || now.IsZero() || localDeadline.IsZero() || !now.Before(localDeadline) {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	recoveryDeadline := gatewayDestinationTokenRotationEarliestDeadline(
		now.Add(gatewayDestinationTokenRotationRecoveryLimit),
		localDeadline,
	)
	recoveryCtx, cancel, ok := gatewayDestinationTokenRotationBoundedContext(ctx, recoveryDeadline)
	if !ok {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	defer cancel()
	if coordinator.participant.RollbackRotation(recoveryCtx, handle.clone()) != nil || recoveryCtx.Err() != nil {
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
	return nil
}

func (coordinator *GatewayDestinationTokenRotationCoordinator) detachedRecoveryContext(
	ctx context.Context,
	localDeadline time.Time,
) (context.Context, context.CancelFunc, bool) {
	now := coordinator.monotonicNow()
	if ctx == nil || now.IsZero() || localDeadline.IsZero() || !now.Before(localDeadline) {
		return nil, nil, false
	}
	deadline := gatewayDestinationTokenRotationEarliestDeadline(
		now.Add(gatewayDestinationTokenRotationRecoveryLimit),
		localDeadline,
	)
	return gatewayDestinationTokenRotationBoundedContext(context.WithoutCancel(ctx), deadline)
}

func gatewayDestinationTokenRotationValidInterval(start, deadline time.Time) bool {
	if start.IsZero() || deadline.IsZero() {
		return false
	}
	interval := deadline.Sub(start)
	return interval > 0 && interval <= gatewayDestinationTokenRotationMaxOverlap
}

func gatewayDestinationTokenRotationLocalDeadline(anchor, start, deadline time.Time) (time.Time, bool) {
	if anchor.IsZero() || !gatewayDestinationTokenRotationValidInterval(start, deadline) {
		return time.Time{}, false
	}
	return anchor.Add(deadline.Sub(start)), true
}

func gatewayDestinationTokenRotationOperationContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, time.Time, bool) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, time.Time{}, false
	}
	operationDeadline := time.Now().Add(gatewayDestinationTokenRotationRecoveryLimit)
	if callerDeadline, bounded := ctx.Deadline(); bounded {
		operationDeadline = gatewayDestinationTokenRotationEarliestDeadline(operationDeadline, callerDeadline)
	}
	operationCtx, cancel, ok := gatewayDestinationTokenRotationBoundedContext(ctx, operationDeadline)
	return operationCtx, cancel, operationDeadline, ok
}

func gatewayDestinationTokenRotationValidLockContext(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil || !permission.System(ctx) {
		return false
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return false
	}
	remaining := time.Until(deadline)
	return remaining > 0 && remaining <= gatewayDestinationTokenRotationRecoveryLimit
}

func gatewayDestinationTokenRotationBoundedContext(
	ctx context.Context,
	deadline time.Time,
) (context.Context, context.CancelFunc, bool) {
	if ctx == nil || deadline.IsZero() || ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, nil, false
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	if bounded.Err() != nil {
		cancel()
		return nil, nil, false
	}
	return bounded, cancel, true
}

func gatewayDestinationTokenRotationEarliestDeadline(first, second time.Time) time.Time {
	if second.Before(first) {
		return second
	}
	return first
}

func gatewayDestinationTokenRotationResult(
	status GatewayDestinationTokenRotationStatus,
	handle GatewayDestinationTokenRotationHandle,
) GatewayDestinationTokenRotationResult {
	return GatewayDestinationTokenRotationResult{status: status, handle: handle.clone()}
}

func gatewayDestinationTokenRotationReconciliationResult(
	handle GatewayDestinationTokenRotationHandle,
) (GatewayDestinationTokenRotationResult, error) {
	return gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationNeedsReconciliation, handle),
		ErrGatewayDestinationTokenRotationReconciliationRequired
}

func gatewayDestinationTokenRotationBeginError(err error) error {
	switch {
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationInvalid):
		return ErrGatewayDestinationTokenRotationInvalid
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationPermissionDenied):
		return ErrGatewayDestinationTokenRotationPermissionDenied
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationConflict):
		return ErrGatewayDestinationTokenRotationConflict
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationUnavailable):
		return ErrGatewayDestinationTokenRotationUnavailable
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationCanceled):
		return ErrGatewayDestinationTokenRotationCanceled
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenRotationDeadlineExceeded):
		return ErrGatewayDestinationTokenRotationDeadlineExceeded
	default:
		return ErrGatewayDestinationTokenRotationReconciliationRequired
	}
}

func gatewayDestinationTokenRotationSafeCASError(err error) (error, bool) {
	switch {
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenURLCASInvalid):
		return ErrGatewayDestinationTokenRotationInvalid, true
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenURLCASPermissionDenied):
		return ErrGatewayDestinationTokenRotationPermissionDenied, true
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenURLCASConflict):
		return ErrGatewayDestinationTokenRotationConflict, true
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenURLCASUnavailable):
		return ErrGatewayDestinationTokenRotationUnavailable, true
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenURLCASCanceled):
		return ErrGatewayDestinationTokenRotationCanceled, true
	case directGatewayDestinationTokenRotationError(err, ErrGatewayDestinationTokenURLCASDeadlineExceeded):
		return ErrGatewayDestinationTokenRotationDeadlineExceeded, true
	default:
		return nil, false
	}
}

func directGatewayDestinationTokenRotationError(got, want error) bool {
	if got == nil || want == nil || gatewayDestinationTokenURLCASNilError(got) || gatewayDestinationTokenURLCASNilError(want) {
		return false
	}
	gotType := reflect.TypeOf(got)
	return gotType.Comparable() && gotType == reflect.TypeOf(want) && got == want
}

func nilGatewayDestinationTokenRotationDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func gatewayDestinationTokenRotationContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrGatewayDestinationTokenRotationInvalid
	}
	switch ctx.Err() {
	case context.Canceled:
		return ErrGatewayDestinationTokenRotationCanceled
	case context.DeadlineExceeded:
		return ErrGatewayDestinationTokenRotationDeadlineExceeded
	default:
		return nil
	}
}
