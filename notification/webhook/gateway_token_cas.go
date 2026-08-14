package webhook

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

var (
	ErrGatewayDestinationTokenURLCASInvalid          = errors.New("gateway destination token URL CAS invalid")
	ErrGatewayDestinationTokenURLCASPermissionDenied = errors.New("gateway destination token URL CAS permission denied")
	ErrGatewayDestinationTokenURLCASConflict         = errors.New("gateway destination token URL CAS conflict")
	ErrGatewayDestinationTokenURLCASUnavailable      = errors.New("gateway destination token URL CAS unavailable")
	ErrGatewayDestinationTokenURLCASOutcomeUnknown   = errors.New("gateway destination token URL CAS outcome unknown")
	ErrGatewayDestinationTokenURLCASCanceled         = errors.New("gateway destination token URL CAS canceled")
	ErrGatewayDestinationTokenURLCASDeadlineExceeded = errors.New("gateway destination token URL CAS deadline exceeded")
)

// GatewayDestinationTokenURLCASRequest contains the sensitive expected URL
// and replacement token for one internal compare-and-swap operation. Its
// formatted representation is always redacted.
type GatewayDestinationTokenURLCASRequest struct {
	redactedValue
	contactMethodID  uuid.UUID
	expectedURL      string
	replacementToken string
}

// NewGatewayDestinationTokenURLCASRequest creates an opaque request value.
// Validation is performed by CompareAndSwap against the configured matcher.
func NewGatewayDestinationTokenURLCASRequest(contactMethodID uuid.UUID, expectedURL, replacementToken string) GatewayDestinationTokenURLCASRequest {
	return GatewayDestinationTokenURLCASRequest{
		contactMethodID:  contactMethodID,
		expectedURL:      expectedURL,
		replacementToken: replacementToken,
	}
}

type gatewayDestinationTokenURLCASRepository interface {
	CompareAndSwapGatewayDestination(context.Context, uuid.UUID, gadb.DestV1, gadb.DestV1) (int64, error)
}

type gatewayDestinationTokenURLCASSQLRepository struct {
	db *sql.DB
}

// GatewayDestinationTokenURLCAS performs a System-only, token-only
// conditional update. Its formatted representation is always redacted.
type GatewayDestinationTokenURLCAS struct {
	redactedValue
	matcher    *GatewayTargetMatcher
	repository gatewayDestinationTokenURLCASRepository
}

// NewGatewayDestinationTokenURLCAS constructs the internal CAS service. The
// SQL adapter acquires a dedicated *sql.Conn so database/sql cannot replay the
// update after driver.ErrBadConn.
func NewGatewayDestinationTokenURLCAS(matcher *GatewayTargetMatcher, db *sql.DB) (*GatewayDestinationTokenURLCAS, error) {
	if matcher == nil || !matcher.valid() || db == nil {
		return nil, ErrGatewayDestinationTokenURLCASInvalid
	}
	return newGatewayDestinationTokenURLCASWithRepository(matcher, &gatewayDestinationTokenURLCASSQLRepository{db: db})
}

func newGatewayDestinationTokenURLCASWithRepository(matcher *GatewayTargetMatcher, repository gatewayDestinationTokenURLCASRepository) (*GatewayDestinationTokenURLCAS, error) {
	if matcher == nil || !matcher.valid() || nilGatewayDestinationTokenURLCASRepository(repository) {
		return nil, ErrGatewayDestinationTokenURLCASInvalid
	}
	return &GatewayDestinationTokenURLCAS{matcher: matcher, repository: repository}, nil
}

func nilGatewayDestinationTokenURLCASRepository(repository gatewayDestinationTokenURLCASRepository) bool {
	if repository == nil {
		return true
	}
	v := reflect.ValueOf(repository)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// CompareAndSwap replaces only the final opaque-token segment when the stored
// complete destination still equals the caller's expected complete destination.
func (s *GatewayDestinationTokenURLCAS) CompareAndSwap(ctx context.Context, request GatewayDestinationTokenURLCASRequest) error {
	if s == nil || !s.matcher.valid() || nilGatewayDestinationTokenURLCASRepository(s.repository) || ctx == nil {
		return ErrGatewayDestinationTokenURLCASInvalid
	}
	if !permission.System(ctx) {
		return ErrGatewayDestinationTokenURLCASPermissionDenied
	}
	if err := gatewayDestinationTokenURLCASContextError(ctx); err != nil {
		return err
	}

	expected, replacement, err := s.prepare(request)
	if err != nil {
		return ErrGatewayDestinationTokenURLCASInvalid
	}

	rowsAffected, err := s.repository.CompareAndSwapGatewayDestination(
		ctx,
		request.contactMethodID,
		expected,
		replacement,
	)
	if err != nil {
		switch err {
		case ErrGatewayDestinationTokenURLCASConflict,
			ErrGatewayDestinationTokenURLCASUnavailable,
			ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			ErrGatewayDestinationTokenURLCASCanceled,
			ErrGatewayDestinationTokenURLCASDeadlineExceeded:
			return err
		default:
			return ErrGatewayDestinationTokenURLCASOutcomeUnknown
		}
	}

	switch rowsAffected {
	case 0:
		return ErrGatewayDestinationTokenURLCASConflict
	case 1:
		return nil
	default:
		return ErrGatewayDestinationTokenURLCASUnavailable
	}
}

func (s *GatewayDestinationTokenURLCAS) prepare(request GatewayDestinationTokenURLCASRequest) (gadb.DestV1, gadb.DestV1, error) {
	if request.contactMethodID == uuid.Nil || request.expectedURL == "" || request.replacementToken == "" {
		return gadb.DestV1{}, gadb.DestV1{}, ErrGatewayDestinationTokenURLCASInvalid
	}

	target, err := url.Parse(request.expectedURL)
	if err != nil || target.String() != request.expectedURL {
		return gadb.DestV1{}, gadb.DestV1{}, ErrGatewayDestinationTokenURLCASInvalid
	}
	canonicalPath, matched := s.matcher.Match(target)
	if !matched {
		return gadb.DestV1{}, gadb.DestV1{}, ErrGatewayDestinationTokenURLCASInvalid
	}

	oldToken := strings.TrimPrefix(canonicalPath, gatewayContactMethodPathPrefix)
	if !validGatewayToken(request.replacementToken) || request.replacementToken == oldToken ||
		!strings.HasSuffix(request.expectedURL, oldToken) {
		return gadb.DestV1{}, gadb.DestV1{}, ErrGatewayDestinationTokenURLCASInvalid
	}

	replacementURL := strings.TrimSuffix(request.expectedURL, oldToken) + request.replacementToken
	replacementTarget, err := url.Parse(replacementURL)
	if err != nil || replacementTarget.String() != replacementURL {
		return gadb.DestV1{}, gadb.DestV1{}, ErrGatewayDestinationTokenURLCASInvalid
	}
	replacementPath, matched := s.matcher.Match(replacementTarget)
	if !matched || replacementPath != gatewayContactMethodPathPrefix+request.replacementToken {
		return gadb.DestV1{}, gadb.DestV1{}, ErrGatewayDestinationTokenURLCASInvalid
	}

	return NewWebhookDest(request.expectedURL), NewWebhookDest(replacementURL), nil
}

func (r *gatewayDestinationTokenURLCASSQLRepository) CompareAndSwapGatewayDestination(ctx context.Context, id uuid.UUID, expected, replacement gadb.DestV1) (int64, error) {
	if r == nil || r.db == nil || ctx == nil {
		return 0, ErrGatewayDestinationTokenURLCASUnavailable
	}
	if err := gatewayDestinationTokenURLCASContextError(ctx); err != nil {
		return 0, err
	}

	conn, err := r.db.Conn(ctx)
	if err != nil {
		if contextErr := gatewayDestinationTokenURLCASContextError(ctx); contextErr != nil {
			return 0, contextErr
		}
		return 0, ErrGatewayDestinationTokenURLCASUnavailable
	}
	if conn == nil {
		return 0, ErrGatewayDestinationTokenURLCASUnavailable
	}
	defer func() { _ = conn.Close() }()

	if err := gatewayDestinationTokenURLCASContextError(ctx); err != nil {
		return 0, err
	}

	result, err := gadb.New(conn).ContactMethodCompareAndSwapGatewayDest(ctx, gadb.ContactMethodCompareAndSwapGatewayDestParams{
		ID:              id,
		ReplacementDest: gadb.NullDestV1{Valid: true, DestV1: replacement},
		ExpectedDest:    gadb.NullDestV1{Valid: true, DestV1: expected},
	})
	if err != nil {
		classified := classifyGatewayDestinationTokenURLCASExecutionError(err)
		if classified == ErrGatewayDestinationTokenURLCASOutcomeUnknown {
			discardGatewayDestinationTokenURLCASConnection(conn)
		}
		return 0, classified
	}
	rowsAffected, valid := gatewayDestinationTokenURLCASRowsAffected(result)
	if !valid {
		discardGatewayDestinationTokenURLCASConnection(conn)
		return 0, ErrGatewayDestinationTokenURLCASOutcomeUnknown
	}
	return rowsAffected, nil
}

func gatewayDestinationTokenURLCASRowsAffected(result sql.Result) (rowsAffected int64, valid bool) {
	if result == nil {
		return 0, false
	}
	value := reflect.ValueOf(result)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		if value.IsNil() {
			return 0, false
		}
	}
	defer func() {
		if recover() != nil {
			rowsAffected = 0
			valid = false
		}
	}()
	rowsAffected, err := result.RowsAffected()
	return rowsAffected, err == nil
}

func gatewayDestinationTokenURLCASContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrGatewayDestinationTokenURLCASInvalid
	}
	switch ctx.Err() {
	case context.Canceled:
		return ErrGatewayDestinationTokenURLCASCanceled
	case context.DeadlineExceeded:
		return ErrGatewayDestinationTokenURLCASDeadlineExceeded
	default:
		return nil
	}
}

func classifyGatewayDestinationTokenURLCASExecutionError(err error) error {
	if err == nil {
		return nil
	}
	if gatewayDestinationTokenURLCASSingleCauseMatches(err, driver.ErrBadConn) ||
		gatewayDestinationTokenURLCASSingleCauseMatches(err, sql.ErrConnDone) ||
		(gatewayDestinationTokenURLCASSingleCauseChain(err) && pgconn.SafeToRetry(err)) {
		return ErrGatewayDestinationTokenURLCASUnavailable
	}

	databaseError, ok := gatewayDestinationTokenURLCASSingleCausePostgresError(err)
	if !ok {
		return ErrGatewayDestinationTokenURLCASOutcomeUnknown
	}
	if databaseError.Code == "23505" && (databaseError.ConstraintName == "user_contact_methods_dest_key" ||
		databaseError.ConstraintName == "user_contact_methods_type_value_key") {
		return ErrGatewayDestinationTokenURLCASConflict
	}
	if databaseError.Code == "40003" || strings.HasPrefix(databaseError.Code, "08") {
		return ErrGatewayDestinationTokenURLCASOutcomeUnknown
	}
	switch databaseError.Code {
	case "57P01", "57P02", "57P03", "57P04", "57P05":
		return ErrGatewayDestinationTokenURLCASOutcomeUnknown
	default:
		return ErrGatewayDestinationTokenURLCASUnavailable
	}
}

func gatewayDestinationTokenURLCASSingleCausePostgresError(err error) (*pgconn.PgError, bool) {
	for depth, current := 0, err; current != nil && depth < 64; depth++ {
		if _, multiple := current.(interface{ Unwrap() []error }); multiple {
			return nil, false
		}
		if gatewayDestinationTokenURLCASNilError(current) {
			return nil, false
		}
		if databaseError, ok := current.(*pgconn.PgError); ok && databaseError != nil {
			return databaseError, true
		}
		current = errors.Unwrap(current)
	}
	return nil, false
}

func gatewayDestinationTokenURLCASSingleCauseMatches(err, target error) bool {
	for depth, current := 0, err; current != nil && depth < 64; depth++ {
		if _, multiple := current.(interface{ Unwrap() []error }); multiple {
			return false
		}
		if gatewayDestinationTokenURLCASNilError(current) {
			return false
		}
		if reflect.TypeOf(current).Comparable() && current == target {
			return true
		}
		current = errors.Unwrap(current)
	}
	return false
}

func gatewayDestinationTokenURLCASSingleCauseChain(err error) bool {
	for depth, current := 0, err; current != nil && depth < 64; depth++ {
		if _, multiple := current.(interface{ Unwrap() []error }); multiple {
			return false
		}
		if gatewayDestinationTokenURLCASNilError(current) {
			return false
		}
		current = errors.Unwrap(current)
		if current == nil {
			return true
		}
	}
	return false
}

func gatewayDestinationTokenURLCASNilError(err error) bool {
	value := reflect.ValueOf(err)
	if !value.IsValid() {
		return true
	}
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func discardGatewayDestinationTokenURLCASConnection(conn *sql.Conn) {
	if conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = conn.Raw(func(driverConnection any) error {
		physicalConnection := gatewayDestinationTokenURLCASPhysicalConnection(driverConnection)
		if physicalConnection != nil {
			_ = physicalConnection.Close(ctx)
		}
		return driver.ErrBadConn
	})
}

type gatewayDestinationTokenURLCASConnectionCloser interface {
	Close(context.Context) error
}

type gatewayDestinationTokenURLCASConnectionProvider interface {
	gatewayDestinationTokenURLCASConnection() gatewayDestinationTokenURLCASConnectionCloser
}

func gatewayDestinationTokenURLCASPhysicalConnection(driverConnection any) gatewayDestinationTokenURLCASConnectionCloser {
	switch connection := driverConnection.(type) {
	case *stdlib.Conn:
		if connection != nil && connection.Conn() != nil {
			return connection.Conn()
		}
	case gatewayDestinationTokenURLCASConnectionProvider:
		return connection.gatewayDestinationTokenURLCASConnection()
	}
	return nil
}
