package webhook

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

const (
	testOnlyRotationDestinationID = "123e4567-e89b-12d3-a456-426614174099"
	testOnlyRotationHandleValue   = "test-only-exact-rotation-handle"
)

var testOnlyRotationNow = time.Date(2026, 8, 15, 3, 0, 0, 0, time.UTC)

type gatewayRotationTestCAS struct {
	mu      sync.Mutex
	calls   int
	err     error
	before  func(context.Context, GatewayDestinationTokenURLCASRequest)
	request GatewayDestinationTokenURLCASRequest
}

func (cas *gatewayRotationTestCAS) CompareAndSwap(ctx context.Context, request GatewayDestinationTokenURLCASRequest) error {
	cas.mu.Lock()
	cas.calls++
	cas.request = request
	before, err := cas.before, cas.err
	cas.mu.Unlock()
	if before != nil {
		before(ctx, request)
	}
	return err
}

func (cas *gatewayRotationTestCAS) callCount() int {
	cas.mu.Lock()
	defer cas.mu.Unlock()
	return cas.calls
}

type gatewayRotationTestStore struct {
	lock          sync.Mutex
	mu            sync.Mutex
	calls         int
	callbackCalls int
	destination   GatewayDestinationTokenRotationAuthoritativeDestination
	err           error
	callbackCount int
	before        func(context.Context)
}

func (store *gatewayRotationTestStore) WithLockedGatewayDestination(
	ctx context.Context,
	_ uuid.UUID,
	callback func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination),
) error {
	store.lock.Lock()
	defer store.lock.Unlock()
	store.mu.Lock()
	store.calls++
	count := store.callbackCount
	if count == 0 && store.err == nil {
		count = 1
	}
	destination, err, before := store.destination, store.err, store.before
	store.mu.Unlock()
	if before != nil {
		before(ctx)
	}
	if err != nil {
		return err
	}
	lockCtx, cancel := context.WithTimeout(ctx, gatewayDestinationTokenRotationRecoveryLimit)
	defer cancel()
	for range count {
		store.mu.Lock()
		store.callbackCalls++
		store.mu.Unlock()
		callback(lockCtx, destination)
	}
	return nil
}

func (store *gatewayRotationTestStore) counts() (calls, callbacks int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls, store.callbackCalls
}

type gatewayRotationTestParticipant struct {
	mu sync.Mutex

	beginCalls    int
	observeCalls  int
	rollbackCalls int
	finalizeCalls int

	beginAttempt GatewayDestinationTokenRotationParticipantAttempt
	beginErr     error
	observation  GatewayDestinationTokenRotationObservation
	observeErr   error
	rollbackErr  error
	finalizeErr  error

	beginFn       func(context.Context, GatewayDestinationTokenRotationBeginRequest)
	beginResultFn func(context.Context, GatewayDestinationTokenRotationBeginRequest) (GatewayDestinationTokenRotationParticipantAttempt, error)
	observeFn     func(context.Context, GatewayDestinationTokenRotationObserveRequest) (GatewayDestinationTokenRotationObservation, error)
	rollbackFn    func(context.Context, GatewayDestinationTokenRotationParticipantHandle) error
	finalizeFn    func(context.Context, GatewayDestinationTokenRotationFinalizeRequest) error
}

func (participant *gatewayRotationTestParticipant) BeginRotation(
	ctx context.Context,
	request GatewayDestinationTokenRotationBeginRequest,
) (GatewayDestinationTokenRotationParticipantAttempt, error) {
	participant.mu.Lock()
	participant.beginCalls++
	fn, resultFn, attempt, err := participant.beginFn, participant.beginResultFn, participant.beginAttempt, participant.beginErr
	participant.mu.Unlock()
	if resultFn != nil {
		return resultFn(ctx, request)
	}
	if fn != nil {
		fn(ctx, request)
	}
	return attempt, err
}

func (participant *gatewayRotationTestParticipant) ObserveRotation(
	ctx context.Context,
	request GatewayDestinationTokenRotationObserveRequest,
) (GatewayDestinationTokenRotationObservation, error) {
	participant.mu.Lock()
	participant.observeCalls++
	fn, observation, err := participant.observeFn, participant.observation, participant.observeErr
	participant.mu.Unlock()
	if fn != nil {
		return fn(ctx, request)
	}
	return observation, err
}

func (participant *gatewayRotationTestParticipant) RollbackRotation(
	ctx context.Context,
	handle GatewayDestinationTokenRotationParticipantHandle,
) error {
	participant.mu.Lock()
	participant.rollbackCalls++
	fn, err := participant.rollbackFn, participant.rollbackErr
	participant.mu.Unlock()
	if fn != nil {
		return fn(ctx, handle)
	}
	return err
}

func (participant *gatewayRotationTestParticipant) FinalizeRotation(
	ctx context.Context,
	request GatewayDestinationTokenRotationFinalizeRequest,
) error {
	participant.mu.Lock()
	participant.finalizeCalls++
	fn, err := participant.finalizeFn, participant.finalizeErr
	participant.mu.Unlock()
	if fn != nil {
		return fn(ctx, request)
	}
	return err
}

func (participant *gatewayRotationTestParticipant) counts() (begin, observe, rollback, finalize int) {
	participant.mu.Lock()
	defer participant.mu.Unlock()
	return participant.beginCalls, participant.observeCalls, participant.rollbackCalls, participant.finalizeCalls
}

func testOnlyRotationParticipantHandle(t *testing.T) GatewayDestinationTokenRotationParticipantHandle {
	t.Helper()
	handle, err := NewGatewayDestinationTokenRotationParticipantHandle([]byte(testOnlyRotationHandleValue))
	if err != nil {
		t.Fatal("failed to create test-only participant handle")
	}
	return handle
}

func testOnlyRotationAttempt(t *testing.T) GatewayDestinationTokenRotationParticipantAttempt {
	t.Helper()
	attempt, err := NewGatewayDestinationTokenRotationParticipantAttempt(
		testOnlyRotationParticipantHandle(t),
		testOnlyGatewayCASReplacementToken(0x70),
		testOnlyRotationNow,
		testOnlyRotationNow.Add(time.Hour),
	)
	if err != nil {
		t.Fatal("failed to create test-only participant attempt")
	}
	return attempt
}

func testOnlyRotationObservation(
	t *testing.T,
	state GatewayDestinationTokenRotationParticipantState,
	identity GatewayDestinationTokenRotationTokenIdentity,
	deadline time.Time,
) GatewayDestinationTokenRotationObservation {
	t.Helper()
	observedAt := time.Time{}
	if state == GatewayDestinationTokenRotationParticipantActiveWithRetiring {
		observedAt = testOnlyRotationNow
	}
	return testOnlyRotationObservationAt(t, state, identity, observedAt, deadline)
}

func testOnlyRotationObservationAt(
	t *testing.T,
	state GatewayDestinationTokenRotationParticipantState,
	identity GatewayDestinationTokenRotationTokenIdentity,
	observedAt time.Time,
	deadline time.Time,
) GatewayDestinationTokenRotationObservation {
	t.Helper()
	observation, err := NewGatewayDestinationTokenRotationObservation(state, identity, observedAt, deadline)
	if err != nil {
		t.Fatal("failed to create test-only participant observation")
	}
	return observation
}

func testOnlyRotationStartRequest() GatewayDestinationTokenRotationStartRequest {
	return NewGatewayDestinationTokenRotationStartRequest(
		testOnlyGatewayCASContactMethodID,
		testOnlyGatewayURL,
		testOnlyAudienceID,
		testOnlyRotationDestinationID,
	)
}

func testOnlyRotationAuthoritativeURL(value string) GatewayDestinationTokenRotationAuthoritativeDestination {
	return NewGatewayDestinationTokenRotationAuthoritativeDestination(NewWebhookDest(value))
}

func testOnlyRotationHandle(t *testing.T) GatewayDestinationTokenRotationHandle {
	t.Helper()
	return GatewayDestinationTokenRotationHandle{
		contactMethodID: testOnlyGatewayCASContactMethodID,
		participant:     testOnlyRotationParticipantHandle(t),
	}
}

func testOnlyRotationCoordinator(
	t *testing.T,
	cas gatewayDestinationTokenRotationCAS,
	store GatewayDestinationTokenRotationAuthoritativeStore,
	participant GatewayDestinationTokenRotationParticipant,
	now func() time.Time,
) *GatewayDestinationTokenRotationCoordinator {
	t.Helper()
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	if err != nil {
		t.Fatal("failed to create test-only matcher")
	}
	coordinator, err := newGatewayDestinationTokenRotationCoordinator(matcher, cas, store, participant, now)
	if err != nil {
		t.Fatal("failed to create test-only rotation coordinator")
	}
	return coordinator
}

func testOnlyRotationDefaultCoordinator(
	t *testing.T,
) (*GatewayDestinationTokenRotationCoordinator, *gatewayRotationTestCAS, *gatewayRotationTestStore, *gatewayRotationTestParticipant) {
	t.Helper()
	cas := &gatewayRotationTestCAS{}
	store := &gatewayRotationTestStore{destination: testOnlyRotationAuthoritativeURL(testOnlyGatewayURL)}
	participant := &gatewayRotationTestParticipant{beginAttempt: testOnlyRotationAttempt(t)}
	coordinator := testOnlyRotationCoordinator(t, cas, store, participant, time.Now)
	return coordinator, cas, store, participant
}

func requireRotationFixedError(t *testing.T, got, want, private error) {
	t.Helper()
	if got != want {
		t.Fatal("unexpected fixed rotation error classification")
	}
	if private != nil && (errors.Is(got, private) || strings.Contains(got.Error(), private.Error())) {
		t.Fatal("rotation error retained private dependency content")
	}
}

func TestGatewayDestinationTokenRotationCrossRepositoryDTOContract(t *testing.T) {
	if GatewayDestinationTokenRotationTokenNew != 1 ||
		GatewayDestinationTokenRotationTokenOld != 2 ||
		GatewayDestinationTokenRotationTokenNeither != 3 {
		t.Fatal("Core token-identity ordinals drifted from the reviewed Gateway contract")
	}
	if GatewayDestinationTokenRotationFinalizeDeadlineElapsed != 2 {
		t.Fatal("Core deadline-elapsed reason drifted from the reviewed Gateway lifecycle contract")
	}
	if GatewayDestinationTokenRotationParticipantActiveWithRetiring != 1 ||
		GatewayDestinationTokenRotationParticipantRolledBack != 2 ||
		GatewayDestinationTokenRotationParticipantCompleted != 3 {
		t.Fatal("Core participant-state ordinals drifted from the reviewed Gateway contract")
	}
	if gatewayDestinationTokenRotationMaxOverlap != 24*time.Hour {
		t.Fatal("Core retirement-deadline bound drifted from the reviewed Gateway protocol")
	}
	if gatewayDestinationTokenRotationBeginLimit != 5*time.Second ||
		gatewayDestinationTokenRotationCASLimit != 5*time.Second ||
		gatewayDestinationTokenRotationDiscardLimit != 5*time.Second ||
		gatewayDestinationTokenRotationRecoveryLimit != 5*time.Second ||
		gatewayDestinationTokenRotationReleaseLimit != 5*time.Second {
		t.Fatal("Core B/C/D/R/L protocol budgets drifted from five seconds")
	}
	attempt := testOnlyRotationAttempt(t)
	if !attempt.ActivatedAt().Equal(testOnlyRotationNow) {
		t.Fatal("Core Begin DTO lost the authoritative Gateway activation snapshot")
	}
	if !attempt.RetirementDeadline().Equal(testOnlyRotationNow.Add(time.Hour)) {
		t.Fatal("Core Begin DTO lost the authoritative Gateway retirement deadline")
	}
	observation := testOnlyRotationObservationAt(
		t,
		GatewayDestinationTokenRotationParticipantActiveWithRetiring,
		GatewayDestinationTokenRotationTokenNew,
		testOnlyRotationNow.Add(time.Minute),
		testOnlyRotationNow.Add(time.Hour),
	)
	if !observation.ObservedAt().Equal(testOnlyRotationNow.Add(time.Minute)) ||
		!observation.RetirementDeadline().Equal(testOnlyRotationNow.Add(time.Hour)) {
		t.Fatal("Core Observe DTO lost its same-operation O/G snapshot")
	}
}

func TestGatewayDestinationTokenRotationHandleBoundsAndDefensiveCopies(t *testing.T) {
	for _, value := range [][]byte{nil, make([]byte, gatewayDestinationTokenRotationMaxHandleBytes+1)} {
		if handle, err := NewGatewayDestinationTokenRotationParticipantHandle(value); handle.valid() ||
			err != ErrGatewayDestinationTokenRotationInvalid {
			t.Fatal("invalid participant handle length was accepted")
		}
	}
	if handle, err := NewGatewayDestinationTokenRotationParticipantHandle(
		make([]byte, gatewayDestinationTokenRotationMaxHandleBytes),
	); err != nil || !handle.valid() {
		t.Fatal("maximum-size participant handle was rejected")
	}

	source := []byte(testOnlyRotationHandleValue)
	handle, err := NewGatewayDestinationTokenRotationParticipantHandle(source)
	if err != nil {
		t.Fatal("valid participant handle was rejected")
	}
	source[0] ^= 0xff
	first := handle.Bytes()
	if string(first) != testOnlyRotationHandleValue {
		t.Fatal("participant handle retained constructor input storage")
	}
	first[0] ^= 0xff
	if string(handle.Bytes()) != testOnlyRotationHandleValue {
		t.Fatal("participant handle exposed mutable internal storage")
	}

	outer := GatewayDestinationTokenRotationHandle{
		contactMethodID: testOnlyGatewayCASContactMethodID,
		participant:     handle,
	}
	result := gatewayDestinationTokenRotationResult(GatewayDestinationTokenRotationPendingFinalization, outer)
	copyOne := result.Handle()
	copyOne.participant.value[0] ^= 0xff
	if string(result.Handle().participant.Bytes()) != testOnlyRotationHandleValue {
		t.Fatal("coordinator result exposed mutable continuation-handle storage")
	}
}

func TestGatewayDestinationTokenRotationRejectsInvalidObservations(t *testing.T) {
	for _, test := range []struct {
		state    GatewayDestinationTokenRotationParticipantState
		identity GatewayDestinationTokenRotationTokenIdentity
		observed time.Time
		deadline time.Time
	}{
		{identity: GatewayDestinationTokenRotationTokenNew},
		{state: GatewayDestinationTokenRotationParticipantActiveWithRetiring, deadline: testOnlyRotationNow},
		{state: GatewayDestinationTokenRotationParticipantActiveWithRetiring, identity: GatewayDestinationTokenRotationTokenNew},
		{state: GatewayDestinationTokenRotationParticipantRolledBack, identity: GatewayDestinationTokenRotationTokenOld, observed: testOnlyRotationNow},
		{state: GatewayDestinationTokenRotationParticipantRolledBack, identity: GatewayDestinationTokenRotationTokenOld, deadline: testOnlyRotationNow},
		{state: GatewayDestinationTokenRotationParticipantCompleted, identity: GatewayDestinationTokenRotationTokenIdentity(4)},
	} {
		observation, err := NewGatewayDestinationTokenRotationObservation(test.state, test.identity, test.observed, test.deadline)
		if observation.valid() || err != ErrGatewayDestinationTokenRotationInvalid {
			t.Fatal("invalid participant observation was accepted")
		}
	}
	if attempt, err := NewGatewayDestinationTokenRotationParticipantAttempt(
		testOnlyRotationParticipantHandle(t),
		testOnlyGatewayCASReplacementToken(0x70),
		testOnlyRotationNow,
		time.Time{},
	); attempt.valid() || err != ErrGatewayDestinationTokenRotationInvalid {
		t.Fatal("confirmed Begin attempt without an authoritative deadline was accepted")
	}
	for _, interval := range []struct {
		start, deadline time.Time
	}{
		{deadline: testOnlyRotationNow.Add(time.Hour)},
		{start: testOnlyRotationNow, deadline: testOnlyRotationNow},
		{start: testOnlyRotationNow, deadline: testOnlyRotationNow.Add(gatewayDestinationTokenRotationMaxOverlap + time.Nanosecond)},
	} {
		attempt, err := NewGatewayDestinationTokenRotationParticipantAttempt(
			testOnlyRotationParticipantHandle(t),
			testOnlyGatewayCASReplacementToken(0x70),
			interval.start,
			interval.deadline,
		)
		if attempt.valid() || err != ErrGatewayDestinationTokenRotationInvalid {
			t.Fatal("confirmed Begin attempt accepted an invalid authoritative A/G interval")
		}
	}
}

func TestGatewayDestinationTokenRotationStartOrderAndRedaction(t *testing.T) {
	coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
	var sequenceMu sync.Mutex
	var sequence []string
	participant.beginFn = func(_ context.Context, request GatewayDestinationTokenRotationBeginRequest) {
		sequenceMu.Lock()
		sequence = append(sequence, "gateway-begin")
		sequenceMu.Unlock()
		if request.Audience() != testOnlyAudienceID || request.Destination() != testOnlyRotationDestinationID ||
			request.CurrentToken() != testOnlyGatewayToken {
			t.Fatal("participant received an invalid validated begin request")
		}
	}
	cas.before = func(_ context.Context, request GatewayDestinationTokenURLCASRequest) {
		sequenceMu.Lock()
		sequence = append(sequence, "core-cas")
		sequenceMu.Unlock()
		if request.replacementToken != testOnlyGatewayCASReplacementToken(0x70) {
			t.Fatal("Core CAS did not consume the one-time Gateway token")
		}
	}

	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	if err != nil {
		t.Fatal("valid rotation start failed")
	}
	if result.Status() != GatewayDestinationTokenRotationPendingFinalization || !result.Handle().valid() {
		t.Fatal("rotation start did not return a pending-finalization handle")
	}
	sequenceMu.Lock()
	if fmt.Sprint(sequence) != "[gateway-begin core-cas]" {
		t.Fatal("rotation start did not execute Gateway Begin before Core CAS")
	}
	sequenceMu.Unlock()
	if cas.callCount() != 1 {
		t.Fatal("rotation start did not call Core CAS exactly once")
	}
	if calls, _ := store.counts(); calls != 0 {
		t.Fatal("confirmed CAS success performed an authoritative read")
	}
	begin, observe, rollback, finalize := participant.counts()
	if begin != 1 || observe != 0 || rollback != 0 || finalize != 0 {
		t.Fatal("confirmed CAS success performed an unexpected participant operation")
	}

	for _, value := range []any{
		testOnlyRotationStartRequest(), result, &result, result.Handle(), coordinator,
		participant.beginAttempt, participant.beginAttempt.handle,
	} {
		for _, formatted := range []string{
			fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value), fmt.Sprintf("%s", value),
		} {
			if formatted != "[redacted]" || strings.Contains(formatted, testOnlyGatewayToken) {
				t.Fatal("sensitive rotation value did not format as redacted")
			}
		}
	}
}

func TestGatewayDestinationTokenRotationRequiresSystemBeforeDependencies(t *testing.T) {
	contexts := []context.Context{
		context.Background(),
		permission.UserContext(context.Background(), "11111111-1111-1111-8111-111111111111", permission.RoleUser),
		permission.UserContext(context.Background(), "11111111-1111-1111-8111-111111111111", permission.RoleAdmin),
		permission.ServiceContext(context.Background(), "11111111-1111-1111-8111-111111111111"),
		permission.TeamContext(context.Background(), "11111111-1111-1111-8111-111111111111"),
	}
	for _, ctx := range contexts {
		coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
		_, err := coordinator.Start(ctx, testOnlyRotationStartRequest())
		requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationPermissionDenied, nil)
		_, err = coordinator.Reconcile(ctx, testOnlyRotationHandle(t))
		requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationPermissionDenied, nil)
		_, err = coordinator.Finalize(ctx, testOnlyRotationHandle(t))
		requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationPermissionDenied, nil)
		if cas.callCount() != 0 {
			t.Fatal("non-System rotation reached Core CAS")
		}
		if calls, _ := store.counts(); calls != 0 {
			t.Fatal("non-System rotation reached authoritative store")
		}
		if begin, observe, rollback, finalize := participant.counts(); begin+observe+rollback+finalize != 0 {
			t.Fatal("non-System rotation reached Gateway participant")
		}
	}
}

func TestGatewayDestinationTokenRotationRejectsInvalidStartBeforeParticipant(t *testing.T) {
	tests := []struct {
		name        string
		id          uuid.UUID
		expectedURL string
		audience    string
		destination string
	}{
		{name: "zero ID", expectedURL: testOnlyGatewayURL, audience: testOnlyAudienceID, destination: testOnlyRotationDestinationID},
		{name: "ordinary webhook", id: testOnlyGatewayCASContactMethodID, expectedURL: "https://hooks.test.invalid/path", audience: testOnlyAudienceID, destination: testOnlyRotationDestinationID},
		{name: "noncanonical Gateway", id: testOnlyGatewayCASContactMethodID, expectedURL: testOnlyGatewayURL + "?", audience: testOnlyAudienceID, destination: testOnlyRotationDestinationID},
		{name: "bad audience", id: testOnlyGatewayCASContactMethodID, expectedURL: testOnlyGatewayURL, audience: "not-a-uuid", destination: testOnlyRotationDestinationID},
		{name: "bad destination", id: testOnlyGatewayCASContactMethodID, expectedURL: testOnlyGatewayURL, audience: testOnlyAudienceID, destination: "not-a-uuid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
			request := NewGatewayDestinationTokenRotationStartRequest(test.id, test.expectedURL, test.audience, test.destination)
			_, err := coordinator.Start(testOnlyGatewayCASSystemContext(), request)
			requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationInvalid, nil)
			if cas.callCount() != 0 {
				t.Fatal("invalid start reached Core CAS")
			}
			if begin, observe, rollback, finalize := participant.counts(); begin+observe+rollback+finalize != 0 {
				t.Fatal("invalid start reached Gateway participant")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationBeginFailureAndHandle(t *testing.T) {
	private := errors.New("test-only-private-begin:" + testOnlyGatewayToken)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid", err: ErrGatewayDestinationTokenRotationInvalid, want: ErrGatewayDestinationTokenRotationInvalid},
		{name: "permission", err: ErrGatewayDestinationTokenRotationPermissionDenied, want: ErrGatewayDestinationTokenRotationPermissionDenied},
		{name: "conflict", err: ErrGatewayDestinationTokenRotationConflict, want: ErrGatewayDestinationTokenRotationConflict},
		{name: "unavailable", err: ErrGatewayDestinationTokenRotationUnavailable, want: ErrGatewayDestinationTokenRotationUnavailable},
		{name: "canceled", err: ErrGatewayDestinationTokenRotationCanceled, want: ErrGatewayDestinationTokenRotationCanceled},
		{name: "deadline", err: ErrGatewayDestinationTokenRotationDeadlineExceeded, want: ErrGatewayDestinationTokenRotationDeadlineExceeded},
		{name: "outcome unknown", err: ErrGatewayDestinationTokenRotationOutcomeUnknown, want: ErrGatewayDestinationTokenRotationReconciliationRequired},
		{name: "reconciliation", err: ErrGatewayDestinationTokenRotationReconciliationRequired, want: ErrGatewayDestinationTokenRotationReconciliationRequired},
		{name: "private", err: private, want: ErrGatewayDestinationTokenRotationReconciliationRequired},
		{name: "joined safe and private", err: errors.Join(ErrGatewayDestinationTokenRotationConflict, private), want: ErrGatewayDestinationTokenRotationReconciliationRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
			participant.beginAttempt = GatewayDestinationTokenRotationParticipantAttempt{}
			participant.beginErr = test.err
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			requireRotationFixedError(t, err, test.want, private)
			if result.Handle().valid() {
				t.Fatal("handle-free Begin failure returned a continuation handle")
			}
			if cas.callCount() != 0 {
				t.Fatal("failed Begin reached Core CAS")
			}
			if calls, _ := store.counts(); calls != 0 {
				t.Fatal("failed Begin reached Core authoritative store")
			}
		})
	}

	reconciliationAttempt, err := NewGatewayDestinationTokenRotationParticipantReconciliationAttempt(testOnlyRotationParticipantHandle(t))
	if err != nil {
		t.Fatal("failed to construct test-only handle-only attempt")
	}
	if !reconciliationAttempt.ActivatedAt().IsZero() || !reconciliationAttempt.RetirementDeadline().IsZero() {
		t.Fatal("handle-only Begin reconciliation attempt exposed an unconfirmed A/G receipt")
	}
	for _, test := range tests {
		t.Run(test.name+" with handle", func(t *testing.T) {
			coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
			participant.beginAttempt = reconciliationAttempt
			participant.beginErr = test.err
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, private)
			if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
				t.Fatal("Begin failure with a valid handle did not require reconciliation and preserve the handle")
			}
			if cas.callCount() != 0 {
				t.Fatal("handle-only Begin failure reached Core CAS")
			}
			if calls, _ := store.counts(); calls != 0 {
				t.Fatal("handle-only Begin failure reached Core authoritative store")
			}
		})
	}

	for _, newToken := range []string{"not-a-canonical-token", testOnlyGatewayToken} {
		coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
		participant.beginAttempt = GatewayDestinationTokenRotationParticipantAttempt{
			handle:             testOnlyRotationParticipantHandle(t),
			newToken:           newToken,
			retirementDeadline: testOnlyRotationNow.Add(time.Hour),
		}
		result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
		requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, nil)
		if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
			t.Fatal("malformed successful Begin lost its valid continuation handle")
		}
		if cas.callCount() != 0 {
			t.Fatal("malformed successful Begin reached Core CAS")
		}
	}
	coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
	participant.beginAttempt.retirementDeadline = time.Time{}
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, nil)
	if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() || cas.callCount() != 0 {
		t.Fatal("deadline-free successful Begin did not fail closed with its handle before CAS")
	}
}

func TestGatewayDestinationTokenRotationCASConfirmedNoMutationRollsBackOnce(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid", err: ErrGatewayDestinationTokenURLCASInvalid, want: ErrGatewayDestinationTokenRotationInvalid},
		{name: "permission", err: ErrGatewayDestinationTokenURLCASPermissionDenied, want: ErrGatewayDestinationTokenRotationPermissionDenied},
		{name: "conflict", err: ErrGatewayDestinationTokenURLCASConflict, want: ErrGatewayDestinationTokenRotationConflict},
		{name: "unavailable", err: ErrGatewayDestinationTokenURLCASUnavailable, want: ErrGatewayDestinationTokenRotationUnavailable},
		{name: "canceled", err: ErrGatewayDestinationTokenURLCASCanceled, want: ErrGatewayDestinationTokenRotationCanceled},
		{name: "deadline", err: ErrGatewayDestinationTokenURLCASDeadlineExceeded, want: ErrGatewayDestinationTokenRotationDeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
			cas.err = test.err
			participant.rollbackFn = func(ctx context.Context, handle GatewayDestinationTokenRotationParticipantHandle) error {
				if ctx.Err() != nil || !permission.System(ctx) || !handle.valid() {
					t.Fatal("safe CAS compensation did not use a fresh bounded System context")
				}
				return nil
			}
			_, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			requireRotationFixedError(t, err, test.want, nil)
			if cas.callCount() != 1 {
				t.Fatal("safe CAS failure was retried")
			}
			if calls, _ := store.counts(); calls != 0 {
				t.Fatal("safe CAS failure performed an unnecessary authoritative read")
			}
			_, _, rollback, _ := participant.counts()
			if rollback != 1 {
				t.Fatal("safe CAS failure did not perform exactly one rollback")
			}
		})
	}

	coordinator, _, _, participant := testOnlyRotationDefaultCoordinator(t)
	coordinator.cas.(*gatewayRotationTestCAS).err = ErrGatewayDestinationTokenURLCASConflict
	participant.rollbackErr = ErrGatewayDestinationTokenRotationConflict
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, nil)
	if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
		t.Fatal("failed safe-CAS rollback lost the post-Begin continuation handle")
	}
	_, _, rollback, _ := participant.counts()
	if rollback != 1 {
		t.Fatal("failed rollback was retried")
	}
}

func TestGatewayDestinationTokenRotationCASUnknownMatrix(t *testing.T) {
	private := errors.New("test-only-private-CAS:" + testOnlyGatewayToken)
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	tests := []struct {
		name         string
		casErr       error
		destination  GatewayDestinationTokenRotationAuthoritativeDestination
		observation  GatewayDestinationTokenRotationObservation
		observeErr   error
		rollbackErr  error
		storeErr     error
		wantStatus   GatewayDestinationTokenRotationStatus
		wantErr      error
		wantObserve  int
		wantRollback int
	}{
		{
			name: "new token and exact pair confirms success", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(newURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(time.Hour)),
			wantStatus:  GatewayDestinationTokenRotationPendingFinalization, wantObserve: 1,
		},
		{
			name: "old token and exact pair rolls back safely", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(testOnlyGatewayURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow.Add(time.Hour)),
			wantErr:     ErrGatewayDestinationTokenRotationUnavailable, wantObserve: 1, wantRollback: 1,
		},
		{
			name: "old token exact pair rollback failure", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(testOnlyGatewayURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow.Add(time.Hour)),
			rollbackErr: ErrGatewayDestinationTokenRotationConflict,
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1, wantRollback: 1,
		},
		{
			name: "old token mismatched attempt deadline cannot rollback", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(testOnlyGatewayURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1,
		},
		{
			name: "new token mismatched attempt deadline requires reconciliation", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(newURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1,
		},
		{
			name: "third token", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x20)),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNeither, testOnlyRotationNow.Add(time.Hour)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1,
		},
		{
			name: "old token but already rolled back is not an unknown-CAS shortcut", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(testOnlyGatewayURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantRolledBack, GatewayDestinationTokenRotationTokenOld, time.Time{}),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1,
		},
		{
			name: "new token but already finalized is not an unknown-CAS shortcut", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(newURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantCompleted, GatewayDestinationTokenRotationTokenNew, time.Time{}),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1,
		},
		{
			name: "non Gateway authoritative destination", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL("https://hooks.test.invalid/notify"),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "malformed authoritative destination", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: NewGatewayDestinationTokenRotationAuthoritativeDestination(gadb.DestV1{Type: DestTypeWebhook, Args: map[string]string{}}),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "authoritative lock read failure", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(newURL), storeErr: private,
			wantErr: ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "observation failure", casErr: ErrGatewayDestinationTokenURLCASOutcomeUnknown,
			destination: testOnlyRotationAuthoritativeURL(newURL), observeErr: private,
			wantErr: ErrGatewayDestinationTokenRotationReconciliationRequired, wantObserve: 1,
		},
		{
			name: "unrecognized CAS failure has no quarantine proof", casErr: private,
			destination: testOnlyRotationAuthoritativeURL(newURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(time.Hour)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "unconfirmed physical quarantine never enters recovery", casErr: errGatewayDestinationTokenRotationQuarantineUnconfirmed,
			destination: testOnlyRotationAuthoritativeURL(newURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(time.Hour)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "joined conflict has no quarantine proof", casErr: errors.Join(ErrGatewayDestinationTokenURLCASConflict, private),
			destination: testOnlyRotationAuthoritativeURL(newURL),
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(time.Hour)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
			cas.err = test.casErr
			store.destination = test.destination
			store.err = test.storeErr
			participant.observation = test.observation
			participant.observeErr = test.observeErr
			participant.rollbackErr = test.rollbackErr
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			if test.wantErr == nil {
				if err != nil || result.Status() != test.wantStatus {
					t.Fatal("CAS unknown matrix returned an unexpected proven state")
				}
			} else {
				requireRotationFixedError(t, err, test.wantErr, private)
				if test.wantErr == ErrGatewayDestinationTokenRotationReconciliationRequired &&
					(result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid()) {
					t.Fatal("CAS unknown reconciliation path lost the post-Begin continuation handle")
				}
			}
			if cas.callCount() != 1 {
				t.Fatal("CAS unknown path retried Core CAS")
			}
			_, observe, rollback, finalize := participant.counts()
			if observe != test.wantObserve || rollback != test.wantRollback || finalize != 0 {
				t.Fatal("CAS unknown path executed an invalid participant operation matrix")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationUnknownUsesFreshUncanceledLockedRead(t *testing.T) {
	coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
	callerCtx, cancelCaller := context.WithCancel(testOnlyGatewayCASSystemContext())
	cas.before = func(context.Context, GatewayDestinationTokenURLCASRequest) { cancelCaller() }
	cas.err = ErrGatewayDestinationTokenURLCASOutcomeUnknown
	store.destination = testOnlyRotationAuthoritativeURL(testOnlyGatewayURL)
	store.before = func(ctx context.Context) {
		if ctx.Err() != nil || !permission.System(ctx) {
			t.Fatal("unknown-CAS authoritative read inherited caller cancellation or lost System permission")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unknown-CAS authoritative read was not bounded")
		}
	}
	participant.observation = testOnlyRotationObservation(
		t,
		GatewayDestinationTokenRotationParticipantActiveWithRetiring,
		GatewayDestinationTokenRotationTokenOld,
		testOnlyRotationNow.Add(time.Hour),
	)
	participant.rollbackFn = func(ctx context.Context, _ GatewayDestinationTokenRotationParticipantHandle) error {
		if ctx.Err() != nil || !permission.System(ctx) {
			t.Fatal("unknown-CAS rollback inherited caller cancellation or lost System permission")
		}
		return nil
	}

	_, err := coordinator.Start(callerCtx, testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationUnavailable, nil)
	if cas.callCount() != 1 {
		t.Fatal("unknown-CAS recovery retried CAS")
	}
	if calls, callbacks := store.counts(); calls != 1 || callbacks != 1 {
		t.Fatal("unknown-CAS recovery did not perform one locked read")
	}
	_, observe, rollback, _ := participant.counts()
	if observe != 1 || rollback != 1 {
		t.Fatal("unknown-CAS recovery did not observe then rollback exactly once")
	}
}

func TestGatewayDestinationTokenRotationSafeCanceledCASStillUsesFreshRollbackContext(t *testing.T) {
	coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
	callerCtx, cancelCaller := context.WithCancel(testOnlyGatewayCASSystemContext())
	cas.before = func(context.Context, GatewayDestinationTokenURLCASRequest) { cancelCaller() }
	cas.err = ErrGatewayDestinationTokenURLCASCanceled
	participant.rollbackFn = func(ctx context.Context, _ GatewayDestinationTokenRotationParticipantHandle) error {
		if ctx.Err() != nil || !permission.System(ctx) {
			t.Fatal("safe canceled CAS rollback inherited canceled caller context")
		}
		return nil
	}
	_, err := coordinator.Start(callerCtx, testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationCanceled, nil)
	if calls, _ := store.counts(); calls != 0 {
		t.Fatal("safe canceled CAS performed an authoritative read")
	}
	_, _, rollback, _ := participant.counts()
	if rollback != 1 {
		t.Fatal("safe canceled CAS did not rollback exactly once")
	}
}

func TestGatewayDestinationTokenRotationBoundsPostBeginCASAndReservesRollback(t *testing.T) {
	coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
	deadline := testOnlyRotationNow.Add(
		gatewayDestinationTokenRotationCASLimit + gatewayDestinationTokenRotationDiscardLimit +
			gatewayDestinationTokenRotationRecoveryLimit + time.Second,
	)
	participant.beginAttempt.activatedAt = testOnlyRotationNow
	participant.beginAttempt.retirementDeadline = deadline
	callerCtx, cancelCaller := context.WithTimeout(testOnlyGatewayCASSystemContext(), time.Second)
	defer cancelCaller()
	cas.before = func(ctx context.Context, _ GatewayDestinationTokenURLCASRequest) {
		if ctx.Err() != nil || !permission.System(ctx) {
			t.Fatal("admitted CAS lost its live caller deadline or System permission")
		}
		contextDeadline, ok := ctx.Deadline()
		remaining := time.Until(contextDeadline)
		if !ok || remaining <= 0 || remaining > time.Second {
			t.Fatal("admitted CAS did not preserve the earlier caller deadline")
		}
	}
	result, err := coordinator.Start(callerCtx, testOnlyRotationStartRequest())
	if err != nil || result.Status() != GatewayDestinationTokenRotationPendingFinalization || cas.callCount() != 1 {
		t.Fatal("bounded CAS did not complete one admitted transition")
	}
}

func TestGatewayDestinationTokenRotationBeginUsesAbsoluteFiveSecondBound(t *testing.T) {
	for _, test := range []struct {
		name          string
		callerTimeout time.Duration
	}{
		{name: "local begin cap"},
		{name: "earlier caller deadline", callerTimeout: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator, _, _, participant := testOnlyRotationDefaultCoordinator(t)
			ctx := testOnlyGatewayCASSystemContext()
			cancel := func() {}
			if test.callerTimeout != 0 {
				ctx, cancel = context.WithTimeout(ctx, test.callerTimeout)
			}
			defer cancel()
			participant.beginFn = func(beginCtx context.Context, _ GatewayDestinationTokenRotationBeginRequest) {
				deadline, bounded := beginCtx.Deadline()
				remaining := time.Until(deadline)
				wantMaximum := gatewayDestinationTokenRotationBeginLimit
				if test.callerTimeout != 0 {
					wantMaximum = test.callerTimeout
				}
				if !bounded || remaining <= 0 || remaining > wantMaximum {
					t.Fatal("Gateway Begin did not receive the required earlier absolute deadline")
				}
			}
			result, err := coordinator.Start(ctx, testOnlyRotationStartRequest())
			if err != nil || result.Status() != GatewayDestinationTokenRotationPendingFinalization {
				t.Fatal("bounded Gateway Begin did not complete the valid transition")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationBeginSamplingConsumesOverlap(t *testing.T) {
	coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
	anchor := time.Now()
	current := anchor
	coordinator.monotonicNow = func() time.Time { return current }
	participant.beginAttempt.activatedAt = testOnlyRotationNow
	participant.beginAttempt.retirementDeadline = testOnlyRotationNow.Add(
		gatewayDestinationTokenRotationCASLimit + gatewayDestinationTokenRotationDiscardLimit +
			gatewayDestinationTokenRotationRecoveryLimit + gatewayDestinationTokenRotationBeginLimit,
	)
	participant.beginFn = func(context.Context, GatewayDestinationTokenRotationBeginRequest) {
		current = anchor.Add(gatewayDestinationTokenRotationBeginLimit)
	}
	participant.rollbackFn = func(ctx context.Context, _ GatewayDestinationTokenRotationParticipantHandle) error {
		deadline, bounded := ctx.Deadline()
		want := current.Add(gatewayDestinationTokenRotationRecoveryLimit)
		if !bounded || !deadline.Equal(want) {
			t.Fatal("pre-CAS rollback did not use min(now+R, localG)")
		}
		return nil
	}
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	if err != ErrGatewayDestinationTokenRotationUnavailable || result.Status() != 0 {
		t.Fatal("time spent after the pre-Begin sample was not charged to the local overlap")
	}
	if cas.callCount() != 0 {
		t.Fatal("strict C+D+R boundary admitted Core CAS after Begin pause")
	}
	if _, _, rollback, _ := participant.counts(); rollback != 1 {
		t.Fatal("strict C+D+R boundary did not perform one bounded pre-CAS rollback")
	}
}

func TestGatewayDestinationTokenRotationGatewayClockOffsetDoesNotShiftCASBudget(t *testing.T) {
	coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
	anchor := time.Now()
	coordinator.monotonicNow = func() time.Time { return anchor }
	remoteActivation := time.Date(2042, 4, 3, 2, 1, 0, 0, time.FixedZone("test-only-offset", 13*60*60))
	participant.beginAttempt.activatedAt = remoteActivation
	participant.beginAttempt.retirementDeadline = remoteActivation.Add(time.Hour)
	cas.before = func(ctx context.Context, _ GatewayDestinationTokenURLCASRequest) {
		deadline, bounded := ctx.Deadline()
		if !bounded || !deadline.Equal(anchor.Add(gatewayDestinationTokenRotationCASLimit)) {
			t.Fatal("Gateway wall-clock offset changed the local absolute CAS deadline")
		}
	}
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	if err != nil || result.Status() != GatewayDestinationTokenRotationPendingFinalization {
		t.Fatal("valid A/G duration with a remote clock offset was rejected")
	}
}

func TestGatewayDestinationTokenRotationUnknownAtLocalDeadlineMatrix(t *testing.T) {
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	for _, test := range []struct {
		name        string
		identity    GatewayDestinationTokenRotationTokenIdentity
		destination string
		wantStatus  GatewayDestinationTokenRotationStatus
		wantErr     error
	}{
		{
			name: "final Core old cannot rollback", identity: GatewayDestinationTokenRotationTokenOld,
			destination: testOnlyGatewayURL, wantStatus: GatewayDestinationTokenRotationNeedsReconciliation,
			wantErr: ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "final Core new remains pending", identity: GatewayDestinationTokenRotationTokenNew,
			destination: newURL, wantStatus: GatewayDestinationTokenRotationPendingFinalization,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
			anchor := time.Now()
			current := anchor
			coordinator.monotonicNow = func() time.Time { return current }
			localDeadline := anchor.Add(participant.beginAttempt.retirementDeadline.Sub(participant.beginAttempt.activatedAt))
			cas.err = ErrGatewayDestinationTokenURLCASOutcomeUnknown
			store.destination = testOnlyRotationAuthoritativeURL(test.destination)
			observation := testOnlyRotationObservationAt(
				t,
				GatewayDestinationTokenRotationParticipantActiveWithRetiring,
				test.identity,
				participant.beginAttempt.activatedAt,
				participant.beginAttempt.retirementDeadline,
			)
			participant.observeFn = func(context.Context, GatewayDestinationTokenRotationObserveRequest) (GatewayDestinationTokenRotationObservation, error) {
				current = localDeadline
				return observation, nil
			}
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			if err != test.wantErr || result.Status() != test.wantStatus {
				t.Fatal("unknown-CAS local-deadline matrix returned an unsafe state")
			}
			if _, observe, rollback, _ := participant.counts(); observe != 1 || rollback != 0 {
				t.Fatal("unknown-CAS local-deadline matrix executed an invalid recovery mutation")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationObserveSamplingConsumesRemainingDuration(t *testing.T) {
	coordinator, _, store, participant := testOnlyRotationDefaultCoordinator(t)
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	store.destination = testOnlyRotationAuthoritativeURL(newURL)
	anchor := time.Now()
	current := anchor
	coordinator.monotonicNow = func() time.Time { return current }
	remoteObservedAt := time.Date(2044, 7, 8, 9, 10, 11, 0, time.FixedZone("test-only-offset", -9*60*60))
	observation := testOnlyRotationObservationAt(
		t,
		GatewayDestinationTokenRotationParticipantActiveWithRetiring,
		GatewayDestinationTokenRotationTokenNew,
		remoteObservedAt,
		remoteObservedAt.Add(time.Second),
	)
	participant.observeFn = func(context.Context, GatewayDestinationTokenRotationObserveRequest) (GatewayDestinationTokenRotationObservation, error) {
		current = anchor.Add(2 * time.Second)
		return observation, nil
	}
	result, err := coordinator.Finalize(testOnlyGatewayCASSystemContext(), testOnlyRotationHandle(t))
	if err != nil || result.Status() != GatewayDestinationTokenRotationCompleted {
		t.Fatal("time spent after the pre-Observe sample was not charged to G-O")
	}
	if _, observe, rollback, finalize := participant.counts(); observe != 1 || rollback != 0 || finalize != 1 {
		t.Fatal("Observe sampling test executed an invalid participant matrix")
	}
}

func TestGatewayDestinationTokenRotationInsufficientWindowRollsBackBeforeCAS(t *testing.T) {
	for _, test := range []struct {
		name         string
		deadline     time.Time
		wantErr      error
		wantRollback int
	}{
		{
			name: "exact minimum window is rejected",
			deadline: testOnlyRotationNow.Add(
				gatewayDestinationTokenRotationCASLimit + gatewayDestinationTokenRotationDiscardLimit +
					gatewayDestinationTokenRotationRecoveryLimit,
			),
			wantErr: ErrGatewayDestinationTokenRotationUnavailable, wantRollback: 1,
		},
		{
			name:     "elapsed overlap cannot be rolled back",
			deadline: testOnlyRotationNow, wantErr: ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name:     "deadline beyond protocol maximum is rejected",
			deadline: testOnlyRotationNow.Add(gatewayDestinationTokenRotationMaxOverlap + time.Nanosecond),
			wantErr:  ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
			participant.beginAttempt.retirementDeadline = test.deadline
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			requireRotationFixedError(t, err, test.wantErr, nil)
			if cas.callCount() != 0 {
				t.Fatal("insufficient overlap window reached Core CAS")
			}
			if calls, callbacks := store.counts(); calls != 0 || callbacks != 0 {
				t.Fatal("pre-CAS timing rejection performed an authoritative Core read")
			}
			_, _, rollback, _ := participant.counts()
			if rollback != test.wantRollback {
				t.Fatal("pre-CAS timing rejection used an invalid rollback matrix")
			}
			if test.wantErr == ErrGatewayDestinationTokenRotationReconciliationRequired &&
				(result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid()) {
				t.Fatal("elapsed pre-CAS overlap lost its continuation handle")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationCancellationObservedAfterBeginRollsBackBeforeCAS(t *testing.T) {
	coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
	callerCtx, cancelCaller := context.WithCancel(testOnlyGatewayCASSystemContext())
	participant.beginFn = func(context.Context, GatewayDestinationTokenRotationBeginRequest) { cancelCaller() }
	participant.rollbackFn = func(ctx context.Context, _ GatewayDestinationTokenRotationParticipantHandle) error {
		if ctx.Err() != nil || !permission.System(ctx) {
			t.Fatal("post-Begin cancellation rollback was not detached and bounded")
		}
		return nil
	}
	_, err := coordinator.Start(callerCtx, testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationCanceled, nil)
	if cas.callCount() != 0 {
		t.Fatal("cancellation observed after Begin still admitted Core CAS")
	}
	_, _, rollback, _ := participant.counts()
	if rollback != 1 {
		t.Fatal("cancellation observed after Begin did not rollback exactly once")
	}
}

func TestGatewayDestinationTokenRotationSafeCASAfterDeadlineDoesNotRollback(t *testing.T) {
	coordinator, cas, _, participant := testOnlyRotationDefaultCoordinator(t)
	var nowMu sync.Mutex
	current := time.Now()
	localDeadline := current.Add(participant.beginAttempt.retirementDeadline.Sub(participant.beginAttempt.activatedAt))
	coordinator.monotonicNow = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return current
	}
	cas.before = func(context.Context, GatewayDestinationTokenURLCASRequest) {
		nowMu.Lock()
		current = localDeadline
		nowMu.Unlock()
	}
	cas.err = ErrGatewayDestinationTokenURLCASConflict
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, nil)
	if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
		t.Fatal("late safe-CAS result lost its post-Begin continuation handle")
	}
	_, _, rollback, _ := participant.counts()
	if rollback != 0 {
		t.Fatal("late safe-CAS result attempted rollback outside the authoritative overlap")
	}
}

func TestGatewayDestinationTokenRotationReconcileMatrix(t *testing.T) {
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	tests := []struct {
		name         string
		destination  string
		observation  GatewayDestinationTokenRotationObservation
		rollbackErr  error
		wantStatus   GatewayDestinationTokenRotationStatus
		wantErr      error
		wantRollback int
	}{
		{
			name: "new and exact pair", destination: newURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(time.Hour)),
			wantStatus:  GatewayDestinationTokenRotationPendingFinalization,
		},
		{
			name: "new and exact pair beyond protocol deadline bound", destination: newURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(gatewayDestinationTokenRotationMaxOverlap+time.Nanosecond)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "old and exact pair", destination: testOnlyGatewayURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow.Add(time.Hour)),
			wantStatus:  GatewayDestinationTokenRotationRolledBack, wantRollback: 1,
		},
		{
			name: "old and exact pair rollback failure", destination: testOnlyGatewayURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow.Add(time.Hour)),
			rollbackErr: ErrGatewayDestinationTokenRotationOutcomeUnknown,
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantRollback: 1,
		},
		{
			name: "old and exact pair at deadline", destination: testOnlyGatewayURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "exact old active stable", destination: testOnlyGatewayURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantRolledBack, GatewayDestinationTokenRotationTokenOld, time.Time{}),
			wantStatus:  GatewayDestinationTokenRotationRolledBack,
		},
		{
			name: "exact new active finalized", destination: newURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantCompleted, GatewayDestinationTokenRotationTokenNew, time.Time{}),
			wantStatus:  GatewayDestinationTokenRotationCompleted,
		},
		{
			name: "third token and pair", destination: newURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNeither, testOnlyRotationNow.Add(time.Hour)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "new token but rolled back", destination: newURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantRolledBack, GatewayDestinationTokenRotationTokenNew, time.Time{}),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "old token but completed", destination: testOnlyGatewayURL,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantCompleted, GatewayDestinationTokenRotationTokenOld, time.Time{}),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, _, store, participant := testOnlyRotationDefaultCoordinator(t)
			store.destination = testOnlyRotationAuthoritativeURL(test.destination)
			participant.observation = test.observation
			participant.rollbackErr = test.rollbackErr
			result, err := coordinator.Reconcile(testOnlyGatewayCASSystemContext(), testOnlyRotationHandle(t))
			if test.wantErr == nil {
				if err != nil || result.Status() != test.wantStatus {
					t.Fatal("explicit reconciliation returned an unexpected stable state")
				}
			} else {
				requireRotationFixedError(t, err, test.wantErr, nil)
				if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
					t.Fatal("explicit reconciliation failure lost its continuation handle")
				}
			}
			begin, observe, rollback, finalize := participant.counts()
			if begin != 0 || observe != 1 || rollback != test.wantRollback || finalize != 0 {
				t.Fatal("explicit reconciliation executed an invalid operation matrix")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationFinalizeMatrix(t *testing.T) {
	private := errors.New("test-only-private-finalize:" + testOnlyGatewayToken)
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	tests := []struct {
		name         string
		now          time.Time
		observation  GatewayDestinationTokenRotationObservation
		finalizeErr  error
		wantStatus   GatewayDestinationTokenRotationStatus
		wantErr      error
		wantFinalize int
	}{
		{
			name: "before deadline", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(time.Nanosecond)),
			wantErr:     ErrGatewayDestinationTokenRotationTooEarly,
		},
		{
			name: "deadline beyond protocol bound", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(gatewayDestinationTokenRotationMaxOverlap+time.Nanosecond)),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "at deadline", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			wantStatus:  GatewayDestinationTokenRotationCompleted, wantFinalize: 1,
		},
		{
			name: "after deadline", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow.Add(-time.Nanosecond)),
			wantStatus:  GatewayDestinationTokenRotationCompleted, wantFinalize: 1,
		},
		{
			name: "old Core token", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "already completed is not duplicate success", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantCompleted, GatewayDestinationTokenRotationTokenNew, time.Time{}),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired,
		},
		{
			name: "finalize conflict", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: ErrGatewayDestinationTokenRotationConflict,
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantFinalize: 1,
		},
		{
			name: "finalize unavailable", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: ErrGatewayDestinationTokenRotationUnavailable,
			wantErr:     ErrGatewayDestinationTokenRotationUnavailable, wantFinalize: 1,
		},
		{
			name: "finalize canceled", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: ErrGatewayDestinationTokenRotationCanceled,
			wantErr:     ErrGatewayDestinationTokenRotationCanceled, wantFinalize: 1,
		},
		{
			name: "finalize deadline", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: ErrGatewayDestinationTokenRotationDeadlineExceeded,
			wantErr:     ErrGatewayDestinationTokenRotationDeadlineExceeded, wantFinalize: 1,
		},
		{
			name: "finalize outcome unknown", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: ErrGatewayDestinationTokenRotationOutcomeUnknown,
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantFinalize: 1,
		},
		{
			name: "finalize joined", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: errors.Join(ErrGatewayDestinationTokenRotationCanceled, private),
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantFinalize: 1,
		},
		{
			name: "finalize private", now: testOnlyRotationNow,
			observation: testOnlyRotationObservation(t, GatewayDestinationTokenRotationParticipantActiveWithRetiring, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow),
			finalizeErr: private,
			wantErr:     ErrGatewayDestinationTokenRotationReconciliationRequired, wantFinalize: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator, _, store, participant := testOnlyRotationDefaultCoordinator(t)
			store.destination = testOnlyRotationAuthoritativeURL(newURL)
			participant.observation = test.observation
			participant.finalizeErr = test.finalizeErr
			coordinator.monotonicNow = func() time.Time { return test.now }
			participant.finalizeFn = func(_ context.Context, request GatewayDestinationTokenRotationFinalizeRequest) error {
				if request.Reason() != GatewayDestinationTokenRotationFinalizeDeadlineElapsed || !request.ParticipantHandle().valid() {
					t.Fatal("finalization did not use the exact handle and deadline-elapsed reason")
				}
				return test.finalizeErr
			}
			result, err := coordinator.Finalize(testOnlyGatewayCASSystemContext(), testOnlyRotationHandle(t))
			if test.wantErr == nil {
				if err != nil || result.Status() != test.wantStatus {
					t.Fatal("finalization returned an unexpected state")
				}
			} else {
				requireRotationFixedError(t, err, test.wantErr, private)
				if test.wantErr == ErrGatewayDestinationTokenRotationReconciliationRequired &&
					(result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid()) {
					t.Fatal("ambiguous finalization lost its continuation handle")
				}
			}
			begin, observe, rollback, finalize := participant.counts()
			if begin != 0 || observe != 1 || rollback != 0 || finalize != test.wantFinalize {
				t.Fatal("finalization executed an invalid operation matrix")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationConcurrentStartAdmitsOneGatewayAttempt(t *testing.T) {
	coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
	attempt := testOnlyRotationAttempt(t)
	var admissionMu sync.Mutex
	admitted := false
	participant.beginResultFn = func(
		context.Context,
		GatewayDestinationTokenRotationBeginRequest,
	) (GatewayDestinationTokenRotationParticipantAttempt, error) {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		if admitted {
			return GatewayDestinationTokenRotationParticipantAttempt{}, ErrGatewayDestinationTokenRotationConflict
		}
		admitted = true
		return attempt, nil
	}

	const workers = 16
	type startResult struct {
		result GatewayDestinationTokenRotationResult
		err    error
	}
	results := make(chan startResult, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			results <- startResult{result: result, err: err}
		}()
	}
	wait.Wait()
	close(results)

	var successes, conflicts int
	for item := range results {
		switch item.err {
		case nil:
			successes++
			if item.result.Status() != GatewayDestinationTokenRotationPendingFinalization || !item.result.Handle().valid() {
				t.Fatal("concurrent Start winner lost its pending-finalization handle")
			}
		case ErrGatewayDestinationTokenRotationConflict:
			conflicts++
			if item.result.Handle().valid() {
				t.Fatal("handle-free concurrent Begin conflict fabricated a continuation handle")
			}
		default:
			t.Fatal("concurrent Start returned an unexpected classification")
		}
	}
	if successes != 1 || conflicts != workers-1 || cas.callCount() != 1 {
		t.Fatal("concurrent Start did not preserve single admitted Begin and single CAS")
	}
	if calls, callbacks := store.counts(); calls != 0 || callbacks != 0 {
		t.Fatal("concurrent Start performed an unexpected authoritative read")
	}
	if begin, observe, rollback, finalize := participant.counts(); begin != workers || observe != 0 || rollback != 0 || finalize != 0 {
		t.Fatal("concurrent Start executed an invalid dependency matrix")
	}
}

func TestGatewayDestinationTokenRotationConcurrentReconcileSerializesRollback(t *testing.T) {
	coordinator, _, store, participant := testOnlyRotationDefaultCoordinator(t)
	store.destination = testOnlyRotationAuthoritativeURL(testOnlyGatewayURL)
	var stateMu sync.Mutex
	state := GatewayDestinationTokenRotationParticipantActiveWithRetiring
	participant.observeFn = func(_ context.Context, _ GatewayDestinationTokenRotationObserveRequest) (GatewayDestinationTokenRotationObservation, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if state == GatewayDestinationTokenRotationParticipantActiveWithRetiring {
			return testOnlyRotationObservation(t, state, GatewayDestinationTokenRotationTokenOld, testOnlyRotationNow.Add(time.Hour)), nil
		}
		return testOnlyRotationObservation(t, state, GatewayDestinationTokenRotationTokenOld, time.Time{}), nil
	}
	participant.rollbackFn = func(_ context.Context, _ GatewayDestinationTokenRotationParticipantHandle) error {
		stateMu.Lock()
		defer stateMu.Unlock()
		if state != GatewayDestinationTokenRotationParticipantActiveWithRetiring {
			return ErrGatewayDestinationTokenRotationConflict
		}
		state = GatewayDestinationTokenRotationParticipantRolledBack
		return nil
	}

	const workers = 16
	results := make(chan GatewayDestinationTokenRotationResult, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := coordinator.Reconcile(testOnlyGatewayCASSystemContext(), testOnlyRotationHandle(t))
			results <- result
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("serialized concurrent reconciliation returned an error")
		}
	}
	for result := range results {
		if result.Status() != GatewayDestinationTokenRotationRolledBack {
			t.Fatal("serialized concurrent reconciliation fabricated a non-rollback state")
		}
	}
	_, observe, rollback, finalize := participant.counts()
	if observe != workers || rollback != 1 || finalize != 0 {
		t.Fatal("concurrent reconciliation did not preserve exact single-rollback semantics")
	}
	if calls, callbacks := store.counts(); calls != workers || callbacks != workers {
		t.Fatal("concurrent reconciliation did not use one locked read per invocation")
	}
}

func TestGatewayDestinationTokenRotationConcurrentFinalizeRejectsDuplicateSuccess(t *testing.T) {
	coordinator, _, store, participant := testOnlyRotationDefaultCoordinator(t)
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	store.destination = testOnlyRotationAuthoritativeURL(newURL)
	var stateMu sync.Mutex
	state := GatewayDestinationTokenRotationParticipantActiveWithRetiring
	participant.observeFn = func(_ context.Context, _ GatewayDestinationTokenRotationObserveRequest) (GatewayDestinationTokenRotationObservation, error) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if state == GatewayDestinationTokenRotationParticipantActiveWithRetiring {
			return testOnlyRotationObservation(t, state, GatewayDestinationTokenRotationTokenNew, testOnlyRotationNow), nil
		}
		return testOnlyRotationObservation(t, state, GatewayDestinationTokenRotationTokenNew, time.Time{}), nil
	}
	participant.finalizeFn = func(_ context.Context, _ GatewayDestinationTokenRotationFinalizeRequest) error {
		stateMu.Lock()
		defer stateMu.Unlock()
		if state != GatewayDestinationTokenRotationParticipantActiveWithRetiring {
			return ErrGatewayDestinationTokenRotationConflict
		}
		state = GatewayDestinationTokenRotationParticipantCompleted
		return nil
	}

	const workers = 16
	errs := make(chan error, workers)
	states := make(chan GatewayDestinationTokenRotationStatus, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := coordinator.Finalize(testOnlyGatewayCASSystemContext(), testOnlyRotationHandle(t))
			states <- result.Status()
			errs <- err
		}()
	}
	wg.Wait()
	close(states)
	close(errs)
	var completed, reconciliation int
	for err := range errs {
		switch err {
		case nil:
			completed++
		case ErrGatewayDestinationTokenRotationReconciliationRequired:
			reconciliation++
		default:
			t.Fatal("concurrent finalization returned an unexpected classification")
		}
	}
	if completed != 1 || reconciliation != workers-1 {
		t.Fatal("concurrent finalization treated a duplicate or stale handle as success")
	}
	var completedStates, reconciliationStates int
	for state := range states {
		switch state {
		case GatewayDestinationTokenRotationCompleted:
			completedStates++
		case GatewayDestinationTokenRotationNeedsReconciliation:
			reconciliationStates++
		}
	}
	if completedStates != 1 || reconciliationStates != workers-1 {
		t.Fatal("concurrent finalization lost a completed or reconciliation continuation state")
	}
	_, observe, rollback, finalize := participant.counts()
	if observe != workers || rollback != 0 || finalize != 1 {
		t.Fatal("concurrent finalization did not preserve exact single-mutation semantics")
	}
}

type gatewayRotationTestCallbackStore struct {
	count       int
	destination GatewayDestinationTokenRotationAuthoritativeDestination
	err         error
}

type gatewayRotationTestCancellationFenceStore struct {
	destination GatewayDestinationTokenRotationAuthoritativeDestination
	active      atomic.Bool
}

func (store *gatewayRotationTestCancellationFenceStore) WithLockedGatewayDestination(
	ctx context.Context,
	_ uuid.UUID,
	callback func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination),
) error {
	lockCtx, cancel := context.WithTimeout(ctx, gatewayDestinationTokenRotationRecoveryLimit)
	defer cancel()
	store.active.Store(true)
	defer store.active.Store(false)
	callback(lockCtx, store.destination)
	return nil
}

func (store gatewayRotationTestCallbackStore) WithLockedGatewayDestination(
	ctx context.Context,
	_ uuid.UUID,
	callback func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination),
) error {
	lockCtx, cancel := context.WithTimeout(ctx, gatewayDestinationTokenRotationRecoveryLimit)
	defer cancel()
	for range store.count {
		callback(lockCtx, store.destination)
	}
	return store.err
}

func TestGatewayDestinationTokenRotationAuthoritativeStoreContractFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name  string
		count int
		err   error
	}{
		{name: "callback omitted"},
		{name: "callback repeated", count: 2},
		{name: "error after callback", count: 1, err: errors.New("test-only store completion failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			cas := &gatewayRotationTestCAS{err: ErrGatewayDestinationTokenURLCASOutcomeUnknown}
			participant := &gatewayRotationTestParticipant{
				beginAttempt: testOnlyRotationAttempt(t),
				observation: testOnlyRotationObservation(
					t,
					GatewayDestinationTokenRotationParticipantActiveWithRetiring,
					GatewayDestinationTokenRotationTokenNew,
					testOnlyRotationNow.Add(time.Hour),
				),
			}
			store := gatewayRotationTestCallbackStore{
				count: test.count, destination: testOnlyRotationAuthoritativeURL(
					strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70),
				), err: test.err,
			}
			coordinator := testOnlyRotationCoordinator(t, cas, store, participant, time.Now)
			result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
			requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, test.err)
			if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
				t.Fatal("invalid authoritative callback contract lost the post-Begin continuation handle")
			}
			_, _, rollback, finalize := participant.counts()
			if rollback != 0 || finalize != 0 {
				t.Fatal("invalid authoritative store callback contract triggered a mutation")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationLockedRollbackSharesOuterFenceContext(t *testing.T) {
	store := &gatewayRotationTestCancellationFenceStore{
		destination: testOnlyRotationAuthoritativeURL(testOnlyGatewayURL),
	}
	participant := &gatewayRotationTestParticipant{
		observation: testOnlyRotationObservation(
			t,
			GatewayDestinationTokenRotationParticipantActiveWithRetiring,
			GatewayDestinationTokenRotationTokenOld,
			testOnlyRotationNow.Add(time.Hour),
		),
	}
	coordinator := testOnlyRotationCoordinator(
		t,
		&gatewayRotationTestCAS{},
		store,
		participant,
		time.Now,
	)
	lockedCtx, cancelLocked := context.WithCancel(testOnlyGatewayCASSystemContext())
	participant.rollbackFn = func(ctx context.Context, _ GatewayDestinationTokenRotationParticipantHandle) error {
		if !store.active.Load() {
			t.Fatal("Gateway rollback started without the Core row fence")
		}
		cancelLocked()
		<-ctx.Done()
		if !store.active.Load() {
			t.Fatal("Gateway rollback continued after the Core row fence callback returned")
		}
		return ErrGatewayDestinationTokenRotationCanceled
	}
	result, err := coordinator.inspectLocked(
		lockedCtx,
		testOnlyRotationHandle(t),
		gatewayDestinationTokenRotationInspectReconcile,
		time.Time{},
		time.Time{},
	)
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, nil)
	if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
		t.Fatal("canceled locked rollback lost its continuation handle")
	}
	if store.active.Load() {
		t.Fatal("Core row fence callback remained active after reconciliation returned")
	}
	_, _, rollback, _ := participant.counts()
	if rollback != 1 {
		t.Fatal("canceled locked rollback was retried")
	}
}

func TestGatewayDestinationTokenRotationCanceledBeforeOperationDoesNothing(t *testing.T) {
	coordinator, cas, store, participant := testOnlyRotationDefaultCoordinator(t)
	ctx, cancel := context.WithCancel(testOnlyGatewayCASSystemContext())
	cancel()
	for _, operation := range []func() error{
		func() error { _, err := coordinator.Start(ctx, testOnlyRotationStartRequest()); return err },
		func() error { _, err := coordinator.Reconcile(ctx, testOnlyRotationHandle(t)); return err },
		func() error { _, err := coordinator.Finalize(ctx, testOnlyRotationHandle(t)); return err },
	} {
		requireRotationFixedError(t, operation(), ErrGatewayDestinationTokenRotationCanceled, nil)
	}
	if cas.callCount() != 0 {
		t.Fatal("pre-canceled operation reached Core CAS")
	}
	if calls, _ := store.counts(); calls != 0 {
		t.Fatal("pre-canceled operation reached authoritative store")
	}
	if begin, observe, rollback, finalize := participant.counts(); begin+observe+rollback+finalize != 0 {
		t.Fatal("pre-canceled operation reached Gateway participant")
	}
}

func TestGatewayDestinationTokenRotationExplicitReadsHonorLaterCancellation(t *testing.T) {
	for _, operation := range []string{"reconcile", "finalize"} {
		t.Run(operation, func(t *testing.T) {
			coordinator, _, store, participant := testOnlyRotationDefaultCoordinator(t)
			newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
			store.destination = testOnlyRotationAuthoritativeURL(newURL)
			callerCtx, cancelCaller := context.WithCancel(testOnlyGatewayCASSystemContext())
			store.before = func(ctx context.Context) {
				cancelCaller()
				if ctx.Err() != context.Canceled || !permission.System(ctx) {
					t.Fatal("explicit authoritative read did not retain caller cancellation or System permission")
				}
			}
			participant.observation = testOnlyRotationObservation(
				t,
				GatewayDestinationTokenRotationParticipantActiveWithRetiring,
				GatewayDestinationTokenRotationTokenNew,
				testOnlyRotationNow,
			)
			var result GatewayDestinationTokenRotationResult
			var err error
			switch operation {
			case "reconcile":
				result, err = coordinator.Reconcile(callerCtx, testOnlyRotationHandle(t))
			case "finalize":
				result, err = coordinator.Finalize(callerCtx, testOnlyRotationHandle(t))
			}
			if err != ErrGatewayDestinationTokenRotationReconciliationRequired ||
				result.Status() != GatewayDestinationTokenRotationNeedsReconciliation {
				t.Fatal("canceled explicit authoritative operation did not fail closed")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationValidatesDependenciesAndHandles(t *testing.T) {
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	if err != nil {
		t.Fatal("failed to create test-only matcher")
	}
	cas := &gatewayRotationTestCAS{}
	store := &gatewayRotationTestStore{}
	participant := &gatewayRotationTestParticipant{}
	var nilCAS *gatewayRotationTestCAS
	var nilStore *gatewayRotationTestStore
	var nilParticipant *gatewayRotationTestParticipant
	for _, test := range []struct {
		name        string
		matcher     *GatewayTargetMatcher
		cas         gatewayDestinationTokenRotationCAS
		store       GatewayDestinationTokenRotationAuthoritativeStore
		participant GatewayDestinationTokenRotationParticipant
		now         func() time.Time
	}{
		{name: "nil matcher", cas: cas, store: store, participant: participant, now: time.Now},
		{name: "invalid matcher", matcher: &GatewayTargetMatcher{}, cas: cas, store: store, participant: participant, now: time.Now},
		{name: "nil CAS", matcher: matcher, store: store, participant: participant, now: time.Now},
		{name: "typed nil CAS", matcher: matcher, cas: nilCAS, store: store, participant: participant, now: time.Now},
		{name: "nil store", matcher: matcher, cas: cas, participant: participant, now: time.Now},
		{name: "typed nil store", matcher: matcher, cas: cas, store: nilStore, participant: participant, now: time.Now},
		{name: "nil participant", matcher: matcher, cas: cas, store: store, now: time.Now},
		{name: "typed nil participant", matcher: matcher, cas: cas, store: store, participant: nilParticipant, now: time.Now},
		{name: "nil clock", matcher: matcher, cas: cas, store: store, participant: participant},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator, err := newGatewayDestinationTokenRotationCoordinator(test.matcher, test.cas, test.store, test.participant, test.now)
			if coordinator != nil {
				t.Fatal("invalid dependencies returned a coordinator")
			}
			requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationInvalid, nil)
		})
	}

	coordinator := testOnlyRotationCoordinator(t, cas, store, participant, time.Now)
	for _, operation := range []func() error{
		func() error {
			_, err := coordinator.Reconcile(testOnlyGatewayCASSystemContext(), GatewayDestinationTokenRotationHandle{})
			return err
		},
		func() error {
			_, err := coordinator.Finalize(testOnlyGatewayCASSystemContext(), GatewayDestinationTokenRotationHandle{})
			return err
		},
	} {
		requireRotationFixedError(t, operation(), ErrGatewayDestinationTokenRotationInvalid, nil)
	}
	if created, err := NewGatewayDestinationTokenRotationAuthoritativeStore(nil); created != nil || err != ErrGatewayDestinationTokenRotationInvalid {
		t.Fatal("nil database returned an authoritative store")
	}
	acceptedCAS := testOnlyGatewayCASService(t, &gatewayDestinationTokenURLCASSpy{rows: 1})
	equivalentMatcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	if err != nil {
		t.Fatal("failed to construct equivalent matcher")
	}
	fencedStore, err := newGatewayDestinationTokenRotationAuthoritativeStore(
		func(context.Context) (gatewayDestinationTokenRotationAuthoritativeConnection, error) {
			return nil, errors.New("test-only unused acquire")
		},
	)
	if err != nil {
		t.Fatal("failed to construct test-only fenced store")
	}
	if created, err := NewGatewayDestinationTokenRotationCoordinator(
		equivalentMatcher,
		acceptedCAS,
		fencedStore,
		participant,
	); created != nil || err != ErrGatewayDestinationTokenRotationInvalid {
		t.Fatal("production coordinator accepted an independently configured matcher instance")
	}
}

type gatewayRotationStoreTestConnector struct {
	conn *gatewayRotationStoreTestConn
}

func (connector gatewayRotationStoreTestConnector) Connect(context.Context) (driver.Conn, error) {
	connector.conn.mu.Lock()
	connector.conn.connects++
	connector.conn.mu.Unlock()
	return connector.conn, nil
}

func (gatewayRotationStoreTestConnector) Driver() driver.Driver {
	return gatewayRotationStoreTestDriver{}
}

type gatewayRotationStoreTestDriver struct{}

func (gatewayRotationStoreTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("test-only unsupported open")
}

type gatewayRotationStoreTestSeamConnection struct {
	transaction gatewayDestinationTokenRotationAuthoritativeTransaction
	err         error
	begins      int
	closes      int
	discards    int
}

func (connection *gatewayRotationStoreTestSeamConnection) BeginTx(
	context.Context,
	*sql.TxOptions,
) (gatewayDestinationTokenRotationAuthoritativeTransaction, error) {
	connection.begins++
	return connection.transaction, connection.err
}

func (connection *gatewayRotationStoreTestSeamConnection) Close() error {
	connection.closes++
	return nil
}

func (connection *gatewayRotationStoreTestSeamConnection) DiscardBefore(time.Time) bool {
	connection.discards++
	return true
}

type gatewayRotationStoreTestTypedNilTransaction struct {
	*sql.Tx
}

type gatewayRotationStoreTestConn struct {
	mu              sync.Mutex
	connects        int
	queries         int
	execs           int
	begins          int
	commits         int
	rollbacks       int
	closed          int
	txOpen          bool
	query           string
	execQuery       string
	args            []driver.NamedValue
	execArgs        []driver.NamedValue
	sequence        []string
	destJSON        []byte
	beginErr        error
	queryErr        error
	execErr         error
	commitErr       error
	rollbackErr     error
	rowsAffected    int64
	rowsAffectedSet bool
	rollbackHook    func()
	physical        *gatewayRotationStoreTestPhysicalConnection
	beginContext    context.Context
}

type gatewayRotationStoreTestPhysicalConnection struct {
	mu            sync.Mutex
	closed        int
	closeDeadline time.Time
	closeErr      error
	beforeClose   func()
}

func (connection *gatewayRotationStoreTestPhysicalConnection) Close(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	connection.mu.Lock()
	connection.closeDeadline = deadline
	connection.mu.Unlock()
	if connection.beforeClose != nil {
		connection.beforeClose()
	}
	connection.mu.Lock()
	defer connection.mu.Unlock()
	connection.closed++
	return connection.closeErr
}

func (connection *gatewayRotationStoreTestPhysicalConnection) deadline() time.Time {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.closeDeadline
}

func (connection *gatewayRotationStoreTestPhysicalConnection) closeCount() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.closed
}

func (conn *gatewayRotationStoreTestConn) gatewayDestinationTokenURLCASConnection() gatewayDestinationTokenURLCASConnectionCloser {
	return conn.physical
}

func (*gatewayRotationStoreTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("test-only prepare must not be used")
}

func (*gatewayRotationStoreTestConn) CheckNamedValue(*driver.NamedValue) error { return nil }

func (conn *gatewayRotationStoreTestConn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.closed++
	return nil
}

func (conn *gatewayRotationStoreTestConn) Begin() (driver.Tx, error) {
	return conn.BeginTx(context.Background(), driver.TxOptions{})
}

func (conn *gatewayRotationStoreTestConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.txOpen {
		return nil, errors.New("test-only nested transaction")
	}
	conn.begins++
	conn.beginContext = ctx
	conn.sequence = append(conn.sequence, "begin")
	if conn.beginErr != nil {
		return nil, conn.beginErr
	}
	conn.txOpen = true
	return &gatewayRotationStoreTestTx{conn: conn}, nil
}

func (conn *gatewayRotationStoreTestConn) QueryContext(
	_ context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Rows, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.txOpen {
		return nil, errors.New("test-only query outside transaction")
	}
	conn.queries++
	conn.sequence = append(conn.sequence, "lock")
	conn.query = query
	conn.args = append([]driver.NamedValue(nil), args...)
	if conn.queryErr != nil {
		return nil, conn.queryErr
	}
	return &gatewayRotationStoreTestRows{values: []driver.Value{
		append([]byte(nil), conn.destJSON...),
		false,
		true,
		testOnlyGatewayCASContactMethodID.String(),
		nil,
		[]byte("{}"),
		"test-only",
		false,
		"WEBHOOK",
		"123e4567-e89b-12d3-a456-426614174088",
		"",
	}}, nil
}

func (conn *gatewayRotationStoreTestConn) ExecContext(
	_ context.Context,
	query string,
	args []driver.NamedValue,
) (driver.Result, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.txOpen {
		return nil, errors.New("test-only execution outside transaction")
	}
	conn.execs++
	conn.sequence = append(conn.sequence, "update")
	conn.execQuery = query
	conn.execArgs = append([]driver.NamedValue(nil), args...)
	if conn.execErr != nil {
		return nil, conn.execErr
	}
	rowsAffected := int64(1)
	if conn.rowsAffectedSet {
		rowsAffected = conn.rowsAffected
	}
	return driver.RowsAffected(rowsAffected), nil
}

type gatewayRotationStoreTestTx struct {
	conn *gatewayRotationStoreTestConn
}

func (tx *gatewayRotationStoreTestTx) Commit() error {
	tx.conn.mu.Lock()
	defer tx.conn.mu.Unlock()
	if !tx.conn.txOpen {
		return sql.ErrTxDone
	}
	tx.conn.commits++
	tx.conn.sequence = append(tx.conn.sequence, "commit")
	if tx.conn.commitErr != nil {
		return tx.conn.commitErr
	}
	tx.conn.txOpen = false
	return nil
}

func (tx *gatewayRotationStoreTestTx) Rollback() error {
	tx.conn.mu.Lock()
	defer tx.conn.mu.Unlock()
	if !tx.conn.txOpen {
		return sql.ErrTxDone
	}
	tx.conn.rollbacks++
	tx.conn.sequence = append(tx.conn.sequence, "rollback")
	if tx.conn.rollbackHook != nil {
		tx.conn.rollbackHook()
	}
	if tx.conn.rollbackErr != nil {
		return tx.conn.rollbackErr
	}
	tx.conn.txOpen = false
	return nil
}

type gatewayRotationStoreTestRows struct {
	values []driver.Value
	done   bool
}

func (*gatewayRotationStoreTestRows) Columns() []string {
	return []string{
		"dest", "disabled", "enable_status_updates", "id", "last_test_verify_at", "metadata",
		"name", "pending", "type", "user_id", "value",
	}
}

func (*gatewayRotationStoreTestRows) Close() error { return nil }

func (rows *gatewayRotationStoreTestRows) Next(destination []driver.Value) error {
	if rows.done {
		return io.EOF
	}
	copy(destination, rows.values)
	rows.done = true
	return nil
}

func TestGatewayDestinationTokenRotationSQLAuthoritativeStoreLocksAcrossCallback(t *testing.T) {
	destination := NewWebhookDest(testOnlyGatewayURL)
	encoded, err := json.Marshal(destination)
	if err != nil {
		t.Fatal("failed to encode test-only destination")
	}
	physical := &gatewayRotationStoreTestPhysicalConnection{}
	conn := &gatewayRotationStoreTestConn{destJSON: encoded, physical: physical}
	db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
	if err != nil {
		t.Fatal("failed to create SQL authoritative store")
	}
	callbackCalls := 0
	err = store.WithLockedGatewayDestination(
		testOnlyGatewayCASSystemContext(),
		testOnlyGatewayCASContactMethodID,
		func(lockCtx context.Context, authoritative GatewayDestinationTokenRotationAuthoritativeDestination) {
			callbackCalls++
			conn.mu.Lock()
			defer conn.mu.Unlock()
			if !conn.txOpen || !strings.Contains(strings.ToLower(conn.query), "for update") {
				t.Fatal("authoritative callback did not run under SELECT FOR UPDATE row lock")
			}
			if authoritative.destination.Arg(FieldWebhookURL) != testOnlyGatewayURL {
				t.Fatal("authoritative callback did not receive the complete stored destination")
			}
			if fmt.Sprintf("%v", authoritative) != "[redacted]" {
				t.Fatal("authoritative destination formatting was not redacted")
			}
			lockDeadline, lockBounded := lockCtx.Deadline()
			txDeadline, txBounded := conn.beginContext.Deadline()
			if !lockBounded || !txBounded || lockCtx.Err() != nil ||
				time.Until(lockDeadline) <= 0 ||
				time.Until(lockDeadline) > gatewayDestinationTokenRotationRecoveryLimit ||
				!txDeadline.Equal(lockDeadline.Add(gatewayDestinationTokenRotationReleaseLimit)) {
				t.Fatal("unbounded caller did not receive the store-derived operation and absolute release deadlines")
			}
		},
	)
	if err != nil {
		t.Fatal("SQL authoritative locking read failed")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if callbackCalls != 1 || conn.connects != 1 || conn.begins != 1 || conn.queries != 1 ||
		conn.rollbacks != 1 || conn.txOpen || len(conn.args) != 1 {
		t.Fatal("SQL authoritative store did not use one fresh locking transaction with confirmed release")
	}
	query := strings.ToLower(conn.query)
	if strings.Contains(query, "\nupdate ") || strings.Contains(query, "\ninsert ") ||
		strings.Contains(query, "\ndelete ") {
		t.Fatal("SQL authoritative store executed a data mutation")
	}
}

func TestGatewayDestinationTokenRotationLockedCallbackCannotOutliveTransactionFence(t *testing.T) {
	encoded, err := json.Marshal(NewWebhookDest(testOnlyGatewayURL))
	if err != nil {
		t.Fatal("failed to encode transaction-lifetime destination")
	}
	physical := &gatewayRotationStoreTestPhysicalConnection{}
	conn := &gatewayRotationStoreTestConn{destJSON: encoded, physical: physical}
	db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
	if err != nil {
		t.Fatal("failed to create transaction-lifetime store")
	}
	operationCtx, cancelOperation := context.WithCancel(testOnlyGatewayCASSystemContext())
	callbackCalls := 0
	err = store.WithLockedGatewayDestination(operationCtx, testOnlyGatewayCASContactMethodID, func(_ context.Context, _ GatewayDestinationTokenRotationAuthoritativeDestination) {
		callbackCalls++
		cancelOperation()
		if operationCtx.Err() != context.Canceled {
			t.Fatal("test operation context did not cancel inside locked callback")
		}
		conn.mu.Lock()
		defer conn.mu.Unlock()
		if conn.beginContext == nil {
			t.Fatal("Core transaction fence did not retain a transaction context")
		}
		transactionDeadline, bounded := conn.beginContext.Deadline()
		transactionRemaining := time.Until(transactionDeadline)
		if conn.beginContext.Err() != nil || !bounded || transactionRemaining <= 0 ||
			transactionRemaining > gatewayDestinationTokenRotationRecoveryLimit+gatewayDestinationTokenRotationReleaseLimit ||
			!conn.txOpen || conn.rollbacks != 0 {
			t.Fatal("bounded callback cancellation released the detached Core transaction fence")
		}
	})
	if err != ErrGatewayDestinationTokenRotationReconciliationRequired || callbackCalls != 1 {
		t.Fatal("expired operation context was not reported as reconciliation after explicit fence release")
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.txOpen || conn.rollbacks != 1 {
		t.Fatal("Core transaction fence was not explicitly released after the callback returned")
	}
	if physical.closeCount() != 1 {
		t.Fatal("expired locked operation did not discard its physical connection after explicit release")
	}
}

func TestGatewayDestinationTokenRotationProductionCASFencesBeforeSingleUpdate(t *testing.T) {
	destination := NewWebhookDest(testOnlyGatewayURL)
	encoded, err := json.Marshal(destination)
	if err != nil {
		t.Fatal("failed to encode fenced-CAS destination")
	}
	physical := &gatewayRotationStoreTestPhysicalConnection{}
	conn := &gatewayRotationStoreTestConn{destJSON: encoded, physical: physical}
	db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
	if err != nil {
		t.Fatal("failed to create fenced Core store")
	}
	autocommitRepository := &gatewayDestinationTokenURLCASSpy{rows: 1}
	acceptedCAS := testOnlyGatewayCASService(t, autocommitRepository)
	participant := &gatewayRotationTestParticipant{}
	attempt, err := NewGatewayDestinationTokenRotationParticipantAttempt(
		testOnlyRotationParticipantHandle(t),
		testOnlyGatewayCASReplacementToken(0x70),
		time.Now(),
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal("failed to create production-constructor attempt")
	}
	participant.beginAttempt = attempt
	coordinator, err := NewGatewayDestinationTokenRotationCoordinator(acceptedCAS.matcher, acceptedCAS, store, participant)
	if err != nil {
		t.Fatal("failed to create production fenced coordinator")
	}
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	if err != nil || result.Status() != GatewayDestinationTokenRotationPendingFinalization {
		t.Fatal("production fenced coordinator start failed")
	}
	if autocommitRepository.callCount() != 0 {
		t.Fatal("coordinator used the accepted standalone autocommit CAS repository")
	}

	conn.mu.Lock()
	sequence := append([]string(nil), conn.sequence...)
	queries, execs, commits, rollbacks := conn.queries, conn.execs, conn.commits, conn.rollbacks
	lockQuery, updateQuery := strings.ToLower(conn.query), strings.ToLower(conn.execQuery)
	updateArgs := len(conn.execArgs)
	beginContext := conn.beginContext
	conn.mu.Unlock()
	if fmt.Sprint(sequence) != "[begin lock update commit]" || queries != 1 || execs != 1 || commits != 1 || rollbacks != 0 {
		t.Fatal("production CAS did not hold a pre-update row fence through exactly one update and commit")
	}
	if !strings.Contains(lockQuery, "for update") || !strings.Contains(updateQuery, "\nupdate\n") || updateArgs != 3 {
		t.Fatal("production fenced CAS did not use the reviewed lock and conditional-update statements")
	}
	if beginContext == nil {
		t.Fatal("production fenced CAS did not bind the transaction to its CAS context")
	}
	if deadline, bounded := beginContext.Deadline(); !bounded || time.Until(deadline) > gatewayDestinationTokenRotationCASLimit {
		t.Fatal("production fenced CAS transaction did not inherit the bounded CAS deadline")
	}
	if physical.closeCount() != 0 {
		t.Fatal("confirmed fenced CAS success destroyed its safe physical connection")
	}
}

func TestGatewayDestinationTokenRotationUncertainSerializationDomainFailsClosed(t *testing.T) {
	store, err := newGatewayDestinationTokenRotationAuthoritativeStore(
		func(context.Context) (gatewayDestinationTokenRotationAuthoritativeConnection, error) {
			return nil, errGatewayDestinationTokenRotationSerializationUncertain
		},
	)
	if err != nil {
		t.Fatal("failed to create topology-uncertain store")
	}
	autocommitRepository := &gatewayDestinationTokenURLCASSpy{rows: 1}
	acceptedCAS := testOnlyGatewayCASService(t, autocommitRepository)
	attempt, err := NewGatewayDestinationTokenRotationParticipantAttempt(
		testOnlyRotationParticipantHandle(t),
		testOnlyGatewayCASReplacementToken(0x70),
		time.Now(),
		time.Now().Add(time.Hour),
	)
	if err != nil {
		t.Fatal("failed to create topology-uncertain attempt")
	}
	participant := &gatewayRotationTestParticipant{beginAttempt: attempt}
	coordinator, err := NewGatewayDestinationTokenRotationCoordinator(acceptedCAS.matcher, acceptedCAS, store, participant)
	if err != nil {
		t.Fatal("failed to create topology-uncertain coordinator")
	}
	result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
	requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, nil)
	if result.Status() != GatewayDestinationTokenRotationNeedsReconciliation || !result.Handle().valid() {
		t.Fatal("uncertain serialization domain lost its continuation handle")
	}
	if autocommitRepository.callCount() != 0 {
		t.Fatal("uncertain serialization domain reached the standalone CAS repository")
	}
	begin, observe, rollback, finalize := participant.counts()
	if begin != 1 || observe != 0 || rollback != 0 || finalize != 0 {
		t.Fatal("uncertain serialization domain reached a post-Begin participant mutation or callback")
	}
}

func TestGatewayDestinationTokenRotationCommitUnknownResolvesFenceBeforeRecoveryRead(t *testing.T) {
	oldDestination, err := json.Marshal(NewWebhookDest(testOnlyGatewayURL))
	if err != nil {
		t.Fatal("failed to encode old fenced destination")
	}
	newURL := strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken) + testOnlyGatewayCASReplacementToken(0x70)
	newDestination, err := json.Marshal(NewWebhookDest(newURL))
	if err != nil {
		t.Fatal("failed to encode new fenced destination")
	}
	discardStarted := make(chan struct{})
	allowResolution := make(chan struct{})
	conn := &gatewayRotationStoreTestConn{
		destJSON:  oldDestination,
		commitErr: errors.New("test-only delayed commit acknowledgement"),
	}
	physical := &gatewayRotationStoreTestPhysicalConnection{beforeClose: func() {
		close(discardStarted)
		<-allowResolution
		conn.mu.Lock()
		conn.txOpen = false
		conn.commitErr = nil
		conn.destJSON = append([]byte(nil), newDestination...)
		conn.mu.Unlock()
	}}
	conn.physical = physical
	db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
	if err != nil {
		t.Fatal("failed to create delayed-resolution Core store")
	}
	autocommitRepository := &gatewayDestinationTokenURLCASSpy{rows: 1}
	acceptedCAS := testOnlyGatewayCASService(t, autocommitRepository)
	activatedAt := time.Now()
	retirementDeadline := activatedAt.Add(time.Hour)
	attempt, err := NewGatewayDestinationTokenRotationParticipantAttempt(
		testOnlyRotationParticipantHandle(t),
		testOnlyGatewayCASReplacementToken(0x70),
		activatedAt,
		retirementDeadline,
	)
	if err != nil {
		t.Fatal("failed to construct delayed-resolution attempt")
	}
	participant := &gatewayRotationTestParticipant{
		beginAttempt: attempt,
		observation: testOnlyRotationObservation(
			t,
			GatewayDestinationTokenRotationParticipantActiveWithRetiring,
			GatewayDestinationTokenRotationTokenNew,
			retirementDeadline,
		),
	}
	coordinator, err := NewGatewayDestinationTokenRotationCoordinator(acceptedCAS.matcher, acceptedCAS, store, participant)
	if err != nil {
		t.Fatal("failed to create delayed-resolution coordinator")
	}
	type startOutcome struct {
		result GatewayDestinationTokenRotationResult
		err    error
	}
	done := make(chan startOutcome, 1)
	go func() {
		result, err := coordinator.Start(testOnlyGatewayCASSystemContext(), testOnlyRotationStartRequest())
		done <- startOutcome{result: result, err: err}
	}()
	select {
	case <-discardStarted:
	case <-time.After(time.Second):
		t.Fatal("commit-unknown path did not begin physical connection destruction")
	}
	if _, observe, rollback, finalize := participant.counts(); observe != 0 || rollback != 0 || finalize != 0 {
		t.Fatal("recovery reached Gateway before the unknown Core transaction fence resolved")
	}
	conn.mu.Lock()
	queriesBeforeResolution := conn.queries
	conn.mu.Unlock()
	if queriesBeforeResolution != 1 {
		t.Fatal("authoritative recovery read started before commit-unknown connection destruction completed")
	}
	close(allowResolution)
	select {
	case outcome := <-done:
		if outcome.err != nil || outcome.result.Status() != GatewayDestinationTokenRotationPendingFinalization {
			t.Fatal("post-fence recovery did not observe the resolved new Core value")
		}
	case <-time.After(time.Second):
		t.Fatal("post-fence recovery did not complete")
	}
	if physical.closeCount() != 1 || autocommitRepository.callCount() != 0 {
		t.Fatal("commit-unknown recovery did not destroy exactly the fenced physical connection")
	}
	conn.mu.Lock()
	queriesAfterResolution := conn.queries
	conn.mu.Unlock()
	if queriesAfterResolution != 2 {
		t.Fatal("commit-unknown recovery did not perform one ordered authoritative locking read")
	}
}

func TestGatewayDestinationTokenRotationFencedCASFaultDisposition(t *testing.T) {
	destination := NewWebhookDest(testOnlyGatewayURL)
	encoded, err := json.Marshal(destination)
	if err != nil {
		t.Fatal("failed to encode fenced-CAS fault destination")
	}
	private := errors.New("test-only fenced CAS fault")
	for _, test := range []struct {
		name          string
		queryErr      error
		execErr       error
		commitErr     error
		rollbackErr   error
		rowsAffected  int64
		rowsSet       bool
		want          error
		wantSequence  string
		wantDiscarded int
	}{
		{name: "missing row", queryErr: sql.ErrNoRows, want: ErrGatewayDestinationTokenURLCASConflict, wantSequence: "[begin lock rollback]"},
		{name: "lock read failure", queryErr: private, want: ErrGatewayDestinationTokenURLCASUnavailable, wantSequence: "[begin lock rollback]"},
		{name: "ambiguous update with confirmed rollback", execErr: private, want: ErrGatewayDestinationTokenURLCASUnavailable, wantSequence: "[begin lock update rollback]"},
		{name: "ambiguous update and failed rollback", execErr: private, rollbackErr: private, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown, wantSequence: "[begin lock update rollback]", wantDiscarded: 1},
		{name: "zero affected", rowsSet: true, want: ErrGatewayDestinationTokenURLCASConflict, wantSequence: "[begin lock update rollback]"},
		{name: "multiple affected", rowsAffected: 2, rowsSet: true, want: ErrGatewayDestinationTokenURLCASUnavailable, wantSequence: "[begin lock update rollback]"},
		{name: "commit outcome unknown", commitErr: private, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown, wantSequence: "[begin lock update commit]", wantDiscarded: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			physical := &gatewayRotationStoreTestPhysicalConnection{}
			conn := &gatewayRotationStoreTestConn{
				destJSON:        encoded,
				queryErr:        test.queryErr,
				execErr:         test.execErr,
				commitErr:       test.commitErr,
				rollbackErr:     test.rollbackErr,
				rowsAffected:    test.rowsAffected,
				rowsAffectedSet: test.rowsSet,
				physical:        physical,
			}
			db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = db.Close() })
			store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
			if err != nil {
				t.Fatal("failed to construct fenced-CAS fault store")
			}
			fencedStore, ok := store.(gatewayDestinationTokenRotationFencedStore)
			if !ok {
				t.Fatal("SQL authoritative store did not implement the fenced-CAS seam")
			}
			casCtx, cancelCAS := context.WithTimeout(testOnlyGatewayCASSystemContext(), gatewayDestinationTokenRotationCASLimit)
			defer cancelCAS()
			casDeadline, _ := casCtx.Deadline()
			err = fencedStore.compareAndSwapWithFence(
				casCtx,
				testOnlyGatewayCASContactMethodID,
				NewWebhookDest(testOnlyGatewayURL),
				NewWebhookDest(strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken)+testOnlyGatewayCASReplacementToken(0x70)),
			)
			requireGatewayCASFixedError(t, err, test.want, private)
			conn.mu.Lock()
			sequence := fmt.Sprint(conn.sequence)
			conn.mu.Unlock()
			if sequence != test.wantSequence || physical.closeCount() != test.wantDiscarded {
				t.Fatal("fenced-CAS fault did not preserve its required transaction or connection disposition")
			}
			if test.wantDiscarded != 0 &&
				!physical.deadline().Equal(casDeadline.Add(gatewayDestinationTokenRotationDiscardLimit)) {
				t.Fatal("physical quarantine did not use the absolute CAS-deadline-plus-D bound")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationUnconfirmedPhysicalQuarantineIsNotRecoverableUnknown(t *testing.T) {
	encoded, err := json.Marshal(NewWebhookDest(testOnlyGatewayURL))
	if err != nil {
		t.Fatal("failed to encode quarantine-fault destination")
	}
	private := errors.New("test-only physical close failure")
	physical := &gatewayRotationStoreTestPhysicalConnection{closeErr: private}
	conn := &gatewayRotationStoreTestConn{
		destJSON:  encoded,
		commitErr: errors.New("test-only commit ambiguity"),
		physical:  physical,
	}
	db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
	if err != nil {
		t.Fatal("failed to create quarantine-fault store")
	}
	ctx, cancel := context.WithTimeout(testOnlyGatewayCASSystemContext(), gatewayDestinationTokenRotationCASLimit)
	defer cancel()
	err = store.(gatewayDestinationTokenRotationFencedStore).compareAndSwapWithFence(
		ctx,
		testOnlyGatewayCASContactMethodID,
		NewWebhookDest(testOnlyGatewayURL),
		NewWebhookDest(strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken)+testOnlyGatewayCASReplacementToken(0x70)),
	)
	if err != errGatewayDestinationTokenRotationQuarantineUnconfirmed || errors.Is(err, private) {
		t.Fatal("unconfirmed physical quarantine was promoted to recoverable outcome-unknown or leaked its cause")
	}
	if physical.closeCount() != 1 {
		t.Fatal("unconfirmed physical quarantine was not attempted exactly once")
	}
}

func TestGatewayDestinationTokenRotationFencedCASRollbackAfterBudgetIsUnknown(t *testing.T) {
	encoded, err := json.Marshal(NewWebhookDest(testOnlyGatewayURL))
	if err != nil {
		t.Fatal("failed to encode rollback-budget destination")
	}
	deadlineCtx, cancelDeadline := context.WithTimeout(testOnlyGatewayCASSystemContext(), gatewayDestinationTokenRotationCASLimit)
	defer cancelDeadline()
	ctx, cancel := context.WithCancel(deadlineCtx)
	physical := &gatewayRotationStoreTestPhysicalConnection{}
	conn := &gatewayRotationStoreTestConn{
		destJSON:     encoded,
		execErr:      errors.New("test-only ambiguous execution before rollback"),
		rollbackHook: cancel,
		physical:     physical,
	}
	db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
	if err != nil {
		t.Fatal("failed to create rollback-budget store")
	}
	fencedStore := store.(gatewayDestinationTokenRotationFencedStore)
	err = fencedStore.compareAndSwapWithFence(
		ctx,
		testOnlyGatewayCASContactMethodID,
		NewWebhookDest(testOnlyGatewayURL),
		NewWebhookDest(strings.TrimSuffix(testOnlyGatewayURL, testOnlyGatewayToken)+testOnlyGatewayCASReplacementToken(0x70)),
	)
	requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASOutcomeUnknown, nil)
	if physical.closeCount() != 1 {
		t.Fatal("rollback that completed after its context budget was not fail-closed and discarded")
	}
}

func TestGatewayDestinationTokenRotationAuthoritativeStoreDiscardsEveryBeginFailure(t *testing.T) {
	private := errors.New("test-only authoritative begin failure")
	var typedNil *gatewayRotationStoreTestTypedNilTransaction
	for _, test := range []struct {
		name        string
		transaction gatewayDestinationTokenRotationAuthoritativeTransaction
		err         error
	}{
		{name: "begin error", err: private},
		{name: "begin context error", err: context.Canceled},
		{name: "typed nil transaction", transaction: typedNil},
		{name: "typed nil with error", transaction: typedNil, err: private},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection := &gatewayRotationStoreTestSeamConnection{
				transaction: test.transaction,
				err:         test.err,
			}
			store, err := newGatewayDestinationTokenRotationAuthoritativeStore(
				func(context.Context) (gatewayDestinationTokenRotationAuthoritativeConnection, error) {
					return connection, nil
				},
			)
			if err != nil {
				t.Fatal("failed to construct authoritative begin-fault seam")
			}
			callbackCalls := 0
			err = store.WithLockedGatewayDestination(
				testOnlyGatewayCASSystemContext(),
				testOnlyGatewayCASContactMethodID,
				func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination) { callbackCalls++ },
			)
			requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, private)
			if callbackCalls != 0 || connection.begins != 1 || connection.discards != 1 || connection.closes != 1 {
				t.Fatal("authoritative BeginTx failure did not discard and close its acquired connection")
			}
		})
	}
}

func TestGatewayDestinationTokenRotationSQLAuthoritativeStoreQueryAndRollbackFaults(t *testing.T) {
	destination := NewWebhookDest(testOnlyGatewayURL)
	encoded, err := json.Marshal(destination)
	if err != nil {
		t.Fatal("failed to encode authoritative fault destination")
	}
	private := errors.New("test-only authoritative SQL fault")
	for _, test := range []struct {
		name          string
		beginErr      error
		queryErr      error
		rollbackErr   error
		wantCallback  int
		wantQueries   int
		wantRollback  int
		wantDiscarded int
	}{
		{name: "begin error discards physical connection", beginErr: private, wantDiscarded: 1},
		{name: "begin context error discards physical connection", beginErr: context.Canceled, wantDiscarded: 1},
		{name: "query error rolls back", queryErr: private, wantQueries: 1, wantRollback: 1},
		{name: "query context error rolls back", queryErr: context.DeadlineExceeded, wantQueries: 1, wantRollback: 1},
		{name: "query and rollback error discards", queryErr: private, rollbackErr: private, wantQueries: 1, wantRollback: 1, wantDiscarded: 1},
		{name: "confirmed read rollback error discards", rollbackErr: private, wantCallback: 1, wantQueries: 1, wantRollback: 1, wantDiscarded: 1},
		{name: "unexpected transaction done discards", rollbackErr: sql.ErrTxDone, wantCallback: 1, wantQueries: 1, wantRollback: 1, wantDiscarded: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			physical := &gatewayRotationStoreTestPhysicalConnection{}
			connection := &gatewayRotationStoreTestConn{
				destJSON:    encoded,
				beginErr:    test.beginErr,
				queryErr:    test.queryErr,
				rollbackErr: test.rollbackErr,
				physical:    physical,
			}
			db := sql.OpenDB(gatewayRotationStoreTestConnector{conn: connection})
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = db.Close() })
			store, err := NewGatewayDestinationTokenRotationAuthoritativeStore(db)
			if err != nil {
				t.Fatal("failed to construct authoritative fault store")
			}
			callbackCalls := 0
			err = store.WithLockedGatewayDestination(
				testOnlyGatewayCASSystemContext(),
				testOnlyGatewayCASContactMethodID,
				func(context.Context, GatewayDestinationTokenRotationAuthoritativeDestination) { callbackCalls++ },
			)
			requireRotationFixedError(t, err, ErrGatewayDestinationTokenRotationReconciliationRequired, private)
			connection.mu.Lock()
			rollbacks := connection.rollbacks
			queries := connection.queries
			connection.mu.Unlock()
			if callbackCalls != test.wantCallback || queries != test.wantQueries || rollbacks != test.wantRollback ||
				physical.closeCount() != test.wantDiscarded {
				t.Fatal("authoritative query/rollback fault had an unsafe connection disposition")
			}
		})
	}
}

var _ driver.Connector = gatewayRotationStoreTestConnector{}
var _ driver.ConnBeginTx = (*gatewayRotationStoreTestConn)(nil)
var _ driver.QueryerContext = (*gatewayRotationStoreTestConn)(nil)
var _ driver.ExecerContext = (*gatewayRotationStoreTestConn)(nil)
var _ driver.NamedValueChecker = (*gatewayRotationStoreTestConn)(nil)
