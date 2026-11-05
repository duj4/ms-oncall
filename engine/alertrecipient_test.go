package engine

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/engine/message"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/retry"
)

type recipientTestDB struct {
	failStage string
	failure   error
	valid     bool
	queries   int
}
type recipientConnector struct{ db *recipientTestDB }

func (c recipientConnector) Connect(context.Context) (driver.Conn, error) {
	return recipientConn(c), nil
}
func (c recipientConnector) Driver() driver.Driver { return recipientDriver(c) }

type recipientDriver struct{ db *recipientTestDB }

func (d recipientDriver) Open(string) (driver.Conn, error) { return recipientConn(d), nil }

type recipientConn struct{ db *recipientTestDB }

func (recipientConn) CheckNamedValue(*driver.NamedValue) error { return nil }

func (recipientConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (recipientConn) Close() error { return nil }
func (c recipientConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c recipientConn) BeginTx(_ context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if !opts.ReadOnly || opts.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
		return nil, errors.New("authority snapshot must be read only repeatable read")
	}
	if c.db.failStage == "begin" {
		return nil, c.db.failure
	}
	return recipientTx(c), nil
}

type recipientTx struct{ db *recipientTestDB }

func (t recipientTx) Commit() error {
	if t.db.failStage == "commit" {
		return t.db.failure
	}
	return nil
}
func (recipientTx) Rollback() error { return nil }
func (c recipientConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.db.queries++
	stage := "message"
	if strings.Contains(q, "public.user_organization_assignments") {
		stage = "assignment"
	}
	if c.db.failStage == stage {
		return nil, c.db.failure
	}
	owner := "11111111-2222-4333-8444-555555555555"
	org := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	values := []driver.Value{owner, org, c.db.valid}
	if stage == "assignment" {
		values = []driver.Value{owner, "admin", org, "ORG_MEMBER"}
	}
	return &alertStatusTestRows{columns: make([]string, len(values)), values: [][]driver.Value{values}}, nil
}

func recipientTestMessage() *message.Message {
	return &message.Message{ID: uuid.NewString(), UserID: "11111111-2222-4333-8444-555555555555",
		ServiceID: uuid.NewString(), AlertID: 42, Type: notification.MessageTypeAlert,
		DestID: notification.DestID{CMID: uuid.NullUUID{UUID: uuid.New(), Valid: true}},
		Dest:   gadb.NewDestV1("EMAIL", "address", "synthetic@example.invalid")}
}

func TestAlertRecipientAuthorityFailures(t *testing.T) {
	for _, stage := range []string{"begin", "message", "assignment", "commit"} {
		for _, failure := range []error{context.Canceled, context.DeadlineExceeded, &pgconn.PgError{Code: "08006", Message: "private SQL destination synthetic@example.invalid"}} {
			t.Run(stage+fmt.Sprintf("/%T/%v", failure, retry.IsTemporaryError(failure)), func(t *testing.T) {
				source := &recipientTestDB{failStage: stage, failure: failure, valid: true}
				db := sql.OpenDB(recipientConnector{source})
				t.Cleanup(func() { db.Close() })
				eng := &Engine{b: &backend{db: db}}
				result, err := eng.sendMessage(context.Background(), recipientTestMessage())
				require.Nil(t, result)
				require.Error(t, err)
				require.Equal(t, "notification_authority_unavailable", err.Error())
				require.Equal(t, retry.IsTemporaryError(failure), retry.IsTemporaryError(err))
				for _, format := range []string{"%v", "%+v", "%#v"} {
					require.NotContains(t, fmt.Sprintf(format, err), "private SQL")
				}
				if errors.Is(failure, context.Canceled) {
					require.ErrorIs(t, err, context.Canceled)
				}
				if errors.Is(failure, context.DeadlineExceeded) {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
				// No AlertStore/Provider is installed: reaching either would panic.
			})
		}
	}
}

func TestAlertRecipientRechecksEveryAttempt(t *testing.T) {
	source := &recipientTestDB{valid: true}
	db := sql.OpenDB(recipientConnector{source})
	t.Cleanup(func() { db.Close() })
	eng := &Engine{b: &backend{db: db}}
	msg := recipientTestMessage()
	result, err := eng.guardAlertRecipient(context.Background(), msg)
	require.NoError(t, err)
	require.Nil(t, result)
	require.Equal(t, 2, source.queries)
	source.valid = false
	result, err = eng.sendMessage(context.Background(), msg)
	require.NoError(t, err)
	require.Equal(t, notification.StateFailedPerm, result.State)
	require.Equal(t, "notification_recipient_invalid", result.Details)
	require.Equal(t, 3, source.queries)
}

func TestAlertRecipientUnrelatedTypes(t *testing.T) {
	for _, typ := range []gadb.EnumOutgoingMessagesType{notification.MessageTypeVerification, notification.MessageTypeTest, notification.MessageTypeSignalMessage, notification.MessageTypeScheduleOnCallUsers} {
		msg := recipientTestMessage()
		msg.Type = typ
		result, err := (&Engine{}).guardAlertRecipient(context.Background(), msg)
		require.Nil(t, result)
		require.NoError(t, err)
	}
	msg := recipientTestMessage()
	msg.DestID = notification.DestID{NCID: uuid.NullUUID{UUID: uuid.New(), Valid: true}}
	result, err := (&Engine{}).guardAlertRecipient(context.Background(), msg)
	require.Nil(t, result)
	require.NoError(t, err)
}

func TestAlertRecipientMissingAuthority(t *testing.T) {
	for _, stage := range []string{"message", "assignment"} {
		t.Run(stage, func(t *testing.T) {
			source := &recipientTestDB{valid: true, failStage: stage, failure: sql.ErrNoRows}
			db := sql.OpenDB(recipientConnector{source})
			t.Cleanup(func() { db.Close() })
			eng := &Engine{b: &backend{db: db}}
			result, err := eng.sendMessage(context.Background(), recipientTestMessage())
			require.NoError(t, err)
			require.Equal(t, notification.StateFailedPerm, result.State)
			reason := "notification_recipient_invalid"
			if stage == "assignment" {
				reason = "notification_recipient_org_denied"
			}
			require.Equal(t, reason, result.Details)
		})
	}
}
