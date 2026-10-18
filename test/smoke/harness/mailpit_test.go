package harness

import (
	"context"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMailpit(t *testing.T) {
	var mp *mailpit
	t.Run("owner", func(t *testing.T) {
		mp = newMailpit(t)
		assertMailpitStorage(t, mp)
		testMailpitMessages(t, mp)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			require.FileExists(t, mp.database+suffix)
		}
		t.Logf("mailpit pid=%d database=%s: SQLite/WAL/SHM present", mp.cmd.Process.Pid, mp.database)
	})
	require.NotNil(t, mp)
	assertMailpitCleaned(t, mp)
	if runtime.GOOS != "windows" {
		assert.True(t, mp.cmd.ProcessState.Success(), "expected graceful Mailpit exit")
	}
}

func assertMailpitStorage(t *testing.T, mp *mailpit) {
	t.Helper()
	dir := filepath.Dir(mp.database)
	require.DirExists(t, dir)
	require.FileExists(t, mp.database)
	require.NotEqual(t, filepath.Clean(os.TempDir()), dir)
	require.Equal(t, filepath.Clean(os.TempDir()), filepath.Dir(dir))
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		var value string
		for _, entry := range mp.cmd.Environ() {
			if strings.HasPrefix(entry, key+"=") {
				value = strings.TrimPrefix(entry, key+"=")
			}
		}
		require.Equal(t, dir, value, "child-only %s", key)
	}
}

func assertMailpitCleaned(t *testing.T, mp *mailpit) {
	t.Helper()
	select {
	case <-mp.done:
	default:
		t.Fatal("Mailpit cleanup did not finish Wait")
	}
	require.NotNil(t, mp.cmd.ProcessState, "expected Wait to reap Mailpit")
	assert.ErrorIs(t, mp.cmd.Process.Signal(os.Interrupt), os.ErrProcessDone)
	assert.False(t, isListening(mp.smtpAddr), "SMTP listener must close")
	assert.False(t, isListening(mp.apiAddr), "API listener must close")
	for _, path := range []string{filepath.Dir(mp.database), mp.database, mp.database + "-wal", mp.database + "-shm"} {
		_, err := os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist, "owned path must be removed: %s", path)
	}
	// Cleanup is safe to call again, without another Wait or signal.
	assert.NoError(t, mp.cleanup())
	t.Logf("mailpit pid=%d reaped (%s); directory and SQLite sidecars removed: %s", mp.cmd.Process.Pid, mp.cmd.ProcessState, filepath.Dir(mp.database))
}

func TestNewMailpitForcedCleanup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SIGSTOP regression requires Linux; normal cleanup remains covered")
	}
	kill, err := exec.LookPath("kill")
	require.NoError(t, err, "SIGSTOP regression requires kill")
	var mp *mailpit
	var stopped time.Time
	t.Run("owner", func(t *testing.T) {
		mp = newMailpit(t)
		testMailpitMessages(t, mp)
		for _, suffix := range []string{"", "-wal", "-shm"} {
			require.FileExists(t, mp.database+suffix)
		}
		// A stopped real Mailpit cannot handle Interrupt. Cleanup must time out,
		// kill it, reap it, and then remove its database and sidecars.
		require.NoError(t, exec.Command(kill, "-STOP", strconv.Itoa(mp.cmd.Process.Pid)).Run())
		stopped = time.Now()
	})
	require.NotNil(t, mp)
	assert.Less(t, time.Since(stopped), 2*mailpitStopTimeout+3*time.Second)
	assertMailpitCleaned(t, mp)
	assert.False(t, mp.cmd.ProcessState.Success(), "expected forced termination")
}

func TestNewMailpitParallel(t *testing.T) {
	var first, second *mailpit
	t.Run("owner", func(t *testing.T) {
		// One owner keeps both instances alive without requiring two parallel
		// test slots. Constructors retain their existing startup serialization.
		first = newMailpit(t)
		second = newMailpit(t)
		require.NotEqual(t, first.database, second.database)
		require.NotEqual(t, filepath.Dir(first.database), filepath.Dir(second.database))

		for _, mp := range []*mailpit{first, second} {
			select {
			case <-mp.done:
				t.Fatal("Mailpit exited while both instances must remain alive")
			default:
			}
			assertMailpitStorage(t, mp)
			require.True(t, isListening(mp.smtpAddr), "overlapping SMTP listener must be responsive")
			require.True(t, isListening(mp.apiAddr), "overlapping API listener must be responsive")
			require.Empty(t, mp.UnreadMessages(), "each instance must start with an empty mailbox")
		}

		testMailpitMessages(t, first)
		require.Empty(t, second.UnreadMessages(), "first instance messages must not appear in the second")
		testMailpitMessages(t, second)
		require.Len(t, first.UnreadMessages(), 1, "second instance must not change the first instance's unread state")
		t.Logf("overlapping mailpit instances: pid=%d database=%s; pid=%d database=%s",
			first.cmd.Process.Pid, first.database, second.cmd.Process.Pid, second.database)
	})
	require.NotNil(t, first)
	require.NotNil(t, second)
	assertMailpitCleaned(t, first)
	assertMailpitCleaned(t, second)
}

func TestNewMailpitStartupFailure(t *testing.T) {
	const marker = "GOALERT_MAILPIT_STARTUP_FAILURE"
	if os.Getenv(marker) == "1" {
		newMailpit(t)
		t.Fatal("invalid Mailpit configuration unexpectedly became ready")
	}
	// Exercise Fatal/readiness cleanup in a subprocess, with no mutation of
	// the parent environment or of the pinned Mailpit binary.
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNewMailpitStartupFailure$", "-test.v", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), marker+"=1", "TMPDIR="+dir, "TMP="+dir, "TEMP="+dir,
		"MP_SMTP_AUTH_FILE="+filepath.Join(dir, "missing-auth-file"))
	output, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "startup failure must not wait for readiness timeout")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitCode())
	require.Contains(t, string(output), "mailpit exited before readiness")
	require.Contains(t, string(output), "missing-auth-file", "preserve startup diagnostics")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "readiness failure must remove owned storage")
	t.Logf("expected startup failure diagnostics:\n%s", output)
}

func testMailpitMessages(t *testing.T, mp *mailpit) {
	t.Helper()

	err := smtp.SendMail(mp.smtpAddr, nil, "example@example.com", []string{"foo@bar.com"}, []byte("Subject: Hello\nTo: foo@bar.com\n\nWorld!"))
	require.NoError(t, err, "expected to be able to send email")

	err = smtp.SendMail(mp.smtpAddr, nil, "example@example.com", []string{"bin@baz.com"}, []byte("Subject: There\nTo: bin@baz.com\n\nThen!"))
	require.NoError(t, err, "expected to be able to send email")

	found := assert.Eventually(t, func() bool {
		found := mp.ReadMessage("foo@bar.com", "World")
		return found
	}, 5*time.Second, 100*time.Millisecond, "expected to find email to foo@bar.com containing 'World'")
	if !found {
		msgs := mp.UnreadMessages()
		t.Fatalf("timeout waiting for email; Got:\n%v", msgs)
	}

	found = mp.ReadMessage("foo@bar.com", "World")
	assert.False(t, found, "expected message to have been marked as read")

	remaining := mp.UnreadMessages()
	assert.Len(t, remaining, 1, "expected one unread message")
}
