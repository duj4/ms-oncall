package permission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/target/goalert/util/log"
)

// This sentinel is synthetic and must never be used as a real credential.
const syntheticIntegrationKeyID = "synthetic-integration-key-not-for-production"

func TestSourceContextIntegrationKeyLogging(t *testing.T) {
	src := &SourceInfo{Type: SourceTypeIntegrationKey, ID: syntheticIntegrationKeyID}
	want := *src
	ctx := ServiceSourceContext(context.Background(), "synthetic-service", src)

	if got := Source(ctx); got == nil || *got != want {
		t.Fatal("internal source identity or type changed")
	}
	if src.String() != "SourceTypeIntegrationKey{"+syntheticIntegrationKeyID+"}" {
		t.Fatal("SourceInfo.String behavior changed")
	}
	if !All(ctx) || !Service(ctx) || ServiceID(ctx) != "synthetic-service" ||
		User(ctx) || Admin(ctx) || System(ctx) {
		t.Fatal("service authentication or privileges changed")
	}
	if err := LimitCheckAny(ctx, MatchService("synthetic-service")); err != nil {
		t.Fatal("matching service permission rejected")
	}
	if err := LimitCheckAny(ctx, MatchService("other-service")); err == nil {
		t.Fatal("unrelated service permission granted")
	}

	fields := log.ContextFields(ctx)
	if fields["AuthSource"] != "SourceTypeIntegrationKey" {
		t.Error("AuthSource must contain only the safe source type")
	}
	if fields["AuthServiceID"] != "synthetic-service" {
		t.Error("safe service logging field changed")
	}
	projected, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(projected, []byte(syntheticIntegrationKeyID)) {
		t.Error("full ContextFields projection exposes the synthetic credential")
	}

	// Both the caller's value and values returned by Source remain copies.
	src.ID = "changed-synthetic-source"
	got := Source(ctx)
	got.ID = "changed-synthetic-return-value"
	if *Source(ctx) != want {
		t.Fatal("internal source copy changed")
	}
	if !t.Failed() {
		t.Log("internal identity/type and service permissions preserved; safe AuthSource=SourceTypeIntegrationKey")
	}
}

func TestSourceContextOtherSourceLogging(t *testing.T) {
	base := context.Background()
	tests := []struct {
		name string
		ctx  context.Context
		src  SourceInfo
		want string
	}{
		{"auth_provider", UserContext(base, "synthetic-user", RoleUser),
			SourceInfo{Type: SourceTypeAuthProvider, ID: "synthetic-session"},
			"SourceTypeAuthProvider{synthetic-session}"},
		{"gql_api_key", UserContext(base, "synthetic-user", RoleAdmin),
			SourceInfo{Type: SourceTypeGQLAPIKey, ID: "synthetic-gql-key"},
			"SourceTypeGQLAPIKey{synthetic-gql-key}"},
		{"uik", ServiceContext(base, "synthetic-service"),
			SourceInfo{Type: SourceTypeUIK, ID: "synthetic-uik"},
			"SourceTypeUIK{synthetic-uik}"},
		{"notification_callback", UserContext(base, "synthetic-user", RoleUser),
			SourceInfo{Type: SourceTypeNotificationCallback, ID: "synthetic-callback"},
			"SourceTypeNotificationCallback{synthetic-callback}"},
		{"empty_id", base, SourceInfo{Type: SourceTypeAuthProvider}, "SourceTypeAuthProvider"},
		{"unknown_type", base, SourceInfo{Type: SourceType(-1), ID: "synthetic-unknown"},
			"SourceType(-1){synthetic-unknown}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := SourceContext(tt.ctx, &tt.src)
			if got := Source(ctx); got == nil || *got != tt.src {
				t.Fatal("internal source changed")
			}
			if got := log.ContextFields(ctx)["AuthSource"]; got != tt.want {
				t.Fatal("unrelated source logging format changed")
			}
			for _, check := range []Checker{All, Admin, User, Service, System,
				MatchUser("synthetic-user"), MatchService("synthetic-service")} {
				if check(ctx) != check(tt.ctx) ||
					(LimitCheckAny(ctx, check) == nil) != (LimitCheckAny(tt.ctx, check) == nil) {
					t.Fatal("permission check changed")
				}
			}
		})
	}
	t.Run("nil_source", func(t *testing.T) {
		if SourceContext(base, nil) != base {
			t.Fatal("nil source no longer preserves the context")
		}
	})
}

func TestSourceContextIntegrationKeyLogSerialization(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			logger := log.NewLogger()
			logger.SetOutput(&output)
			logger.EnableDebug()
			logger.EnableStacks()
			if format == "json" {
				logger.EnableJSON()
			}
			ctx := ServiceSourceContext(logger.BackgroundContext(), "synthetic-service",
				&SourceInfo{Type: SourceTypeIntegrationKey, ID: syntheticIntegrationKeyID})
			entries := []struct {
				name string
				emit func()
			}{
				{"request", func() { log.Logf(ctx, "request complete") }},
				{"debug", func() { log.Debugf(ctx, "synthetic debug") }},
				{"error", func() { log.Log(ctx, errors.New("synthetic failure")) }},
				{"debug_error", func() { log.Debug(ctx, errors.New("synthetic debug failure")) }},
			}
			for _, entry := range entries {
				t.Run(entry.name, func(t *testing.T) {
					output.Reset()
					entry.emit()
					raw := output.Bytes()
					if len(raw) == 0 {
						t.Fatal("logger emitted no output")
					}
					if bytes.Contains(raw, []byte(syntheticIntegrationKeyID)) {
						t.Error("serialized log exposes the synthetic credential")
					}
					if format == "json" {
						var fields map[string]any
						if err := json.Unmarshal(raw, &fields); err != nil {
							t.Fatal(err)
						}
						if fields["AuthSource"] != "SourceTypeIntegrationKey" ||
							fields["AuthServiceID"] != "synthetic-service" {
							t.Error("structured log source or service projection changed")
						}
						if strings.Contains(entry.name, "error") && fields["error"] == nil {
							t.Error("error field missing")
						}
					} else {
						if !bytes.Contains(raw, []byte("AuthSource=SourceTypeIntegrationKey")) ||
							!bytes.Contains(raw, []byte("AuthServiceID=synthetic-service")) {
							t.Error("text log source or service projection missing")
						}
						if strings.Contains(entry.name, "error") && !bytes.Contains(raw, []byte("error=")) {
							t.Error("text error field missing")
						}
					}
				})
			}
		})
	}
}
