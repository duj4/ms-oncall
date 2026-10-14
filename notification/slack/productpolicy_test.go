package slack

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	slackapi "github.com/slack-go/slack"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/permission"
)

type policyTransport struct{ calls atomic.Int32 }

func (p *policyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	p.calls.Add(1)
	return nil, errors.New("unexpected excluded provider request")
}

func TestExcludedSlackColdWarmOutbound(t *testing.T) {
	var cfg config.Config
	cfg.Slack.Enable, cfg.Slack.InteractiveMessages = true, true
	ctx := cfg.Context(permission.SystemContext(context.Background(), "ProviderPolicyTest"))
	transport := new(policyTransport)
	s, err := NewChannelSender(ctx, Config{Client: &http.Client{Transport: transport}})
	require.NoError(t, err)
	for _, warm := range []bool{false, true} {
		if warm {
			s.botInfoCache.Add("", &slackapi.AuthTestResponse{TeamID: "T", User: "excluded-cached-bot"})
			s.teamInfoCache.Add("T", &slackapi.TeamInfo{ID: "T"})
			s.userInfoCache.Add("U", &slackapi.User{ID: "U"})
			s.chanCache.Add("C", &Channel{ID: "C"})
			s.listCache.Add("", []Channel{{ID: "C"}})
			s.ugInfoCache.Add("G", UserGroup{ID: "G"})
			s.ugCache.Add("T", []slackapi.UserGroup{{ID: "G"}})
		}
		for range 2 {
			var sdkCalls int
			for _, call := range []func() error{
				func() error { _, err := s.BotName(ctx); return err },
				func() error { _, err := s.TeamID(ctx); return err },
				func() error { _, err := s.Team(ctx, "T"); return err },
				func() error { _, err := s.User(ctx, "U"); return err },
				func() error { _, err := s.Channel(ctx, "C"); return err },
				func() error { _, err := s.UserGroup(ctx, "G"); return err },
				func() error { _, err := s.ListChannels(ctx); return err },
				func() error { _, err := s.ListUserGroups(ctx); return err },
				func() error { return s.ValidateChannel(ctx, "C") },
				func() error { return s.ValidateUser(ctx, "U") },
				func() error { return s.ValidateUserGroup(ctx, "G") },
				func() error { _, err := s.DisplayInfo(ctx, nil); return err },
				func() error { _, err := s.SearchField(ctx, FieldSlackChannelID, nfydest.SearchOptions{}); return err },
				func() error { _, err := s.FieldLabel(ctx, FieldSlackChannelID, "C"); return err },
				func() error { _, err := s.SendMessage(ctx, nil); return err },
				func() error { _, err := s.DMSender().SendMessage(ctx, nil); return err },
				func() error { _, err := s.UserGroupSender().SendMessage(ctx, nil); return err },
				func() error { return s.withClient(ctx, func(*slackapi.Client) error { sdkCalls++; return nil }) },
			} {
				require.ErrorIs(t, call(), nfydest.ErrNotEnabled)
			}
			info, err := s.TypeInfo(ctx)
			require.NoError(t, err)
			require.False(t, info.Enabled)
			require.NotContains(t, info.RequiredFields[0].Hint, "excluded-cached-bot")
			require.Zero(t, sdkCalls)
			require.Zero(t, transport.calls.Load())
		}
	}
}
