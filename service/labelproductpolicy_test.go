package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/label"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/search"
)

func TestLabelSearchProductPolicyBeforeSQL(t *testing.T) {
	token := "token=" + uuid.NewString()
	for _, input := range []string{"policy/key=value", "policy/key!=value", "policy/key=*", "policy/key!=*", "policy/key=", "policy/key!=", token + " policy/key=value", token + " policy/key!=*", "token=short"} {
		t.Run(input, func(t *testing.T) {
			opts := SearchOptions{Search: input}
			_, err := renderData(opts).Normalize()
			require.ErrorIs(t, err, label.ErrDisabled)
			// A nil DB proves rejection precedes SQL rendering/execution.
			for _, ctx := range []context.Context{permission.SystemContext(context.Background(), "test"), permission.UserContext(context.Background(), uuid.NewString(), permission.RoleUser)} {
				rows, err := new(Store).Search(ctx, &opts)
				require.Nil(t, rows)
				require.ErrorIs(t, err, label.ErrDisabled)
			}
			cursor, err := search.Cursor(opts)
			require.NoError(t, err)
			var restored SearchOptions
			require.NoError(t, search.ParseCursor(cursor, &restored))
			require.ErrorIs(t, restored.ValidateLabelPolicy(), label.ErrDisabled)
		})
	}
}

func TestNonLabelSearchAndCursorProductPolicy(t *testing.T) {
	for _, input := range []string{"", "ordinary service", "token=" + uuid.NewString()} {
		opts := SearchOptions{Search: input, After: SearchCursor{Name: "neighbor"}}
		data, err := renderData(opts).Normalize()
		require.NoError(t, err)
		query, _, err := search.RenderQuery(context.Background(), searchTemplate, data)
		require.NoError(t, err)
		require.NotContains(t, query, "JOIN labels")
		require.NotContains(t, query, "FROM labels")
		cursor, err := search.Cursor(opts)
		require.NoError(t, err)
		var restored SearchOptions
		require.NoError(t, search.ParseCursor(cursor, &restored))
		require.Equal(t, opts, restored)
		require.NoError(t, restored.ValidateLabelPolicy())
	}
}
