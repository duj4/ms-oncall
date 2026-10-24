package apikey

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/target/goalert/permission"
)

func TestLegacyGraphQLIssuanceRetired(t *testing.T) {
	// A zero Store deliberately has no database or signer. Rejection must not
	// depend on either being available and cannot have persistence side effects.
	store := new(Store)
	for name, ctx := range map[string]context.Context{
		"anonymous":   context.Background(),
		"human admin": permission.UserContext(context.Background(), uuid.NewString(), permission.RoleAdmin),
		"human user":  permission.UserContext(context.Background(), uuid.NewString(), permission.RoleUser),
		"system":      permission.SystemContext(context.Background(), "LegacyRetirementTest"),
		"legacy machine": permission.UserSourceContext(context.Background(), "", permission.RoleAdmin,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, role := range []permission.Role{permission.RoleAdmin, permission.RoleUser} {
				id, token, err := store.CreateAdminGraphQLKey(ctx, NewAdminGQLKeyOpts{
					Name: "retired", Query: "query { user { id } }", Role: role, Expires: time.Now().Add(time.Hour),
				})
				if !permission.IsPermissionError(err) || id != uuid.Nil || token != "" {
					t.Fatal("legacy issuance must deny with no ID or token")
				}
			}
		})
	}
}

func TestLegacyGraphQLAuthenticationRetired(t *testing.T) {
	// Test-only signing never calls the retired production issuance method.
	key := []byte("synthetic-legacy-retirement-unit-test-key")
	for _, role := range []permission.Role{permission.RoleAdmin, permission.RoleUser} {
		for _, version := range []int{1, 0, 2, 999} {
			data, err := json.Marshal(GQLPolicy{Version: version, Role: role, Query: "query { user { id } }"})
			if err != nil {
				t.Fatal(err)
			}
			info, err := parsePolicyInfo(data)
			if err != nil {
				t.Fatal(err)
			}
			id := uuid.New()
			token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, NewGraphQLClaims(id, info.Hash, time.Now().Add(time.Hour))).SignedString(key)
			if err != nil {
				t.Fatal("test-only signing failed")
			}
			var claims Claims
			_, err = jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (any, error) { return key, nil },
				jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(Issuer), jwt.WithAudience(Audience))
			if err != nil || !hmac.Equal(claims.PolicyHash, info.Hash) {
				t.Fatal("invalid signed fixture")
			}
			// Populate the real legacy cache, including its warm-cache case.
			cache := newPolCache(polCacheConfig{MaxSize: 1,
				FillFunc: func(context.Context, uuid.UUID) (*policyInfo, bool, error) { return info, true, nil },
				Verify:   func(context.Context, uuid.UUID) (bool, error) { return true, nil },
			})
			if _, ok, err := cache.Get(context.Background(), id); err != nil || !ok {
				t.Fatal("cache fixture failed")
			}
			store := &Store{polCache: cache}
			for _, raw := range []string{token, "", "malformed", token + "invalid-signature"} {
				ctx := context.Background()
				got, err := store.AuthorizeGraphQL(ctx, raw, "synthetic-agent", "127.0.0.1")
				if !permission.IsUnauthorized(err) || got != ctx {
					t.Fatal("legacy authentication must fail without changing context")
				}
				if permission.All(got) || permission.Admin(got) || permission.User(got) || permission.System(got) || PolicyFromContext(got) != nil || permission.Source(got) != nil {
					t.Fatal("retired authentication granted authority")
				}
			}
		}
	}
}
