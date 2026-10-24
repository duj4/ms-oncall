package apikey

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

// Store is used to manage API keys.
type Store struct {
	db  *sql.DB
	key keyring.Keyring

	polCache      *polCache
	lastUsedCache *lastUsedCache
}

// NewStore will create a new Store.
func NewStore(ctx context.Context, db *sql.DB, key keyring.Keyring) (*Store, error) {
	s := &Store{
		db:  db,
		key: key,
	}

	s.polCache = newPolCache(polCacheConfig{
		FillFunc: s._fetchPolicyInfo,
		Verify:   s._verifyPolicyID,
		MaxSize:  1000,
	})

	s.lastUsedCache = newLastUsedCache(1000, s._updateLastUsed)

	return s, nil
}

type APIKeyInfo struct {
	ID          uuid.UUID
	Name        string
	Description string
	ExpiresAt   time.Time
	LastUsed    *APIKeyUsage
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CreatedBy   *uuid.UUID
	UpdatedBy   *uuid.UUID
	Query       string
	Role        permission.Role
}

func (s *Store) FindAllAdminGraphQLKeys(ctx context.Context) ([]APIKeyInfo, error) {
	err := permission.LimitCheckAny(ctx, permission.Admin)
	if err != nil {
		return nil, err
	}

	keys, err := gadb.New(s.db).APIKeyList(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]APIKeyInfo, 0, len(keys))
	for _, k := range keys {
		k := k

		var p GQLPolicy
		err = json.Unmarshal(k.Policy, &p)
		if err != nil {
			log.Log(ctx, fmt.Errorf("invalid policy for key %s: %w", k.ID, err))
			continue
		}
		if p.Version != 1 {
			log.Log(ctx, fmt.Errorf("unknown policy version for key %s: %d", k.ID, p.Version))
			continue
		}

		var lastUsed *APIKeyUsage
		if k.LastUsedAt.Valid {
			var ip string
			if k.LastIpAddress.Valid {
				ip = k.LastIpAddress.IPNet.IP.String()
			}
			lastUsed = &APIKeyUsage{
				UserAgent: k.LastUserAgent.String,
				IP:        ip,
				Time:      k.LastUsedAt.Time,
			}
		}

		res = append(res, APIKeyInfo{
			ID:          k.ID,
			Name:        k.Name,
			Description: k.Description,
			ExpiresAt:   k.ExpiresAt,
			LastUsed:    lastUsed,
			CreatedAt:   k.CreatedAt,
			UpdatedAt:   k.UpdatedAt,
			CreatedBy:   &k.CreatedBy.UUID,
			UpdatedBy:   &k.UpdatedBy.UUID,
			Query:       p.Query,
			Role:        p.Role,
		})
	}

	return res, nil
}

type APIKeyUsage struct {
	UserAgent string
	IP        string
	Time      time.Time
}

type UpdateKey struct {
	ID          uuid.UUID
	Name        string
	Description string
}

func (s *Store) UpdateAdminGraphQLKey(ctx context.Context, id uuid.UUID, name, desc *string) error {
	err := permission.LimitCheckAny(ctx, permission.Admin)
	if err != nil {
		return err
	}

	if name != nil {
		err = validate.IDName("Name", *name)
	}
	if desc != nil {
		err = validate.Many(err, validate.Text("Description", *desc, 0, 255))
	}
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer sqlutil.Rollback(ctx, "UpdateAdminGraphQLKey", tx)

	key, err := gadb.New(tx).APIKeyForUpdate(ctx, id)
	if err != nil {
		return err
	}
	if name != nil {
		key.Name = *name
	}
	if desc != nil {
		key.Description = *desc
	}

	err = gadb.New(tx).APIKeyUpdate(ctx, gadb.APIKeyUpdateParams{
		ID:          id,
		Name:        key.Name,
		Description: key.Description,
		UpdatedBy:   permission.UserNullUUID(ctx),
	})
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) DeleteAdminGraphQLKey(ctx context.Context, id uuid.UUID) error {
	err := permission.LimitCheckAny(ctx, permission.Admin)
	if err != nil {
		return err
	}

	return gadb.New(s.db).APIKeyDelete(ctx, gadb.APIKeyDeleteParams{
		DeletedBy: permission.UserNullUUID(ctx),
		ID:        id,
	})
}

// AuthorizeGraphQL rejects the retired legacy GraphQL key protocol, including
// unrecognized policy versions. A future Machine protocol must authenticate its
// own authority and must never fall back to legacy Policy.Role authorization.
func (s *Store) AuthorizeGraphQL(ctx context.Context, tok, ua, ip string) (context.Context, error) {
	return ctx, permission.Unauthorized()
}

// NewAdminGQLKeyOpts is used to create a new GraphQL API key.
type NewAdminGQLKeyOpts struct {
	Name    string
	Desc    string
	Expires time.Time
	Role    permission.Role
	Query   string
}

// CreateAdminGraphQLKey rejects issuance of the retired legacy GraphQL keys for
// every caller, including internal System callers. Future Machine key issuance
// requires an independently authorized policy; it must not revive legacy V1.
func (s *Store) CreateAdminGraphQLKey(ctx context.Context, opt NewAdminGQLKeyOpts) (uuid.UUID, string, error) {
	return uuid.Nil, "", permission.NewAccessDenied("legacy GraphQL API key issuance is disabled in MS OnCall")
}
