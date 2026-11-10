package deleteaudit

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

const (
	MaxEffects      = 16384
	MaxJSONBytes    = 8 * 1024 * 1024
	IntegrationKey  = "integration_key"
	Alert           = "alert"
	ServiceFavorite = "service_favorite"
)

var ErrCapacity = errors.New("service.delete audit capacity exceeded")

// Effect is a closed, safe identity projection. In particular, ResourceUUID
// for an IntegrationKey is its independent audit surrogate, never its token ID.
// Nullable fields deliberately remain present in the serialized envelope.
type Effect struct {
	EffectID             uuid.UUID  `json:"effect_id"`
	ResourceType         string     `json:"resource_type"`
	ResourceUUID         *uuid.UUID `json:"resource_uuid"`
	ResourceNumericID    *int64     `json:"resource_numeric_id"`
	OwnerUserID          *uuid.UUID `json:"owner_user_id"`
	OwnerOrganizationID  *uuid.UUID `json:"owner_organization_id"`
	OwnerOrgResolution   string     `json:"owner_org_resolution"`
	TargetOrganizationID uuid.UUID  `json:"target_organization_id"`
	Relation             string     `json:"relation"`
	Change               string     `json:"change"`
	Provenance           string     `json:"provenance"`
	DeletionMechanism    string     `json:"deletion_mechanism"`
	Cause                string     `json:"cause"`
}

func compareEffect(a, b Effect) int {
	if n := stringsCompare(a.ResourceType, b.ResourceType); n != 0 {
		return n
	}
	if a.ResourceUUID != nil && b.ResourceUUID != nil {
		if n := slices.Compare(a.ResourceUUID[:], b.ResourceUUID[:]); n != 0 {
			return n
		}
	} else if a.ResourceNumericID != nil && b.ResourceNumericID != nil {
		if *a.ResourceNumericID < *b.ResourceNumericID {
			return -1
		}
		if *a.ResourceNumericID > *b.ResourceNumericID {
			return 1
		}
	}
	return stringsCompare(a.Relation, b.Relation)
}

func stringsCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Canonical freezes ordering and microsecond time without inventing identities.
// IDs are assigned when actual evidence is accepted, and survive exact replay.
func (e Event) Canonical() Event {
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	e.Effects = append([]Effect{}, e.Effects...)
	slices.SortFunc(e.Effects, compareEffect)
	return e
}

func (e Effect) valid(org uuid.UUID) bool {
	if e.EffectID == uuid.Nil || e.TargetOrganizationID != org || org == uuid.Nil {
		return false
	}
	if e.Provenance == "EXPLICIT" {
		explicit := e.DeletionMechanism == "explicit_sql" && e.Cause == "explicit_target"
		cascade := e.DeletionMechanism == "fk_cascade" && e.Cause == "service_delete"
		if !explicit && !cascade {
			return false
		}
	} else if e.Provenance != "CASCADE" || e.DeletionMechanism != "fk_cascade" || e.Cause != "service_delete" {
		return false
	}
	if e.ResourceType == IntegrationKey {
		if e.ResourceUUID == nil || *e.ResourceUUID == uuid.Nil || e.ResourceNumericID != nil || e.Relation != "service.integration_key" || e.Change != "deleted" {
			return false
		}
	} else {
		if e.ResourceUUID != nil || e.ResourceNumericID == nil || *e.ResourceNumericID <= 0 {
			return false
		}
		switch e.ResourceType {
		case Alert:
			if e.Relation != "service.alert" || e.Change != "deleted" {
				return false
			}
		case ServiceFavorite:
			if e.Relation != "service.favorite" || e.Change != "relationship_removed" || e.Provenance != "CASCADE" {
				return false
			}
		default:
			return false
		}
	}
	if e.ResourceType != ServiceFavorite {
		return e.OwnerUserID == nil && e.OwnerOrganizationID == nil && e.OwnerOrgResolution == "not_applicable"
	}
	if e.OwnerUserID == nil || *e.OwnerUserID == uuid.Nil {
		return false
	}
	if e.OwnerOrgResolution == "unknown" {
		return e.OwnerOrganizationID == nil
	}
	if e.OwnerOrganizationID == nil || *e.OwnerOrganizationID == uuid.Nil {
		return false
	}
	isDefault := e.OwnerOrganizationID.String() == organization.DefaultOrganizationID
	return e.OwnerOrgResolution == "known_default" && isDefault || e.OwnerOrgResolution == "known_normal" && !isDefault
}

// Validate accepts only new complete envelopes. Historical SQL NULL envelopes
// remain unread/unchanged in the database and cannot be appended as new writes.
func (e Event) Validate() error {
	if !e.valid() || e.EffectsVersion != 1 || e.ExecutionID == uuid.Nil || e.Outcome != "committed" && len(e.Effects) != 0 {
		return ErrInvalid
	}
	if len(e.Effects) > MaxEffects {
		return ErrCapacity
	}
	seen := make(map[uuid.UUID]bool, len(e.Effects))
	e = e.Canonical()
	for i, f := range e.Effects {
		if !f.valid(e.TargetOrganizationID) || seen[f.EffectID] || i > 0 && compareEffect(e.Effects[i-1], f) == 0 {
			return ErrInvalid
		}
		seen[f.EffectID] = true
	}
	raw, err := json.Marshal(e.Effects)
	if err != nil {
		return ErrInvalid
	}
	if len(raw) > MaxJSONBytes {
		return ErrCapacity
	}
	return nil
}

// ValidateBatch enforces one Service-group budget and one root per child.
func ValidateBatch(events []Event) error {
	count, size := 0, 0
	seen := make(map[string]bool)
	ids := make(map[uuid.UUID]bool)
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		raw, _ := json.Marshal(e.Canonical().Effects)
		count += len(e.Effects)
		size += len(raw)
		if count > MaxEffects || size > MaxJSONBytes {
			return ErrCapacity
		}
		for _, f := range e.Effects {
			raw, _ := json.Marshal(struct {
				Type     string
				UUID     *uuid.UUID
				Numeric  *int64
				Relation string
			}{f.ResourceType, f.ResourceUUID, f.ResourceNumericID, f.Relation})
			if seen[string(raw)] || ids[f.EffectID] {
				return ErrInvalid
			}
			seen[string(raw)], ids[f.EffectID] = true, true
		}
	}
	return nil
}
