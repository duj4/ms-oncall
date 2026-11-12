package deleteaudit

import "github.com/google/uuid"

// ValidateReceipts requires an exact, unique identity and complete before-row
// version match; counts alone cannot witness deletion of the intended roots.
func ValidateReceipts(targets, receipts []Before) error {
	if len(targets) != len(receipts) || len(targets) > MaxRoots {
		return ErrInvalid
	}
	want := make(map[uuid.UUID]Before, len(targets))
	for _, b := range targets {
		if b.Validate() != nil {
			return ErrInvalid
		}
		if _, ok := want[b.RootID]; ok {
			return ErrInvalid
		}
		want[b.RootID] = b
	}
	for _, r := range receipts {
		b, ok := want[r.RootID]
		if !ok || r.Validate() != nil || b.ParentScheduleID != r.ParentScheduleID || b.TargetOrganizationID != r.TargetOrganizationID || b.Version != r.Version || b.RowVersion != r.RowVersion || !b.Start.Equal(r.Start) || !b.End.Equal(r.End) || !sameID(b.AddUserID, r.AddUserID) || !sameID(b.RemoveUserID, r.RemoveUserID) {
			return ErrInvalid
		}
		delete(want, r.RootID)
	}
	if len(want) != 0 {
		return ErrInvalid
	}
	return nil
}

func sameID(a, b *uuid.UUID) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
