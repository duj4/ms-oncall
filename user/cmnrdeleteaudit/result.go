package cmnrdeleteaudit

import "github.com/google/uuid"

// Target contains locked, verified identities only. Captured and actually
// deleted targets are deliberately distinct; a suppressing trigger must not
// produce a success witness. No destination/authentication object is retained.
type Target struct {
	ID, OwnerID, ParentCMID, OrganizationID uuid.UUID
	OrgResolution                           string
	Deleted                                 bool
	Effects                                 []Effect
}

type DeleteResult struct {
	Targets      []Target
	CascadeRules []Target
}
