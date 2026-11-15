package deletionsafety

type ErrorCode string

const (
	DeletionBlocked              ErrorCode = "DELETION_BLOCKED"
	DeletionConfirmationRequired ErrorCode = "DELETION_CONFIRMATION_REQUIRED"
	DeletionDependencyChanged    ErrorCode = "DELETION_DEPENDENCY_CHANGED"
	DeletionUnavailable          ErrorCode = "DELETION_UNAVAILABLE"
	DeletionPreviewLimitExceeded ErrorCode = "DELETION_PREVIEW_LIMIT_EXCEEDED"
)

// DeletionSafetyError carries no raw collector errors, IDs or private data.
// GraphQL presentation and controller retry decisions belong to the caller.
type DeletionSafetyError struct {
	Code ErrorCode
}

func (e *DeletionSafetyError) Error() string {
	switch e.Code {
	case DeletionBlocked:
		return "deletion is blocked by a dependency"
	case DeletionConfirmationRequired:
		return "deletion impact requires confirmation"
	case DeletionDependencyChanged:
		return "deletion dependencies changed; preview again"
	case DeletionPreviewLimitExceeded:
		return "complete deletion preview exceeds the processing budget"
	default:
		return "deletion safety is unavailable"
	}
}

func unavailable() error { return &DeletionSafetyError{Code: DeletionUnavailable} }
