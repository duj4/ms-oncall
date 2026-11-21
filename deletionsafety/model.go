package deletionsafety

import "time"

// PolicyVersion changes whenever the frozen policy or its interpretation changes.
const PolicyVersion = "deletion-safety-spec1-v2"

type ResourceKind uint8

const (
	ResourceUnknown ResourceKind = iota
	ResourceService
	ResourceEscalationPolicy
	ResourceEscalationPolicyStep
	ResourceEscalationPolicyAction
	ResourceSchedule
	ResourceScheduleRule
	ResourceRotation
	ResourceRotationParticipant
	ResourceContactMethod
	ResourceNotificationRule
	ResourceIntegrationKey
	ResourceUserOverride
	ResourceUser
	ResourceAlert
	ResourceOutgoingMessage
	ResourcePendingSignal
	ResourceNotificationPolicyCycle
	ResourceEscalationPolicyState
	ResourceTemporarySchedule
	ResourceFixedShift
	ResourceOnCallNotificationRule
	ResourceScheduleHistory
	ResourceEscalationHistory
	ResourceAlertStatusSubscription
	ResourceFavorite
	ResourceRotationState
	ResourceAuthSubject
	ResourceUserSession
	ResourceBasicAuthLink
	ResourceVerificationState
	ResourceOrganizationAssignment
	ResourceLegacyKeyAttribution
	ResourceCalendarSubscription
	ResourceAlertData
	ResourceAlertFeedback
	ResourceAlertMetrics
	ResourceAlertLog
	ResourceMessageStatusHistory
	ResourceNotificationChannel
	ResourceScheduleTarget
	resourceKindEnd
)

// Resource intentionally has no labels, destinations, subjects, or payloads.
// ID supports UUIDs, numeric PKs, and safe composite/JSON-fragment identities.
type Resource struct {
	Kind ResourceKind
	ID   string
}

type RelationshipKind uint8

const (
	RelationshipUnknown RelationshipKind = iota
	RelationshipServicePolicy
	RelationshipPolicyStep
	RelationshipPolicyAction
	RelationshipStepAction
	RelationshipStepRouting
	RelationshipExecutionState
	RelationshipActionTarget
	RelationshipScheduleRule
	RelationshipRuleTarget
	RelationshipScheduleOverride
	RelationshipOverrideAddUser
	RelationshipOverrideRemoveUser
	RelationshipScheduleTemporary
	RelationshipScheduleShift
	RelationshipTemporaryShift
	RelationshipShiftUser
	RelationshipScheduleOnCallRule
	RelationshipScheduleHistory
	RelationshipEscalationHistory
	RelationshipRotationParticipant
	RelationshipParticipantUser
	RelationshipRotationState
	RelationshipServiceAlert
	RelationshipServiceIntegrationKey
	RelationshipOutgoingMessage
	RelationshipPendingSignal
	RelationshipRetainedPolicy
	RelationshipContactNotificationRule
	RelationshipStatusContact
	RelationshipContactSubscription
	RelationshipImmediateRoute
	RelationshipContactAuthSubject
	RelationshipVerification
	RelationshipNotificationConfiguration
	RelationshipRetainedContact
	RelationshipIntegrationSource
	RelationshipIntegrationLog
	RelationshipOverrideCoverage
	RelationshipUserContact
	RelationshipUserNotificationRule
	RelationshipUserCycle
	RelationshipFavorite
	RelationshipUserOrganization
	RelationshipUserIdentity
	RelationshipKeyCreator
	RelationshipKeyUpdater
	RelationshipKeyDeleter
	RelationshipRemovedAction
	RelationshipRemovedRule
	RelationshipRemovedParticipant
	RelationshipChangedTemporary
	RelationshipRemovedOnCallRule
	RelationshipChangedServicePolicy
	RelationshipServiceState
	RelationshipAlertData
	RelationshipAlertFeedback
	RelationshipAlertMetrics
	RelationshipAlertSubscription
	RelationshipAlertCycle
	RelationshipAlertState
	RelationshipAlertLog
	RelationshipMessageStatus
	RelationshipCalendar
	RelationshipUserLog
	RelationshipRetainedChannel
	RelationshipFavoriteOwner
	relationshipKindEnd
)

type DeletionPolicy uint8

const (
	PolicyUnknown DeletionPolicy = iota
	PolicyWarning
	PolicyBlock
	PolicyCascade
	PolicyInformational
)

type DeletionChangeKind uint8

const (
	ChangeUnknown DeletionChangeKind = iota
	ChangeDeleted
	ChangeRelationRemoved
	ChangeRelationReplaced
	ChangeConfigTrimmed
	ChangePreserved
)

type Operation uint8

const (
	OperationUnknown Operation = iota
	OperationDeleteResources
	OperationUpdateEscalationPolicy
	OperationUpdateEscalationPolicyStep
	OperationUpdateScheduleTarget
	OperationUpdateRotation
	OperationUpdateService
	OperationSetTemporarySchedule
	OperationClearTemporarySchedules
	OperationSetOnCallNotificationRules
)

type DependencyCompleteness uint8

const (
	DependenciesUnknown DependencyCompleteness = iota
	DependenciesComplete
	DependenciesIncomplete
	DependenciesUnsupported
)

type AlertState uint8

const (
	AlertUnknown AlertState = iota
	AlertTriggered
	AlertActive // Acknowledged alerts remain open.
	AlertClosed
)

type PeriodState uint8

const (
	PeriodUnknown PeriodState = iota
	PeriodActive
	PeriodFuture
	PeriodEnded
)

type NotificationRisk uint8

const (
	NotificationRiskUnknown NotificationRisk = iota
	NotificationRiskNone
	NotificationRiskLastImmediateRoute
	NotificationRiskOpenCycle
	NotificationRiskBoth
)

// BusinessState contains only relevant server-observed classifications.
// SameOwner must be proven for a ContactMethod -> NotificationRule edge.
type BusinessState struct {
	Alert            AlertState
	Period           PeriodState
	NotificationRisk NotificationRisk
	SameOwner        bool
}

// Configuration contains only deletion-relevant before/after facts. References
// are a set; ordered roster semantics use Position on each actual row identity.
// WindowStart/End are business intervals, never collection/preview timestamps.
type Configuration struct {
	References             []Resource
	Position               *int
	WindowStart, WindowEnd time.Time
	RotationState          *RotationRuntime `json:",omitempty"`
}

// RotationRuntime is the safe runtime projection of a Rotation-owned State.
// Its row identity, current Participant and position live on the same dependency.
// It is not an interval, a collection timestamp, or an additional audit event.
type RotationRuntime struct {
	ShiftStart time.Time
	Version    int
}

type DestructiveChange struct {
	Resource      Resource
	Kind          DeletionChangeKind
	Before, After Configuration
}

// Dependency identifies one actual relationship, including its row/fragment
// (Referencing), immediate Parent and business-root Owner where applicable.
// Two override endpoints or two Action rows are distinct edges even when they
// involve the same user. Policy is deliberately absent from collector input.
type Dependency struct {
	Target, Referencing Resource
	Parent, Owner       Resource
	Relationship        RelationshipKind
	State               BusinessState
	Before, After       Configuration
}

// Collection asserts complete coverage of every checked object's incoming AND
// retained outgoing relationships, including owned children and runtime data.
// Every object actually removed by the planner must be in Checked. A global
// Complete flag without per-object coverage is insufficient.
type Collection struct {
	Completeness DependencyCompleteness
	Checked      []Resource
	Dependencies []Dependency
}

type RequiredAction uint8

const (
	ActionNone RequiredAction = iota
	ActionDetachReference
	ActionCloseAlert
	ActionConfirmImpact
)

type Decision struct {
	Policy               DeletionPolicy
	Change               DeletionChangeKind
	Affected             Resource
	RequiredAction       RequiredAction
	RequiresConfirmation bool
	CanProceed           bool // Policy permission; confirmation is a separate gate.
}

// EvaluationInput is a trusted domain projection, never a wire request.
// CoDeletion means the referencing row or a verified owning ancestor belongs to
// the complete explicit plan. It never exempts open-alert protection.
type EvaluationInput struct {
	Dependency Dependency
	CoDeletion bool
}

type ChangeCause uint8

const (
	CauseExplicit ChangeCause = iota + 1
	CauseCascade
)

type DeletionImpact struct {
	EdgeID string
	Dependency
	Decision
	IsDerived           bool
	IsPlannedCoDeletion bool
	// DerivedFrom is the direct edge; derived rows never remove resources.
	DerivedFrom string
}

// PlannedChange coalesces actual objects without losing individual impact edges.
// Explicit selection takes precedence over cascade provenance for that object.
type PlannedChange struct {
	DestructiveChange
	Cause ChangeCause
	Edges []string
}

type PlanInput struct {
	Operation Operation
	// ScopeFingerprint is a lowercase SHA-256 of the trusted organization/actor
	// authorization boundary, not client-selected organization or credentials.
	ScopeFingerprint string
	Targets          []Resource
	Intent           []DestructiveChange
	Collection       Collection
}

// Budget bounds raw inputs BEFORE deduplication. MaxImpacts bounds each of the
// materialized impact, change and removal-closure collections, including roots.
// Zero Budget selects defaults. Callers must also apply their mutation family's
// existing raw input/UUID/missing-object validation before calling this package.
type Budget struct {
	MaxTargets, MaxDependencies, MaxImpacts int
}

func DefaultBudget() Budget {
	return Budget{MaxTargets: 100, MaxDependencies: 10000, MaxImpacts: 30000}
}
