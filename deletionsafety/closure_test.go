package deletionsafety

import "testing"

func TestClosedAlertRuntimeClosureKeepsEveryActualRelationship(t *testing.T) {
	service, alert := obj(ResourceService, "service"), obj(ResourceAlert, "123")
	message, cycle := obj(ResourceOutgoingMessage, "message"), obj(ResourceNotificationPolicyCycle, "cycle")
	signal := obj(ResourcePendingSignal, "signal")
	root := dep(service, alert, RelationshipServiceAlert, Resource{}, Resource{})
	root.State.Alert = AlertClosed
	edges := []Dependency{
		root,
		dep(alert, obj(ResourceAlertData, "data"), RelationshipAlertData, Resource{}, Resource{}),
		dep(alert, obj(ResourceAlertFeedback, "feedback"), RelationshipAlertFeedback, Resource{}, Resource{}),
		dep(alert, obj(ResourceAlertMetrics, "metrics"), RelationshipAlertMetrics, Resource{}, Resource{}),
		dep(alert, obj(ResourceAlertStatusSubscription, "subscription"), RelationshipAlertSubscription, Resource{}, Resource{}),
		dep(alert, cycle, RelationshipAlertCycle, Resource{}, Resource{}),
		dep(alert, message, RelationshipOutgoingMessage, Resource{}, Resource{}),
		dep(service, message, RelationshipOutgoingMessage, Resource{}, Resource{}),
		dep(cycle, message, RelationshipOutgoingMessage, Resource{}, Resource{}),
		dep(message, signal, RelationshipPendingSignal, Resource{}, Resource{}),
		dep(service, signal, RelationshipPendingSignal, Resource{}, Resource{}),
		dep(message, obj(ResourceMessageStatusHistory, "message-state"), RelationshipMessageStatus, Resource{}, Resource{}),
		dep(alert, obj(ResourceAlertLog, "log"), RelationshipAlertLog, Resource{}, Resource{}),
	}
	p := mustPlan(t, inputFor([]Resource{service}, edges...))
	if !p.CanProceed() || !p.RequiresConfirmation() || len(p.Targets()) != 1 {
		t.Fatal("closed service data must be confirmable without expanding explicit targets")
	}
	if len(findChange(t, p, message).Edges) != 3 || len(findChange(t, p, signal).Edges) != 2 {
		t.Fatal("same runtime object may have several actual FK relationships")
	}
	assertPreserved(t, p, obj(ResourceAlertLog, "log"))
	root.State.Alert = AlertActive
	edges[0] = root
	p = mustPlan(t, inputFor([]Resource{service}, edges...))
	if p.CanProceed() {
		t.Fatal("open alert cannot be swallowed by service ownership")
	}
	requireCode(t, p.Check(p.ImpactVersion(), true), DeletionBlocked)
}

func TestFavoriteOwnerAndTargetAreDifferentRelationships(t *testing.T) {
	user, favorite := obj(ResourceUser, "user"), obj(ResourceFavorite, "favorite")
	edges := []Dependency{
		dep(user, favorite, RelationshipFavorite, Resource{}, Resource{}),
		dep(user, favorite, RelationshipFavoriteOwner, Resource{}, Resource{}),
	}
	p := mustPlan(t, inputFor([]Resource{user}, edges...))
	if !p.CanProceed() || p.RequiresConfirmation() || len(findChange(t, p, favorite).Edges) != 2 {
		t.Fatal("owner and target relationships must not collapse into one edge")
	}
}

func TestExecutionStateProtectionSurvivesAnotherCascadePath(t *testing.T) {
	service, policy := obj(ResourceService, "service"), obj(ResourceEscalationPolicy, "policy")
	state := obj(ResourceEscalationPolicyState, "state")
	protected := dep(policy, state, RelationshipExecutionState, Resource{}, Resource{})
	protected.State.Alert = AlertActive
	edges := []Dependency{
		dep(service, state, RelationshipServiceState, Resource{}, Resource{}),
		dep(policy, service, RelationshipServicePolicy, Resource{}, Resource{}),
		protected,
	}
	p := mustPlan(t, inputFor([]Resource{service, policy}, edges...))
	if p.CanProceed() {
		t.Fatal("state already reached by cascade is no exemption from open-alert protection")
	}
	requireCode(t, p.Check(p.ImpactVersion(), true), DeletionBlocked)
}
