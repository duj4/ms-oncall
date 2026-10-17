package config

// CalendarSubscriptionsDisabled is the current MS OnCall product policy.
// Calendar subscriptions are outside product scope and cannot be enabled by
// stored configuration, imports, or startup configuration. Retained upstream
// Calendar code is not an Organization-isolation boundary.
func CalendarSubscriptionsDisabled() bool { return true }

// LabelsDisabled is the immutable MS OnCall product policy for every Label
// target. Configuration and caller privileges cannot enable dormant Labels.
func LabelsDisabled() bool { return true }

func (cfg Config) withProductPolicy() Config {
	cfg.General.DisableCalendarSubscriptions = CalendarSubscriptionsDisabled()
	if LabelsDisabled() {
		cfg.General.DisableLabelCreation = true
		cfg.Services.RequiredLabels = nil
	}
	return cfg
}
