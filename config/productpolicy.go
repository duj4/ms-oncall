package config

// CalendarSubscriptionsDisabled is the current MS OnCall product policy.
// Calendar subscriptions are outside product scope and cannot be enabled by
// stored configuration, imports, or startup configuration. Retained upstream
// Calendar code is not an Organization-isolation boundary.
func CalendarSubscriptionsDisabled() bool { return true }

func (cfg Config) withProductPolicy() Config {
	cfg.General.DisableCalendarSubscriptions = CalendarSubscriptionsDisabled()
	return cfg
}
