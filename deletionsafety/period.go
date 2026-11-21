package deletionsafety

import "time"

// ClassifyPeriod uses one caller-supplied observation time. Business intervals
// are [start,end): start is active, end is historical. No wall clock is read or
// included in the impact version; the observed classification and interval are.
func ClassifyPeriod(start, end, asOf time.Time) (PeriodState, error) {
	if asOf.IsZero() || start.IsZero() || !validConfiguration(Configuration{WindowStart: start, WindowEnd: end}) {
		return PeriodUnknown, unavailable()
	}
	if asOf.Before(start) {
		return PeriodFuture, nil
	}
	if asOf.Before(end) {
		return PeriodActive, nil
	}
	return PeriodEnded, nil
}
