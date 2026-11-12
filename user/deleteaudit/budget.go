package deleteaudit

// Budget counts simultaneous safe row versions and retained JSON, including
// reservations made before allocation. Totals over released pages are unlimited.
type Budget struct {
	Units, Bytes         int
	HighUnits, HighBytes int
}

func (b *Budget) Reserve(units, bytes int) error {
	if units < 0 || bytes < 0 || units > MaxCaptureUnits-b.Units || bytes > MaxActiveJSONBytes-b.Bytes {
		return ErrCapacity
	}
	b.Units += units
	b.Bytes += bytes
	b.HighUnits = max(b.HighUnits, b.Units)
	b.HighBytes = max(b.HighBytes, b.Bytes)
	return nil
}
func (b *Budget) Release(units, bytes int) error {
	if units < 0 || bytes < 0 || units > b.Units || bytes > b.Bytes {
		return ErrInvalid
	}
	b.Units -= units
	b.Bytes -= bytes
	return nil
}
