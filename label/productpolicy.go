package label

import "github.com/target/goalert/validation"

// ErrDisabled is the public error for unsupported Label operations. Retained
// upstream schema and data do not enable current-product Label functionality.
var ErrDisabled = validation.NewGenericError("labels are disabled")
