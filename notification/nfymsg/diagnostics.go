package nfymsg

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/target/goalert/retry"
	"github.com/target/goalert/validation"
)

var safeDiagnosticCode = regexp.MustCompile(`^(webhook request failed: HTTP status [1-5][0-9]{2}|Twilio error code [0-9]{1,6}|(queued|sending|sent|delivered|read|failed|undelivered|initiated|ringing|in-progress|completed|busy|no-answer|canceled): \[[0-9]{1,6}\])$`)

// DiagnosticText accepts only Core-defined diagnostic classes. Provider text
// can quote a formatted, encoded, partial or unrelated destination, so removing
// a single known destination string is insufficient (notably for callbacks).
func DiagnosticText(text string) string {
	switch text {
	case "", "queued", "sending", "sent", "delivered", "read", "failed", "undelivered", "initiated", "ringing", "in-progress", "completed", "busy", "no-answer", "canceled",
		"invalid or not allowed URL", "destination address is not allowed by administrator",
		"invalid destination", "invalid phone number", "does not exist", "unknown field ID", "unsupported field ID",
		"scheme is required for URL", "host is required for URL", "url is not allowed by administator",
		"User not found.", "user group not found", "invalid user group id", "Channel is required.", "Channel is archived.",
		"Channel does not exist, is archived, or is private (invite goalert bot).", "Permission Denied.",
		"alerts acked/closed before message sent", "provider operation failed", "provider details withheld",
		"No escalation policy steps", "missing users, sent error to channel", "empty user-group, sent error to channel", "failed to update user-group, sent error to channel and log",
		"unsupported operation", "destination type is not enabled", "unknown destination type",
		"gateway signing failed: gateway signing unavailable", "gateway signing failed: gateway signing configuration is invalid",
		"gateway message type is not supported", "webhook delivery identity is required", "webhook request could not be created", "webhook alert state is invalid",
		"webhook request failed", "webhook request failed: context canceled", "webhook request failed: context deadline exceeded":
		return text
	}
	if safeDiagnosticCode.MatchString(text) {
		return text
	}
	return "provider details withheld"
}

// ProviderError preserves control-flow classifications without retaining an
// untrusted error in its unwrap chain or formatted representation.
func ProviderError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("provider operation failed: %w", context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("provider operation failed: %w", context.DeadlineExceeded)
	}
	reason := err.Error()
	var fieldErr validation.FieldError
	if errors.As(err, &fieldErr) {
		reason = fieldErr.Reason()
	}
	text := DiagnosticText(reason)
	if text == "provider details withheld" {
		text = "provider operation failed"
		if validation.IsClientError(err) {
			text = "invalid destination"
		}
	}
	safe := errors.New(text)
	if validation.IsClientError(err) {
		return validation.WrapError(safe)
	}
	if retry.IsTemporaryError(err) {
		return retry.TemporaryError(safe)
	}
	return safe
}
