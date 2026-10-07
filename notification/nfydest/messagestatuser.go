package nfydest

import (
	"context"

	"github.com/target/goalert/notification/nfymsg"
)

// A MessageStatuser is an optional interface a Sender can implement that allows checking the status
// of a previously sent message by it's externalID.
type MessageStatuser interface {
	MessageStatus(ctx context.Context, externalID string) (*nfymsg.Status, error)
}

func (r *Registry) MessageStatus(ctx context.Context, destType string, externalID string) (*nfymsg.Status, error) {
	p := r.Provider(destType)
	if p == nil {
		return nil, ErrUnknownType
	}

	s, ok := p.(MessageStatuser)
	if !ok {
		return nil, ErrUnsupported
	}

	info, err := p.TypeInfo(ctx)
	if err != nil {
		return nil, err
	}

	if !info.Enabled {
		return nil, ErrNotEnabled
	}

	status, err := s.MessageStatus(ctx, externalID)
	if err != nil {
		return nil, providerError(err)
	}
	if status != nil {
		copyStatus := *status
		copyStatus.Details = nfymsg.DiagnosticText(status.Details)
		status = &copyStatus
	}
	return status, nil
}
