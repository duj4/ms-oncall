package nfydest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/target/goalert/gadb"
	"github.com/target/goalert/notification/nfymsg"
	"github.com/target/goalert/validation"
)

var (
	ErrUnknownType = validation.NewGenericError("unknown destination type")
	ErrUnsupported = errors.New("unsupported operation")
	ErrNotEnabled  = validation.NewGenericError("destination type is not enabled")
)

func providerError(err error) error {
	// Preserve Registry capability sentinels without retaining provider text.
	for _, sentinel := range []error{ErrUnknownType, ErrUnsupported, ErrNotEnabled, sql.ErrNoRows} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return nfymsg.ProviderError(err)
}

func contactProviderError(ctx context.Context, p Provider, err error) error {
	if err == nil {
		return nil
	}
	info, infoErr := p.TypeInfo(ctx)
	if infoErr == nil && !info.IsContactMethod() {
		// Root-resource/signal validation and display diagnostics are outside
		// Contact Method privacy. Preserve their established error contracts.
		return err
	}
	return providerError(err)
}

type Registry struct {
	providers map[string]Provider
	ids       []string

	stubSender bool
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// StubNotifiers will cause all notifications senders to be stubbed out.
//
// This causes all notifications to be marked as delivered, but not actually sent.
func (r *Registry) StubNotifiers() {
	r.stubSender = true
}

func (r *Registry) Provider(id string) Provider { return r.providers[id] }

func (r *Registry) TypeInfo(ctx context.Context, typeID string) (*TypeInfo, error) {
	p := r.Provider(typeID)
	if p == nil {
		return nil, ErrUnknownType
	}

	return p.TypeInfo(ctx)
}

func (r *Registry) IsDynamicAction(ctx context.Context, typeID string) (bool, error) {
	info, err := r.TypeInfo(ctx, typeID)
	if err != nil {
		return false, err
	}

	return info.IsDynamicAction(), nil
}

func (r *Registry) LookupTypeName(ctx context.Context, typeID string) (string, error) {
	info, err := r.TypeInfo(ctx, typeID)
	if err != nil {
		return "", err
	}

	return info.Name, nil
}

func (r *Registry) RegisterProvider(ctx context.Context, p Provider) {
	if r.Provider(p.ID()) != nil {
		panic(fmt.Sprintf("provider with ID %s already registered", p.ID()))
	}

	id := p.ID()
	r.providers[id] = p
	r.ids = append(r.ids, id)
}

func (r *Registry) DisplayInfo(ctx context.Context, d gadb.DestV1) (*DisplayInfo, error) {
	p := r.Provider(d.Type)
	if p == nil {
		return nil, ErrUnknownType
	}

	info, err := p.DisplayInfo(ctx, d.Args)
	return info, contactProviderError(ctx, p, err)
}

func (r *Registry) ValidateField(ctx context.Context, typeID, fieldID, value string) error {
	p := r.Provider(typeID)
	if p == nil {
		return ErrUnknownType
	}

	return contactProviderError(ctx, p, p.ValidateField(ctx, fieldID, value))
}

func (r *Registry) Types(ctx context.Context) ([]TypeInfo, error) {
	var out []TypeInfo
	for _, id := range r.ids {
		ti, err := r.providers[id].TypeInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("get type info for %s: %w", id, err)
		}
		ti.Type = id // ensure ID is set

		out = append(out, *ti)
	}

	return out, nil
}

func (r *Registry) SearchField(ctx context.Context, typeID, fieldID string, options SearchOptions) (*SearchResult, error) {
	p := r.Provider(typeID)
	if p == nil {
		return nil, ErrUnknownType
	}

	s, ok := p.(FieldSearcher)
	if !ok {
		return nil, fmt.Errorf("provider %s does not support field searching: %w", typeID, ErrUnsupported)
	}

	result, err := s.SearchField(ctx, fieldID, options)
	return result, contactProviderError(ctx, p, err)
}

func (r *Registry) FieldLabel(ctx context.Context, typeID, fieldID, value string) (string, error) {
	p := r.Provider(typeID)
	if p == nil {
		return "", ErrUnknownType
	}

	s, ok := p.(FieldSearcher)
	if !ok {
		return "", fmt.Errorf("provider %s does not support field searching: %w", typeID, ErrUnsupported)
	}

	label, err := s.FieldLabel(ctx, fieldID, value)
	return label, contactProviderError(ctx, p, err)
}
