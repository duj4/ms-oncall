package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/target/goalert/config"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/validation"
)

// destinationDisplayInfo applies GraphQL request organization scope to root
// resources represented as destinations. Other destination types continue to
// use the shared registry unchanged.
func (a *App) destinationDisplayInfo(ctx context.Context, dest gadb.DestV1) (*nfydest.DisplayInfo, error) {
	switch dest.Type {
	case schedule.DestTypeSchedule:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return nil, err
		}
		sched, err := a.ScheduleStore.FindOne(ctx, dest.Args[schedule.FieldScheduleID], organizationID)
		if err != nil {
			return nil, err
		}
		cfg := config.FromContext(ctx)
		return &nfydest.DisplayInfo{
			IconURL:     schedule.FallbackIconURL,
			IconAltText: "Schedule",
			LinkURL:     cfg.CallbackURL("/schedules/" + sched.ID),
			Text:        sched.Name,
		}, nil
	case rotation.DestTypeRotation:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return nil, err
		}
		rot, err := a.RotationStore.FindRotation(ctx, dest.Args[rotation.FieldRotationID], organizationID)
		if err != nil {
			return nil, err
		}
		cfg := config.FromContext(ctx)
		return &nfydest.DisplayInfo{
			IconURL:     rotation.FallbackIconURL,
			IconAltText: "Rotation",
			LinkURL:     cfg.CallbackURL("/rotations/" + rot.ID),
			Text:        rot.Name,
		}, nil
	default:
		return a.DestReg.DisplayInfo(ctx, dest)
	}
}

func (a *App) destinationValidateField(ctx context.Context, typeID, fieldID, value string) error {
	switch typeID {
	case schedule.DestTypeSchedule:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return err
		}
		if fieldID != schedule.FieldScheduleID {
			return validation.NewGenericError("unknown field ID")
		}
		_, err = a.ScheduleStore.FindOne(ctx, value, organizationID)
		return err
	case rotation.DestTypeRotation:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return err
		}
		if fieldID != rotation.FieldRotationID {
			return validation.NewGenericError("unknown field ID")
		}
		_, err = a.RotationStore.FindRotation(ctx, value, organizationID)
		return err
	default:
		return a.DestReg.ValidateField(ctx, typeID, fieldID, value)
	}
}

func (a *App) destinationFieldLabel(ctx context.Context, typeID, fieldID, value string) (string, error) {
	switch typeID {
	case schedule.DestTypeSchedule:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return "", err
		}
		if fieldID != schedule.FieldScheduleID {
			return "", validation.NewGenericError("unknown field ID")
		}
		sched, err := a.ScheduleStore.FindOne(ctx, value, organizationID)
		if err != nil {
			return "", err
		}
		return sched.Name, nil
	case rotation.DestTypeRotation:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return "", err
		}
		if fieldID != rotation.FieldRotationID {
			return "", validation.NewGenericError("unknown field ID")
		}
		rot, err := a.RotationStore.FindRotation(ctx, value, organizationID)
		if err != nil {
			return "", err
		}
		return rot.Name, nil
	default:
		return a.DestReg.FieldLabel(ctx, typeID, fieldID, value)
	}
}

func (a *App) destinationSearchField(ctx context.Context, typeID, fieldID string, options nfydest.SearchOptions) (*nfydest.SearchResult, error) {
	switch typeID {
	case schedule.DestTypeSchedule:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return nil, err
		}
		if fieldID != schedule.FieldScheduleID {
			return nil, validation.NewGenericError("unknown field ID")
		}
		return nfydest.SearchByCursorFunc(ctx, options, func(ctx context.Context, opts *schedule.SearchOptions) ([]schedule.Schedule, error) {
			if organizationID != nil {
				opts.OrganizationID = *organizationID
			}
			return a.ScheduleStore.Search(ctx, opts)
		})
	case rotation.DestTypeRotation:
		organizationID, err := rootStoreOrganizationID(ctx)
		if err != nil {
			return nil, err
		}
		if fieldID != rotation.FieldRotationID {
			return nil, validation.NewGenericError("unknown field ID")
		}
		return nfydest.SearchByCursorFunc(ctx, options, func(ctx context.Context, opts *rotation.SearchOptions) ([]rotation.Rotation, error) {
			if organizationID != nil {
				opts.OrganizationID = *organizationID
			}
			return a.RotationStore.Search(ctx, opts)
		})
	default:
		return a.DestReg.SearchField(ctx, typeID, fieldID, options)
	}
}

func (a *App) validateDestination(ctx context.Context, dest gadb.DestV1) error {
	if dest.Type != schedule.DestTypeSchedule && dest.Type != rotation.DestTypeRotation {
		return a.DestReg.ValidateDest(ctx, dest)
	}

	info, err := a.DestReg.TypeInfo(ctx, dest.Type)
	if err != nil {
		return err
	}
	if !info.Enabled {
		return nfydest.ErrNotEnabled
	}
	if dest.Args == nil {
		dest.Args = make(map[string]string)
	}

	fieldNames := make([]string, 0, len(info.RequiredFields))
	for _, field := range info.RequiredFields {
		fieldNames = append(fieldNames, field.FieldID)
	}
	for fieldID := range dest.Args {
		if !slices.Contains(fieldNames, fieldID) {
			return &nfydest.DestArgError{FieldID: fieldID, Err: fmt.Errorf("unexpected field")}
		}
	}
	for _, field := range info.RequiredFields {
		err := a.destinationValidateField(ctx, dest.Type, field.FieldID, dest.Args[field.FieldID])
		if errors.Is(err, sql.ErrNoRows) {
			err = validation.NewGenericError("does not exist")
		}
		if validation.IsClientError(err) {
			return &nfydest.DestArgError{FieldID: field.FieldID, Err: err}
		}
		if err != nil {
			return fmt.Errorf("validate field %s: %w", field.FieldID, err)
		}
	}

	return nil
}
