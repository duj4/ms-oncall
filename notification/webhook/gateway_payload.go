package webhook

import (
	"errors"

	"github.com/target/goalert/notification"
)

// Gateway V1 wire types intentionally do not embed upstream webhook payloads.
// New upstream fields cannot enter this contract without an explicit change.
type gatewayV1Test struct {
	AppName string
	Type    string
}

type gatewayV1Verification struct {
	AppName string
	Type    string
	Code    string
}

type gatewayV1Alert struct {
	AppName     string
	Type        string
	AlertID     int
	Summary     string
	Details     string
	ServiceID   string
	ServiceName string
	Meta        map[string]string
}

type gatewayV1AlertStatus struct {
	AppName    string
	Type       string
	AlertID    int
	LogEntry   string
	AlertState string
}

func gatewayV1Payload(appName string, msg notification.Message) (interface{}, error) {
	switch m := msg.(type) {
	case notification.Test:
		return gatewayV1Test{AppName: appName, Type: "Test"}, nil
	case notification.Verification:
		return gatewayV1Verification{AppName: appName, Type: "Verification", Code: m.Code}, nil
	case notification.Alert:
		meta := m.Meta
		if meta == nil {
			// Gateway V1 requires a JSON object, including for absent metadata.
			meta = map[string]string{}
		}
		return gatewayV1Alert{
			AppName: appName, Type: "Alert", AlertID: m.AlertID,
			Summary: m.Summary, Details: m.Details,
			ServiceID: m.ServiceID, ServiceName: m.ServiceName, Meta: meta,
		}, nil
	case notification.AlertStatus:
		state, err := alertStateWireValue(m.NewAlertState)
		if err != nil {
			return nil, err
		}
		return gatewayV1AlertStatus{
			AppName: appName, Type: "AlertStatus", AlertID: m.AlertID,
			LogEntry: m.LogEntry, AlertState: state,
		}, nil
	default:
		return nil, errors.New("gateway message type is not supported")
	}
}
