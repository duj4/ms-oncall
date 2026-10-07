package twilio

import "fmt"

// Exception contains information on a Twilio error.
type Exception struct {
	Status   int
	Message  string
	Code     int
	MoreInfo string `json:"more_info"`
}

func (e Exception) Error() string {
	return fmt.Sprintf("Twilio error code %d", e.Code)
}

func (e Exception) Format(state fmt.State, _ rune) { _, _ = fmt.Fprint(state, e.Error()) }
