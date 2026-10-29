package domain

import "time"

// ThreatInput задаёт полную замену редактируемых данных, в том числе при PUT.
type ThreatInput struct {
	Name        string
	Type        ThreatType
	Platform    Platform
	Severity    Severity
	Status      ThreatStatus
	SHA256      *string
	FileSize    *int64
	Description *string
	Tags        []string
	FirstSeen   *time.Time
	LastSeen    *time.Time
}
