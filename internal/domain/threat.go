package domain

import "time"

type ThreatType string

const (
	ThreatTypeTrojan     ThreatType = "trojan"
	ThreatTypeVirus      ThreatType = "virus"
	ThreatTypeWorm       ThreatType = "worm"
	ThreatTypeRansomware ThreatType = "ransomware"
	ThreatTypeBackdoor   ThreatType = "backdoor"
	ThreatTypeSpyware    ThreatType = "spyware"
	ThreatTypeAdware     ThreatType = "adware"
	ThreatTypeRiskware   ThreatType = "riskware"
	ThreatTypeExploit    ThreatType = "exploit"
	ThreatTypeUnknown    ThreatType = "unknown"
)

type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformMulti   Platform = "multi"
	PlatformUnknown Platform = "unknown"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

type ThreatStatus string

const (
	ThreatStatusActive        ThreatStatus = "active"
	ThreatStatusFalsePositive ThreatStatus = "false_positive"
	ThreatStatusRevoked       ThreatStatus = "revoked"
)

type Threat struct {
	MD5         string
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
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
