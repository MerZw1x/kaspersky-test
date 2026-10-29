package service

import (
	"fmt"
	"slices"

	"backend/internal/domain"
	errs "backend/internal/errors"
)

func prepareEnums(input *domain.ThreatInput) error {
	if err := defaultEnum(&input.Type, domain.ThreatTypeUnknown, "type",
		domain.ThreatTypeTrojan, domain.ThreatTypeVirus, domain.ThreatTypeWorm, domain.ThreatTypeRansomware,
		domain.ThreatTypeBackdoor, domain.ThreatTypeSpyware, domain.ThreatTypeAdware, domain.ThreatTypeRiskware,
		domain.ThreatTypeExploit, domain.ThreatTypeUnknown); err != nil {
		return err
	}

	if err := defaultEnum(&input.Platform, domain.PlatformUnknown, "platform",
		domain.PlatformWindows, domain.PlatformLinux, domain.PlatformMacOS, domain.PlatformAndroid,
		domain.PlatformIOS, domain.PlatformMulti, domain.PlatformUnknown); err != nil {
		return err
	}

	if err := defaultEnum(&input.Severity, domain.SeverityUnknown, "severity",
		domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical, domain.SeverityUnknown); err != nil {
		return err
	}

	return defaultEnum(&input.Status, domain.ThreatStatusActive, "status",
		domain.ThreatStatusActive, domain.ThreatStatusFalsePositive, domain.ThreatStatusRevoked)
}

func defaultEnum[T ~string](value *T, fallback T, field string, allowed ...T) error {
	if *value == "" {
		*value = fallback
	}

	if !slices.Contains(allowed, *value) {
		return errs.NewValidationError(fmt.Sprintf("invalid %s: %q", field, *value))
	}

	return nil
}
