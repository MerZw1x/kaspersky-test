package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"backend/internal/domain"
	errs "backend/internal/errors"
)

type ThreatRepository interface {
	Create(context.Context, domain.Threat) (domain.Threat, error)
	GetByMD5(context.Context, string) (domain.Threat, error)
	// Update сохраняет исходный CreatedAt и возвращает полную обновлённую запись.
	Update(context.Context, domain.Threat) (domain.Threat, error)
}

type ThreatService struct {
	repo ThreatRepository
	now  func() time.Time
}

func NewThreatService(repo ThreatRepository, now func() time.Time) *ThreatService {
	return &ThreatService{repo: repo, now: now}
}

func (s *ThreatService) Create(ctx context.Context, md5 string, input domain.ThreatInput) (domain.Threat, error) {
	threat, err := s.prepare(md5, input)
	if err != nil {
		return domain.Threat{}, err
	}

	threat.CreatedAt = threat.UpdatedAt

	result, err := s.repo.Create(ctx, threat)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("create threat: %w", err)
	}

	return result, nil
}

func (s *ThreatService) GetByMD5(ctx context.Context, md5 string) (domain.Threat, error) {
	key, err := normalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	result, err := s.repo.GetByMD5(ctx, key)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("get threat: %w", err)
	}

	return result, nil
}

func (s *ThreatService) Update(ctx context.Context, md5 string, input domain.ThreatInput) (domain.Threat, error) {
	threat, err := s.prepare(md5, input)
	if err != nil {
		return domain.Threat{}, err
	}

	result, err := s.repo.Update(ctx, threat)
	if err != nil {
		return domain.Threat{}, fmt.Errorf("update threat: %w", err)
	}

	return result, nil
}

func (s *ThreatService) prepare(md5 string, input domain.ThreatInput) (domain.Threat, error) {
	key, err := normalizeMD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}

	if err := prepareEnums(&input); err != nil {
		return domain.Threat{}, err
	}

	now := s.now().UTC()
	if err := validateDates(input, now); err != nil {
		return domain.Threat{}, err
	}

	// Копируем изменяемые поля: нормализация и репозиторий не должны менять входные данные вызывающего кода.
	threat := domain.Threat{
		MD5: key, Name: input.Name, Type: input.Type, Platform: input.Platform,
		Severity: input.Severity, Status: input.Status,
		SHA256: clone(input.SHA256), FileSize: clone(input.FileSize), Description: clone(input.Description),
		Tags:      append([]string{}, input.Tags...),
		FirstSeen: utcTime(input.FirstSeen), LastSeen: utcTime(input.LastSeen), UpdatedAt: now,
	}
	if threat.SHA256 != nil {
		*threat.SHA256 = strings.ToLower(*threat.SHA256)
	}

	return threat, nil
}

func normalizeMD5(value string) (string, error) {
	const md5Length = 32
	if len(value) != md5Length {
		return "", errs.NewValidationError("md5 must contain 32 hexadecimal characters")
	}

	if _, err := hex.DecodeString(value); err != nil {
		return "", errs.NewValidationError("md5 must contain 32 hexadecimal characters")
	}

	return strings.ToLower(value), nil
}

func validateDates(input domain.ThreatInput, now time.Time) error {
	if input.FirstSeen != nil && input.FirstSeen.After(now) {
		return errs.NewValidationError("first_seen must not be in the future")
	}

	if input.LastSeen != nil && input.LastSeen.After(now) {
		return errs.NewValidationError("last_seen must not be in the future")
	}

	if input.FirstSeen != nil && input.LastSeen != nil && input.LastSeen.Before(*input.FirstSeen) {
		return errs.NewValidationError("last_seen must not precede first_seen")
	}

	return nil
}

func clone[T any](value *T) *T {
	if value == nil {
		return nil
	}

	copyValue := *value

	return &copyValue
}

func utcTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}

	utc := value.UTC()

	return &utc
}
