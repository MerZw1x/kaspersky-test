package v1

import (
	"backend/internal/api"
	"backend/internal/domain"
)

func createInput(request api.ThreatCreateRequest) domain.ThreatInput {
	return updateInput(api.ThreatUpdateRequest{
		Name: request.Name, Type: request.Type, Platform: request.Platform, Severity: request.Severity, Status: request.Status,
		Sha256: request.Sha256, FileSize: request.FileSize, Description: request.Description, Tags: request.Tags,
		FirstSeen: request.FirstSeen, LastSeen: request.LastSeen,
	})
}

func updateInput(request api.ThreatUpdateRequest) domain.ThreatInput {
	return domain.ThreatInput{
		Name: request.Name, Type: domain.ThreatType(value(request.Type)), Platform: domain.Platform(value(request.Platform)),
		Severity: domain.Severity(value(request.Severity)), Status: domain.ThreatStatus(value(request.Status)),
		SHA256: request.Sha256, FileSize: request.FileSize, Description: request.Description, Tags: value(request.Tags),
		FirstSeen: request.FirstSeen, LastSeen: request.LastSeen,
	}
}

func threatResponse(threat domain.Threat) api.ThreatResponse {
	// Даже если репозиторий вернул nil, контракт требует массив [], а не null.
	tags := append([]string{}, threat.Tags...)

	return api.ThreatResponse{
		Md5: threat.MD5, Name: threat.Name, Type: api.ThreatType(threat.Type), Platform: api.Platform(threat.Platform),
		Severity: api.Severity(threat.Severity), Status: api.ThreatStatus(threat.Status),
		Sha256: threat.SHA256, FileSize: threat.FileSize, Description: threat.Description, Tags: tags,
		FirstSeen: threat.FirstSeen, LastSeen: threat.LastSeen, CreatedAt: threat.CreatedAt, UpdatedAt: threat.UpdatedAt,
	}
}

func value[T any](pointer *T) T {
	if pointer != nil {
		return *pointer
	}

	var zero T

	return zero
}
