package v1

import (
	"context"

	"backend/internal/api"
	"backend/internal/domain"
	errs "backend/internal/errors"
)

var _ api.StrictServerInterface = (*ThreatHandler)(nil)

type ThreatService interface {
	Create(context.Context, string, domain.ThreatInput) (domain.Threat, error)
	GetByMD5(context.Context, string) (domain.Threat, error)
	Update(context.Context, string, domain.ThreatInput) (domain.Threat, error)
}

type ThreatHandler struct{ service ThreatService }

func NewThreatHandler(service ThreatService) *ThreatHandler { return &ThreatHandler{service: service} }

func (h *ThreatHandler) CreateThreat(ctx context.Context, request api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	if request.Body == nil {
		return nil, errs.NewValidationError("request body is required")
	}

	threat, err := h.service.Create(ctx, request.Body.Md5, createInput(*request.Body))
	if err != nil {
		return nil, err
	}

	return api.CreateThreat201JSONResponse(threatResponse(threat)), nil
}

func (h *ThreatHandler) GetInfoByMd5(ctx context.Context, request api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	threat, err := h.service.GetByMD5(ctx, request.Md5)
	if err != nil {
		return nil, err
	}

	return api.GetInfoByMd5200JSONResponse(threatResponse(threat)), nil
}

func (h *ThreatHandler) UpdateThreat(ctx context.Context, request api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	if request.Body == nil {
		return nil, errs.NewValidationError("request body is required")
	}

	threat, err := h.service.Update(ctx, request.Md5, updateInput(*request.Body))
	if err != nil {
		return nil, err
	}

	return api.UpdateThreat200JSONResponse(threatResponse(threat)), nil
}
