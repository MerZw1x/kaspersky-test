package v1

import (
	"context"
	"errors"

	"backend/internal/api"
)

var _ api.StrictServerInterface = (*TreatHandler)(nil)

type TreatHandler struct {
}

func NewTreatHandler() *TreatHandler {
	return &TreatHandler{}
}

func (th *TreatHandler) CreateThreat(_ context.Context, _ api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	return nil, errors.New("not implemented")
}

func (th *TreatHandler) GetInfoByMd5(_ context.Context, _ api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	return nil, errors.New("not implemented")
}

func (th *TreatHandler) UpdateThreat(_ context.Context, _ api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	return nil, errors.New("not implemented")
}
