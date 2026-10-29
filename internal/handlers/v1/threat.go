package v1

import (
	"backend/internal/api"
	"context"
	"errors"
)

var _ api.StrictServerInterface = (*TreatHandler)(nil)

type TreatHandler struct {
}

func NewTreatHandler() *TreatHandler {
	return &TreatHandler{}
}

func (th *TreatHandler) CreateThreat(ctx context.Context, request api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	return nil, errors.New("not implemented")
}

func (th *TreatHandler) GetInfoByMd5(ctx context.Context, request api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	return nil, errors.New("not implemented")
}

func (th *TreatHandler) UpdateThreat(ctx context.Context, request api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	return nil, errors.New("not implemented")
}
