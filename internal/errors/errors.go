package errors

import (
	"errors"
	"fmt"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrValidation    = errors.New("validation error")
)

func NewNotFoundError(msg string) error {
	return fmt.Errorf("%w: %s", ErrNotFound, msg)
}

func NewAlreadyExistsError(msg string) error {
	return fmt.Errorf("%w: %s", ErrAlreadyExists, msg)
}

func NewValidationError(msg string) error {
	return fmt.Errorf("%w: %s", ErrValidation, msg)
}
