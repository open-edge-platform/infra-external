// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// DtoUserUpdateRequest dto user update request
//
// swagger:model dto.UserUpdateRequest
type DtoUserUpdateRequest struct {

	// name
	// Max Length: 30
	// Min Length: 3
	Name string `json:"name,omitempty"`

	// role
	Role string `json:"role,omitempty"`
}

// Validate validates this dto user update request
func (m *DtoUserUpdateRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoUserUpdateRequest) validateName(formats strfmt.Registry) error {
	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := validate.MinLength("name", "body", m.Name, 3); err != nil {
		return err
	}

	if err := validate.MaxLength("name", "body", m.Name, 30); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this dto user update request based on context it is used
func (m *DtoUserUpdateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoUserUpdateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoUserUpdateRequest) UnmarshalBinary(b []byte) error {
	var res DtoUserUpdateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
