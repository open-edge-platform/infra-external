// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoUserLoginResponse dto user login response
//
// swagger:model dto.UserLoginResponse
type DtoUserLoginResponse struct {

	// data
	Data *DtoUserLoginResponseData `json:"data,omitempty"`

	// message
	Message string `json:"message,omitempty"`

	// status code
	StatusCode int64 `json:"statusCode,omitempty"`
}

// Validate validates this dto user login response
func (m *DtoUserLoginResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoUserLoginResponse) validateData(formats strfmt.Registry) error {
	if swag.IsZero(m.Data) { // not required
		return nil
	}

	if m.Data != nil {
		if err := m.Data.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this dto user login response based on the context it is used
func (m *DtoUserLoginResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoUserLoginResponse) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

	if m.Data != nil {

		if swag.IsZero(m.Data) { // not required
			return nil
		}

		if err := m.Data.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("data")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("data")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DtoUserLoginResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoUserLoginResponse) UnmarshalBinary(b []byte) error {
	var res DtoUserLoginResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DtoUserLoginResponseData dto user login response data
//
// swagger:model DtoUserLoginResponseData
type DtoUserLoginResponseData struct {

	// refresh token
	RefreshToken string `json:"refresh_token,omitempty"`

	// token
	Token string `json:"token,omitempty"`
}

// Validate validates this dto user login response data
func (m *DtoUserLoginResponseData) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto user login response data based on context it is used
func (m *DtoUserLoginResponseData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoUserLoginResponseData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoUserLoginResponseData) UnmarshalBinary(b []byte) error {
	var res DtoUserLoginResponseData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
