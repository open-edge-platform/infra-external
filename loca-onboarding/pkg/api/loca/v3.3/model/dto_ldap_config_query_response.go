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

// DtoLdapConfigQueryResponse dto ldap config query response
//
// swagger:model dto.LdapConfigQueryResponse
type DtoLdapConfigQueryResponse struct {

	// data
	Data *DtoLdapConfig `json:"data,omitempty"`

	// message
	Message string `json:"message,omitempty"`

	// status code
	StatusCode int64 `json:"statusCode,omitempty"`
}

// Validate validates this dto ldap config query response
func (m *DtoLdapConfigQueryResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoLdapConfigQueryResponse) validateData(formats strfmt.Registry) error {
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

// ContextValidate validate this dto ldap config query response based on the context it is used
func (m *DtoLdapConfigQueryResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoLdapConfigQueryResponse) contextValidateData(ctx context.Context, formats strfmt.Registry) error {

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
func (m *DtoLdapConfigQueryResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoLdapConfigQueryResponse) UnmarshalBinary(b []byte) error {
	var res DtoLdapConfigQueryResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
