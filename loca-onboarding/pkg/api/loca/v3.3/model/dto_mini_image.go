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

// DtoMiniImage dto mini image
//
// swagger:model dto.MiniImage
type DtoMiniImage struct {

	// created by
	CreatedBy string `json:"created_by,omitempty"`

	// created time
	CreatedTime string `json:"created_time,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// expire at
	ExpireAt string `json:"expire_at,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// key
	Key string `json:"key,omitempty"`

	// link
	Link string `json:"link,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// password policy
	PasswordPolicy *DtoMiniImagePasswordPolicy `json:"password_policy,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// type
	Type string `json:"type,omitempty"`
}

// Validate validates this dto mini image
func (m *DtoMiniImage) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePasswordPolicy(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoMiniImage) validatePasswordPolicy(formats strfmt.Registry) error {
	if swag.IsZero(m.PasswordPolicy) { // not required
		return nil
	}

	if m.PasswordPolicy != nil {
		if err := m.PasswordPolicy.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("password_policy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("password_policy")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this dto mini image based on the context it is used
func (m *DtoMiniImage) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePasswordPolicy(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoMiniImage) contextValidatePasswordPolicy(ctx context.Context, formats strfmt.Registry) error {

	if m.PasswordPolicy != nil {

		if swag.IsZero(m.PasswordPolicy) { // not required
			return nil
		}

		if err := m.PasswordPolicy.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("password_policy")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("password_policy")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DtoMiniImage) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoMiniImage) UnmarshalBinary(b []byte) error {
	var res DtoMiniImage
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}

// DtoMiniImagePasswordPolicy dto mini image password policy
//
// swagger:model DtoMiniImagePasswordPolicy
type DtoMiniImagePasswordPolicy struct {

	// bmc
	Bmc string `json:"bmc,omitempty"`

	// uefi
	Uefi string `json:"uefi,omitempty"`
}

// Validate validates this dto mini image password policy
func (m *DtoMiniImagePasswordPolicy) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto mini image password policy based on context it is used
func (m *DtoMiniImagePasswordPolicy) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoMiniImagePasswordPolicy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoMiniImagePasswordPolicy) UnmarshalBinary(b []byte) error {
	var res DtoMiniImagePasswordPolicy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
