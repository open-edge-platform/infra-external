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

// ModelsVaultGetSecretUnderPath models vault get secret under path
//
// swagger:model models.VaultGetSecretUnderPath
type ModelsVaultGetSecretUnderPath struct {

	// secret path
	// Required: true
	SecretPath *string `json:"secretPath"`

	// vault name
	// Required: true
	VaultName *string `json:"vaultName"`
}

// Validate validates this models vault get secret under path
func (m *ModelsVaultGetSecretUnderPath) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSecretPath(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVaultName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModelsVaultGetSecretUnderPath) validateSecretPath(formats strfmt.Registry) error {

	if err := validate.Required("secretPath", "body", m.SecretPath); err != nil {
		return err
	}

	return nil
}

func (m *ModelsVaultGetSecretUnderPath) validateVaultName(formats strfmt.Registry) error {

	if err := validate.Required("vaultName", "body", m.VaultName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this models vault get secret under path based on context it is used
func (m *ModelsVaultGetSecretUnderPath) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsVaultGetSecretUnderPath) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsVaultGetSecretUnderPath) UnmarshalBinary(b []byte) error {
	var res ModelsVaultGetSecretUnderPath
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
