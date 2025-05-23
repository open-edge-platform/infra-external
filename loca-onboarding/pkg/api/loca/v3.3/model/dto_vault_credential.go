// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoVaultCredential The vault credential
//
// swagger:model dto.VaultCredential
type DtoVaultCredential struct {

	// true if only password read from vault and username provided in clear text
	CtUser bool `json:"ctUser,omitempty"`

	// true if this vault credential is enabled
	Enable bool `json:"enable,omitempty"`

	// true if the secret path provided manually
	Manual bool `json:"manual,omitempty"`

	// the name of the vault credential
	Name string `json:"name,omitempty"`

	// the secret path of the vault credential
	SecretPath string `json:"secretPath,omitempty"`
}

// Validate validates this dto vault credential
func (m *DtoVaultCredential) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto vault credential based on context it is used
func (m *DtoVaultCredential) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoVaultCredential) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoVaultCredential) UnmarshalBinary(b []byte) error {
	var res DtoVaultCredential
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
