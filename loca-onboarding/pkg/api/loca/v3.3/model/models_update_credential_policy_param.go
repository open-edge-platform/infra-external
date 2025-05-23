// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ModelsUpdateCredentialPolicyParam models update credential policy param
//
// swagger:model models.UpdateCredentialPolicyParam
type ModelsUpdateCredentialPolicyParam struct {

	// id
	ID string `json:"id,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// password template
	PasswordTemplate string `json:"passwordTemplate,omitempty"`
}

// Validate validates this models update credential policy param
func (m *ModelsUpdateCredentialPolicyParam) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this models update credential policy param based on context it is used
func (m *ModelsUpdateCredentialPolicyParam) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ModelsUpdateCredentialPolicyParam) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModelsUpdateCredentialPolicyParam) UnmarshalBinary(b []byte) error {
	var res ModelsUpdateCredentialPolicyParam
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
