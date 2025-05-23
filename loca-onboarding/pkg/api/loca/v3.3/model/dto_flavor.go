// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoFlavor dto flavor
//
// swagger:model dto.Flavor
type DtoFlavor struct {

	// id
	ID string `json:"id,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// versions
	Versions []string `json:"versions"`
}

// Validate validates this dto flavor
func (m *DtoFlavor) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto flavor based on context it is used
func (m *DtoFlavor) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoFlavor) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoFlavor) UnmarshalBinary(b []byte) error {
	var res DtoFlavor
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
