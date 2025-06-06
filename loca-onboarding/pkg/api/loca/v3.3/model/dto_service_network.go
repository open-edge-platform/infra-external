// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoServiceNetwork dto service network
//
// swagger:model dto.ServiceNetwork
type DtoServiceNetwork struct {

	// ipv4 address
	IPV4Address string `json:"ipv4Address,omitempty"`

	// name
	Name string `json:"name,omitempty"`
}

// Validate validates this dto service network
func (m *DtoServiceNetwork) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto service network based on context it is used
func (m *DtoServiceNetwork) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoServiceNetwork) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoServiceNetwork) UnmarshalBinary(b []byte) error {
	var res DtoServiceNetwork
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
