// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoWorkflow dto workflow
//
// swagger:model dto.Workflow
type DtoWorkflow struct {

	// task uuid
	TaskUUID []string `json:"task_uuid"`

	// workflow
	Workflow string `json:"workflow,omitempty"`
}

// Validate validates this dto workflow
func (m *DtoWorkflow) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto workflow based on context it is used
func (m *DtoWorkflow) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoWorkflow) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoWorkflow) UnmarshalBinary(b []byte) error {
	var res DtoWorkflow
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
