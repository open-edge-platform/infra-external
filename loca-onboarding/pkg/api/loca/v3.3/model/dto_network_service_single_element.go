// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoNetworkServiceSingleElement dto network service single element
//
// swagger:model dto.NetworkServiceSingleElement
type DtoNetworkServiceSingleElement struct {

	// child services
	ChildServices []string `json:"childServices"`

	// connection check
	ConnectionCheck bool `json:"connectionCheck,omitempty"`

	// created at
	CreatedAt string `json:"created_at,omitempty"`

	// description
	Description string `json:"description,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// instances
	Instances []string `json:"instances"`

	// mongouuid
	Mongouuid string `json:"mongouuid,omitempty"`

	// name
	Name string `json:"name,omitempty"`

	// parent service
	ParentService string `json:"parentService,omitempty"`

	// platform type
	PlatformType string `json:"platformType,omitempty"`

	// port
	Port int64 `json:"port,omitempty"`

	// protocol
	Protocol string `json:"protocol,omitempty"`

	// retries
	Retries int64 `json:"retries,omitempty"`

	// role
	Role string `json:"role,omitempty"`

	// role reference
	RoleReference string `json:"roleReference,omitempty"`

	// service address
	ServiceAddress string `json:"serviceAddress,omitempty"`

	// site association
	SiteAssociation []string `json:"siteAssociation"`

	// software version
	SoftwareVersion string `json:"softwareVersion,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// type
	Type string `json:"type,omitempty"`

	// updated at
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Validate validates this dto network service single element
func (m *DtoNetworkServiceSingleElement) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this dto network service single element based on context it is used
func (m *DtoNetworkServiceSingleElement) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DtoNetworkServiceSingleElement) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoNetworkServiceSingleElement) UnmarshalBinary(b []byte) error {
	var res DtoNetworkServiceSingleElement
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
