// Code generated by go-swagger; DO NOT EDIT.

package model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// DtoDeviceListElement dto device list element
//
// swagger:model dto.DeviceListElement
type DtoDeviceListElement struct {

	// connectivity check result
	ConnectivityCheckResult interface{} `json:"connectivityCheckResult,omitempty"`

	// contact
	Contact string `json:"contact,omitempty"`

	// cores number
	CoresNumber string `json:"coresNumber,omitempty"`

	// created at
	CreatedAt string `json:"created_at,omitempty"`

	// credentials
	Credentials []*DtoCredential `json:"credentials"`

	// description
	Description string `json:"description,omitempty"`

	// device role
	DeviceRole string `json:"deviceRole,omitempty"`

	// device type
	DeviceType *DtoDCIMType `json:"deviceType,omitempty"`

	// disk space
	DiskSpace string `json:"diskSpace,omitempty"`

	// editable
	Editable bool `json:"editable,omitempty"`

	// gpu count
	GpuCount string `json:"gpuCount,omitempty"`

	// hostdomain
	Hostdomain string `json:"hostdomain,omitempty"`

	// hostname
	Hostname string `json:"hostname,omitempty"`

	// id
	ID string `json:"id,omitempty"`

	// instance
	Instance string `json:"instance,omitempty"`

	// managed by
	ManagedBy string `json:"managedBy,omitempty"`

	// mongouuid
	Mongouuid string `json:"mongouuid,omitempty"`

	// nic bandwidth
	NicBandwidth string `json:"nicBandwidth,omitempty"`

	// nics
	Nics []*DtoNIC `json:"nics"`

	// platform
	Platform string `json:"platform,omitempty"`

	// primary IP
	PrimaryIP string `json:"primaryIP,omitempty"`

	// ram amount
	RAMAmount string `json:"ramAmount,omitempty"`

	// serial number
	SerialNumber string `json:"serialNumber,omitempty"`

	// settings
	Settings map[string]interface{} `json:"settings,omitempty"`

	// sideload
	Sideload *DtoSideload `json:"sideload,omitempty"`

	// site
	Site string `json:"site,omitempty"`

	// sockets
	Sockets string `json:"sockets,omitempty"`

	// source
	Source string `json:"source,omitempty"`

	// status
	Status string `json:"status,omitempty"`

	// updated at
	UpdatedAt string `json:"updated_at,omitempty"`

	// uuid
	UUID string `json:"uuid,omitempty"`
}

// Validate validates this dto device list element
func (m *DtoDeviceListElement) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCredentials(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeviceType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNics(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSideload(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoDeviceListElement) validateCredentials(formats strfmt.Registry) error {
	if swag.IsZero(m.Credentials) { // not required
		return nil
	}

	for i := 0; i < len(m.Credentials); i++ {
		if swag.IsZero(m.Credentials[i]) { // not required
			continue
		}

		if m.Credentials[i] != nil {
			if err := m.Credentials[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DtoDeviceListElement) validateDeviceType(formats strfmt.Registry) error {
	if swag.IsZero(m.DeviceType) { // not required
		return nil
	}

	if m.DeviceType != nil {
		if err := m.DeviceType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("deviceType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("deviceType")
			}
			return err
		}
	}

	return nil
}

func (m *DtoDeviceListElement) validateNics(formats strfmt.Registry) error {
	if swag.IsZero(m.Nics) { // not required
		return nil
	}

	for i := 0; i < len(m.Nics); i++ {
		if swag.IsZero(m.Nics[i]) { // not required
			continue
		}

		if m.Nics[i] != nil {
			if err := m.Nics[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("nics" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("nics" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DtoDeviceListElement) validateSideload(formats strfmt.Registry) error {
	if swag.IsZero(m.Sideload) { // not required
		return nil
	}

	if m.Sideload != nil {
		if err := m.Sideload.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sideload")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sideload")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this dto device list element based on the context it is used
func (m *DtoDeviceListElement) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCredentials(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDeviceType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateNics(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSideload(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DtoDeviceListElement) contextValidateCredentials(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Credentials); i++ {

		if m.Credentials[i] != nil {

			if swag.IsZero(m.Credentials[i]) { // not required
				return nil
			}

			if err := m.Credentials[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("credentials" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("credentials" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DtoDeviceListElement) contextValidateDeviceType(ctx context.Context, formats strfmt.Registry) error {

	if m.DeviceType != nil {

		if swag.IsZero(m.DeviceType) { // not required
			return nil
		}

		if err := m.DeviceType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("deviceType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("deviceType")
			}
			return err
		}
	}

	return nil
}

func (m *DtoDeviceListElement) contextValidateNics(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Nics); i++ {

		if m.Nics[i] != nil {

			if swag.IsZero(m.Nics[i]) { // not required
				return nil
			}

			if err := m.Nics[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("nics" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("nics" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *DtoDeviceListElement) contextValidateSideload(ctx context.Context, formats strfmt.Registry) error {

	if m.Sideload != nil {

		if swag.IsZero(m.Sideload) { // not required
			return nil
		}

		if err := m.Sideload.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("sideload")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("sideload")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DtoDeviceListElement) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DtoDeviceListElement) UnmarshalBinary(b []byte) error {
	var res DtoDeviceListElement
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
