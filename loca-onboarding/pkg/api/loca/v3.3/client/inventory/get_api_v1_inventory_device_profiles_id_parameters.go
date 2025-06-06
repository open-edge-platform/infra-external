// Code generated by go-swagger; DO NOT EDIT.

package inventory

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetAPIV1InventoryDeviceProfilesIDParams creates a new GetAPIV1InventoryDeviceProfilesIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1InventoryDeviceProfilesIDParams() *GetAPIV1InventoryDeviceProfilesIDParams {
	return &GetAPIV1InventoryDeviceProfilesIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1InventoryDeviceProfilesIDParamsWithTimeout creates a new GetAPIV1InventoryDeviceProfilesIDParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1InventoryDeviceProfilesIDParamsWithTimeout(timeout time.Duration) *GetAPIV1InventoryDeviceProfilesIDParams {
	return &GetAPIV1InventoryDeviceProfilesIDParams{
		timeout: timeout,
	}
}

// NewGetAPIV1InventoryDeviceProfilesIDParamsWithContext creates a new GetAPIV1InventoryDeviceProfilesIDParams object
// with the ability to set a context for a request.
func NewGetAPIV1InventoryDeviceProfilesIDParamsWithContext(ctx context.Context) *GetAPIV1InventoryDeviceProfilesIDParams {
	return &GetAPIV1InventoryDeviceProfilesIDParams{
		Context: ctx,
	}
}

// NewGetAPIV1InventoryDeviceProfilesIDParamsWithHTTPClient creates a new GetAPIV1InventoryDeviceProfilesIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1InventoryDeviceProfilesIDParamsWithHTTPClient(client *http.Client) *GetAPIV1InventoryDeviceProfilesIDParams {
	return &GetAPIV1InventoryDeviceProfilesIDParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1InventoryDeviceProfilesIDParams contains all the parameters to send to the API endpoint

	for the get API v1 inventory device profiles ID operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1InventoryDeviceProfilesIDParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* ID.

	   id of device profile
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 inventory device profiles ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WithDefaults() *GetAPIV1InventoryDeviceProfilesIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 inventory device profiles ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryDeviceProfilesIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WithTimeout(timeout time.Duration) *GetAPIV1InventoryDeviceProfilesIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WithContext(ctx context.Context) *GetAPIV1InventoryDeviceProfilesIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WithHTTPClient(client *http.Client) *GetAPIV1InventoryDeviceProfilesIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WithAuthorization(authorization string) *GetAPIV1InventoryDeviceProfilesIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithID adds the id to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WithID(id string) *GetAPIV1InventoryDeviceProfilesIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get API v1 inventory device profiles ID params
func (o *GetAPIV1InventoryDeviceProfilesIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1InventoryDeviceProfilesIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
