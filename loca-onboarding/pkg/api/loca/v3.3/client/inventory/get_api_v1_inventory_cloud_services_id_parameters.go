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

// NewGetAPIV1InventoryCloudServicesIDParams creates a new GetAPIV1InventoryCloudServicesIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1InventoryCloudServicesIDParams() *GetAPIV1InventoryCloudServicesIDParams {
	return &GetAPIV1InventoryCloudServicesIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1InventoryCloudServicesIDParamsWithTimeout creates a new GetAPIV1InventoryCloudServicesIDParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1InventoryCloudServicesIDParamsWithTimeout(timeout time.Duration) *GetAPIV1InventoryCloudServicesIDParams {
	return &GetAPIV1InventoryCloudServicesIDParams{
		timeout: timeout,
	}
}

// NewGetAPIV1InventoryCloudServicesIDParamsWithContext creates a new GetAPIV1InventoryCloudServicesIDParams object
// with the ability to set a context for a request.
func NewGetAPIV1InventoryCloudServicesIDParamsWithContext(ctx context.Context) *GetAPIV1InventoryCloudServicesIDParams {
	return &GetAPIV1InventoryCloudServicesIDParams{
		Context: ctx,
	}
}

// NewGetAPIV1InventoryCloudServicesIDParamsWithHTTPClient creates a new GetAPIV1InventoryCloudServicesIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1InventoryCloudServicesIDParamsWithHTTPClient(client *http.Client) *GetAPIV1InventoryCloudServicesIDParams {
	return &GetAPIV1InventoryCloudServicesIDParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1InventoryCloudServicesIDParams contains all the parameters to send to the API endpoint

	for the get API v1 inventory cloud services ID operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1InventoryCloudServicesIDParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* ID.

	   get cloud service by id
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 inventory cloud services ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryCloudServicesIDParams) WithDefaults() *GetAPIV1InventoryCloudServicesIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 inventory cloud services ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryCloudServicesIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) WithTimeout(timeout time.Duration) *GetAPIV1InventoryCloudServicesIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) WithContext(ctx context.Context) *GetAPIV1InventoryCloudServicesIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) WithHTTPClient(client *http.Client) *GetAPIV1InventoryCloudServicesIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) WithAuthorization(authorization string) *GetAPIV1InventoryCloudServicesIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithID adds the id to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) WithID(id string) *GetAPIV1InventoryCloudServicesIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get API v1 inventory cloud services ID params
func (o *GetAPIV1InventoryCloudServicesIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1InventoryCloudServicesIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
