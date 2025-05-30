// Code generated by go-swagger; DO NOT EDIT.

package authentication_and_authorization

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

// NewGetAPIV1AuthUsersIDParams creates a new GetAPIV1AuthUsersIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1AuthUsersIDParams() *GetAPIV1AuthUsersIDParams {
	return &GetAPIV1AuthUsersIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1AuthUsersIDParamsWithTimeout creates a new GetAPIV1AuthUsersIDParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1AuthUsersIDParamsWithTimeout(timeout time.Duration) *GetAPIV1AuthUsersIDParams {
	return &GetAPIV1AuthUsersIDParams{
		timeout: timeout,
	}
}

// NewGetAPIV1AuthUsersIDParamsWithContext creates a new GetAPIV1AuthUsersIDParams object
// with the ability to set a context for a request.
func NewGetAPIV1AuthUsersIDParamsWithContext(ctx context.Context) *GetAPIV1AuthUsersIDParams {
	return &GetAPIV1AuthUsersIDParams{
		Context: ctx,
	}
}

// NewGetAPIV1AuthUsersIDParamsWithHTTPClient creates a new GetAPIV1AuthUsersIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1AuthUsersIDParamsWithHTTPClient(client *http.Client) *GetAPIV1AuthUsersIDParams {
	return &GetAPIV1AuthUsersIDParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1AuthUsersIDParams contains all the parameters to send to the API endpoint

	for the get API v1 auth users ID operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1AuthUsersIDParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* ID.

	   User ID
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 auth users ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1AuthUsersIDParams) WithDefaults() *GetAPIV1AuthUsersIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 auth users ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1AuthUsersIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) WithTimeout(timeout time.Duration) *GetAPIV1AuthUsersIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) WithContext(ctx context.Context) *GetAPIV1AuthUsersIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) WithHTTPClient(client *http.Client) *GetAPIV1AuthUsersIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) WithAuthorization(authorization string) *GetAPIV1AuthUsersIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithID adds the id to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) WithID(id string) *GetAPIV1AuthUsersIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get API v1 auth users ID params
func (o *GetAPIV1AuthUsersIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1AuthUsersIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
