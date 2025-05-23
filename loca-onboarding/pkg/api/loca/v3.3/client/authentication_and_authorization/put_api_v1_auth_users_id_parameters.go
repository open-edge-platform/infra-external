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

	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
)

// NewPutAPIV1AuthUsersIDParams creates a new PutAPIV1AuthUsersIDParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPutAPIV1AuthUsersIDParams() *PutAPIV1AuthUsersIDParams {
	return &PutAPIV1AuthUsersIDParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPutAPIV1AuthUsersIDParamsWithTimeout creates a new PutAPIV1AuthUsersIDParams object
// with the ability to set a timeout on a request.
func NewPutAPIV1AuthUsersIDParamsWithTimeout(timeout time.Duration) *PutAPIV1AuthUsersIDParams {
	return &PutAPIV1AuthUsersIDParams{
		timeout: timeout,
	}
}

// NewPutAPIV1AuthUsersIDParamsWithContext creates a new PutAPIV1AuthUsersIDParams object
// with the ability to set a context for a request.
func NewPutAPIV1AuthUsersIDParamsWithContext(ctx context.Context) *PutAPIV1AuthUsersIDParams {
	return &PutAPIV1AuthUsersIDParams{
		Context: ctx,
	}
}

// NewPutAPIV1AuthUsersIDParamsWithHTTPClient creates a new PutAPIV1AuthUsersIDParams object
// with the ability to set a custom HTTPClient for a request.
func NewPutAPIV1AuthUsersIDParamsWithHTTPClient(client *http.Client) *PutAPIV1AuthUsersIDParams {
	return &PutAPIV1AuthUsersIDParams{
		HTTPClient: client,
	}
}

/*
PutAPIV1AuthUsersIDParams contains all the parameters to send to the API endpoint

	for the put API v1 auth users ID operation.

	Typically these are written to a http.Request.
*/
type PutAPIV1AuthUsersIDParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* Body.

	   update a user by id
	*/
	Body *model.DtoUserUpdateRequest

	/* ID.

	   User ID
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the put API v1 auth users ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PutAPIV1AuthUsersIDParams) WithDefaults() *PutAPIV1AuthUsersIDParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the put API v1 auth users ID params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PutAPIV1AuthUsersIDParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) WithTimeout(timeout time.Duration) *PutAPIV1AuthUsersIDParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) WithContext(ctx context.Context) *PutAPIV1AuthUsersIDParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) WithHTTPClient(client *http.Client) *PutAPIV1AuthUsersIDParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) WithAuthorization(authorization string) *PutAPIV1AuthUsersIDParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithBody adds the body to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) WithBody(body *model.DtoUserUpdateRequest) *PutAPIV1AuthUsersIDParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) SetBody(body *model.DtoUserUpdateRequest) {
	o.Body = body
}

// WithID adds the id to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) WithID(id string) *PutAPIV1AuthUsersIDParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the put API v1 auth users ID params
func (o *PutAPIV1AuthUsersIDParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *PutAPIV1AuthUsersIDParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
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
