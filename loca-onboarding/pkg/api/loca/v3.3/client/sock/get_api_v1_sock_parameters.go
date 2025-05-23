// Code generated by go-swagger; DO NOT EDIT.

package sock

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

// NewGetAPIV1SockParams creates a new GetAPIV1SockParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1SockParams() *GetAPIV1SockParams {
	return &GetAPIV1SockParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1SockParamsWithTimeout creates a new GetAPIV1SockParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1SockParamsWithTimeout(timeout time.Duration) *GetAPIV1SockParams {
	return &GetAPIV1SockParams{
		timeout: timeout,
	}
}

// NewGetAPIV1SockParamsWithContext creates a new GetAPIV1SockParams object
// with the ability to set a context for a request.
func NewGetAPIV1SockParamsWithContext(ctx context.Context) *GetAPIV1SockParams {
	return &GetAPIV1SockParams{
		Context: ctx,
	}
}

// NewGetAPIV1SockParamsWithHTTPClient creates a new GetAPIV1SockParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1SockParamsWithHTTPClient(client *http.Client) *GetAPIV1SockParams {
	return &GetAPIV1SockParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1SockParams contains all the parameters to send to the API endpoint

	for the get API v1 sock operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1SockParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 sock params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1SockParams) WithDefaults() *GetAPIV1SockParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 sock params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1SockParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get API v1 sock params
func (o *GetAPIV1SockParams) WithTimeout(timeout time.Duration) *GetAPIV1SockParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 sock params
func (o *GetAPIV1SockParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 sock params
func (o *GetAPIV1SockParams) WithContext(ctx context.Context) *GetAPIV1SockParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 sock params
func (o *GetAPIV1SockParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 sock params
func (o *GetAPIV1SockParams) WithHTTPClient(client *http.Client) *GetAPIV1SockParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 sock params
func (o *GetAPIV1SockParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 sock params
func (o *GetAPIV1SockParams) WithAuthorization(authorization string) *GetAPIV1SockParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 sock params
func (o *GetAPIV1SockParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1SockParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
