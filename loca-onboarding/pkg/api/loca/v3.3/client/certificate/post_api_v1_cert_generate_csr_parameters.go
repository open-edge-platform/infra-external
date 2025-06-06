// Code generated by go-swagger; DO NOT EDIT.

package certificate

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

// NewPostAPIV1CertGenerateCsrParams creates a new PostAPIV1CertGenerateCsrParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostAPIV1CertGenerateCsrParams() *PostAPIV1CertGenerateCsrParams {
	return &PostAPIV1CertGenerateCsrParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostAPIV1CertGenerateCsrParamsWithTimeout creates a new PostAPIV1CertGenerateCsrParams object
// with the ability to set a timeout on a request.
func NewPostAPIV1CertGenerateCsrParamsWithTimeout(timeout time.Duration) *PostAPIV1CertGenerateCsrParams {
	return &PostAPIV1CertGenerateCsrParams{
		timeout: timeout,
	}
}

// NewPostAPIV1CertGenerateCsrParamsWithContext creates a new PostAPIV1CertGenerateCsrParams object
// with the ability to set a context for a request.
func NewPostAPIV1CertGenerateCsrParamsWithContext(ctx context.Context) *PostAPIV1CertGenerateCsrParams {
	return &PostAPIV1CertGenerateCsrParams{
		Context: ctx,
	}
}

// NewPostAPIV1CertGenerateCsrParamsWithHTTPClient creates a new PostAPIV1CertGenerateCsrParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostAPIV1CertGenerateCsrParamsWithHTTPClient(client *http.Client) *PostAPIV1CertGenerateCsrParams {
	return &PostAPIV1CertGenerateCsrParams{
		HTTPClient: client,
	}
}

/*
PostAPIV1CertGenerateCsrParams contains all the parameters to send to the API endpoint

	for the post API v1 cert generate csr operation.

	Typically these are written to a http.Request.
*/
type PostAPIV1CertGenerateCsrParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* Body.

	   csr
	*/
	Body *model.DtoCSRCreateParams

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post API v1 cert generate csr params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAPIV1CertGenerateCsrParams) WithDefaults() *PostAPIV1CertGenerateCsrParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post API v1 cert generate csr params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAPIV1CertGenerateCsrParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) WithTimeout(timeout time.Duration) *PostAPIV1CertGenerateCsrParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) WithContext(ctx context.Context) *PostAPIV1CertGenerateCsrParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) WithHTTPClient(client *http.Client) *PostAPIV1CertGenerateCsrParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) WithAuthorization(authorization string) *PostAPIV1CertGenerateCsrParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithBody adds the body to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) WithBody(body *model.DtoCSRCreateParams) *PostAPIV1CertGenerateCsrParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the post API v1 cert generate csr params
func (o *PostAPIV1CertGenerateCsrParams) SetBody(body *model.DtoCSRCreateParams) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PostAPIV1CertGenerateCsrParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
