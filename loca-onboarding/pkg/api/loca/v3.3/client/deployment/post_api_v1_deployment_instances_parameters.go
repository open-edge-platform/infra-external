// Code generated by go-swagger; DO NOT EDIT.

package deployment

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

// NewPostAPIV1DeploymentInstancesParams creates a new PostAPIV1DeploymentInstancesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostAPIV1DeploymentInstancesParams() *PostAPIV1DeploymentInstancesParams {
	return &PostAPIV1DeploymentInstancesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostAPIV1DeploymentInstancesParamsWithTimeout creates a new PostAPIV1DeploymentInstancesParams object
// with the ability to set a timeout on a request.
func NewPostAPIV1DeploymentInstancesParamsWithTimeout(timeout time.Duration) *PostAPIV1DeploymentInstancesParams {
	return &PostAPIV1DeploymentInstancesParams{
		timeout: timeout,
	}
}

// NewPostAPIV1DeploymentInstancesParamsWithContext creates a new PostAPIV1DeploymentInstancesParams object
// with the ability to set a context for a request.
func NewPostAPIV1DeploymentInstancesParamsWithContext(ctx context.Context) *PostAPIV1DeploymentInstancesParams {
	return &PostAPIV1DeploymentInstancesParams{
		Context: ctx,
	}
}

// NewPostAPIV1DeploymentInstancesParamsWithHTTPClient creates a new PostAPIV1DeploymentInstancesParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostAPIV1DeploymentInstancesParamsWithHTTPClient(client *http.Client) *PostAPIV1DeploymentInstancesParams {
	return &PostAPIV1DeploymentInstancesParams{
		HTTPClient: client,
	}
}

/*
PostAPIV1DeploymentInstancesParams contains all the parameters to send to the API endpoint

	for the post API v1 deployment instances operation.

	Typically these are written to a http.Request.
*/
type PostAPIV1DeploymentInstancesParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* Body.

	   The detailed info of cloud instance.
	*/
	Body *model.ModelsOnboardInstancesParams

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post API v1 deployment instances params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAPIV1DeploymentInstancesParams) WithDefaults() *PostAPIV1DeploymentInstancesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post API v1 deployment instances params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAPIV1DeploymentInstancesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) WithTimeout(timeout time.Duration) *PostAPIV1DeploymentInstancesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) WithContext(ctx context.Context) *PostAPIV1DeploymentInstancesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) WithHTTPClient(client *http.Client) *PostAPIV1DeploymentInstancesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) WithAuthorization(authorization string) *PostAPIV1DeploymentInstancesParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithBody adds the body to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) WithBody(body *model.ModelsOnboardInstancesParams) *PostAPIV1DeploymentInstancesParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the post API v1 deployment instances params
func (o *PostAPIV1DeploymentInstancesParams) SetBody(body *model.ModelsOnboardInstancesParams) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PostAPIV1DeploymentInstancesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
