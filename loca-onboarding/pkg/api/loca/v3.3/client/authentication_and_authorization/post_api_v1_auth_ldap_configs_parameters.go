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
	"github.com/go-openapi/swag"
)

// NewPostAPIV1AuthLdapConfigsParams creates a new PostAPIV1AuthLdapConfigsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPostAPIV1AuthLdapConfigsParams() *PostAPIV1AuthLdapConfigsParams {
	return &PostAPIV1AuthLdapConfigsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPostAPIV1AuthLdapConfigsParamsWithTimeout creates a new PostAPIV1AuthLdapConfigsParams object
// with the ability to set a timeout on a request.
func NewPostAPIV1AuthLdapConfigsParamsWithTimeout(timeout time.Duration) *PostAPIV1AuthLdapConfigsParams {
	return &PostAPIV1AuthLdapConfigsParams{
		timeout: timeout,
	}
}

// NewPostAPIV1AuthLdapConfigsParamsWithContext creates a new PostAPIV1AuthLdapConfigsParams object
// with the ability to set a context for a request.
func NewPostAPIV1AuthLdapConfigsParamsWithContext(ctx context.Context) *PostAPIV1AuthLdapConfigsParams {
	return &PostAPIV1AuthLdapConfigsParams{
		Context: ctx,
	}
}

// NewPostAPIV1AuthLdapConfigsParamsWithHTTPClient creates a new PostAPIV1AuthLdapConfigsParams object
// with the ability to set a custom HTTPClient for a request.
func NewPostAPIV1AuthLdapConfigsParamsWithHTTPClient(client *http.Client) *PostAPIV1AuthLdapConfigsParams {
	return &PostAPIV1AuthLdapConfigsParams{
		HTTPClient: client,
	}
}

/*
PostAPIV1AuthLdapConfigsParams contains all the parameters to send to the API endpoint

	for the post API v1 auth ldap configs operation.

	Typically these are written to a http.Request.
*/
type PostAPIV1AuthLdapConfigsParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	// BindPassword.
	BindPassword *string

	// BindUsername.
	BindUsername *string

	/* File.

	   File
	*/
	File runtime.NamedReadCloser

	// GroupFilter.
	GroupFilter *string

	// GroupSearchAttribute.
	GroupSearchAttribute []string

	// ID.
	ID *string

	// LocalRole.
	LocalRole *string

	// Name.
	Name *string

	/* Path.

	   file path
	*/
	Path string

	// RootDn.
	RootDn *string

	// UserFilter.
	UserFilter *string

	// UserSearchAttribute.
	UserSearchAttribute *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the post API v1 auth ldap configs params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAPIV1AuthLdapConfigsParams) WithDefaults() *PostAPIV1AuthLdapConfigsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the post API v1 auth ldap configs params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PostAPIV1AuthLdapConfigsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithTimeout(timeout time.Duration) *PostAPIV1AuthLdapConfigsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithContext(ctx context.Context) *PostAPIV1AuthLdapConfigsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithHTTPClient(client *http.Client) *PostAPIV1AuthLdapConfigsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithAuthorization(authorization string) *PostAPIV1AuthLdapConfigsParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithBindPassword adds the bindPassword to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithBindPassword(bindPassword *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetBindPassword(bindPassword)
	return o
}

// SetBindPassword adds the bindPassword to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetBindPassword(bindPassword *string) {
	o.BindPassword = bindPassword
}

// WithBindUsername adds the bindUsername to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithBindUsername(bindUsername *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetBindUsername(bindUsername)
	return o
}

// SetBindUsername adds the bindUsername to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetBindUsername(bindUsername *string) {
	o.BindUsername = bindUsername
}

// WithFile adds the file to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithFile(file runtime.NamedReadCloser) *PostAPIV1AuthLdapConfigsParams {
	o.SetFile(file)
	return o
}

// SetFile adds the file to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetFile(file runtime.NamedReadCloser) {
	o.File = file
}

// WithGroupFilter adds the groupFilter to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithGroupFilter(groupFilter *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetGroupFilter(groupFilter)
	return o
}

// SetGroupFilter adds the groupFilter to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetGroupFilter(groupFilter *string) {
	o.GroupFilter = groupFilter
}

// WithGroupSearchAttribute adds the groupSearchAttribute to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithGroupSearchAttribute(groupSearchAttribute []string) *PostAPIV1AuthLdapConfigsParams {
	o.SetGroupSearchAttribute(groupSearchAttribute)
	return o
}

// SetGroupSearchAttribute adds the groupSearchAttribute to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetGroupSearchAttribute(groupSearchAttribute []string) {
	o.GroupSearchAttribute = groupSearchAttribute
}

// WithID adds the id to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithID(id *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetID(id *string) {
	o.ID = id
}

// WithLocalRole adds the localRole to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithLocalRole(localRole *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetLocalRole(localRole)
	return o
}

// SetLocalRole adds the localRole to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetLocalRole(localRole *string) {
	o.LocalRole = localRole
}

// WithName adds the name to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithName(name *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetName(name *string) {
	o.Name = name
}

// WithPath adds the path to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithPath(path string) *PostAPIV1AuthLdapConfigsParams {
	o.SetPath(path)
	return o
}

// SetPath adds the path to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetPath(path string) {
	o.Path = path
}

// WithRootDn adds the rootDn to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithRootDn(rootDn *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetRootDn(rootDn)
	return o
}

// SetRootDn adds the rootDn to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetRootDn(rootDn *string) {
	o.RootDn = rootDn
}

// WithUserFilter adds the userFilter to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithUserFilter(userFilter *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetUserFilter(userFilter)
	return o
}

// SetUserFilter adds the userFilter to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetUserFilter(userFilter *string) {
	o.UserFilter = userFilter
}

// WithUserSearchAttribute adds the userSearchAttribute to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) WithUserSearchAttribute(userSearchAttribute *string) *PostAPIV1AuthLdapConfigsParams {
	o.SetUserSearchAttribute(userSearchAttribute)
	return o
}

// SetUserSearchAttribute adds the userSearchAttribute to the post API v1 auth ldap configs params
func (o *PostAPIV1AuthLdapConfigsParams) SetUserSearchAttribute(userSearchAttribute *string) {
	o.UserSearchAttribute = userSearchAttribute
}

// WriteToRequest writes these params to a swagger request
func (o *PostAPIV1AuthLdapConfigsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	if o.BindPassword != nil {

		// form param bind_password
		var frBindPassword string
		if o.BindPassword != nil {
			frBindPassword = *o.BindPassword
		}
		fBindPassword := frBindPassword
		if fBindPassword != "" {
			if err := r.SetFormParam("bind_password", fBindPassword); err != nil {
				return err
			}
		}
	}

	if o.BindUsername != nil {

		// form param bind_username
		var frBindUsername string
		if o.BindUsername != nil {
			frBindUsername = *o.BindUsername
		}
		fBindUsername := frBindUsername
		if fBindUsername != "" {
			if err := r.SetFormParam("bind_username", fBindUsername); err != nil {
				return err
			}
		}
	}
	// form file param file
	if err := r.SetFileParam("file", o.File); err != nil {
		return err
	}

	if o.GroupFilter != nil {

		// form param group_filter
		var frGroupFilter string
		if o.GroupFilter != nil {
			frGroupFilter = *o.GroupFilter
		}
		fGroupFilter := frGroupFilter
		if fGroupFilter != "" {
			if err := r.SetFormParam("group_filter", fGroupFilter); err != nil {
				return err
			}
		}
	}

	if o.GroupSearchAttribute != nil {

		// binding items for group_search_attribute
		joinedGroupSearchAttribute := o.bindParamGroupSearchAttribute(reg)

		// form array param group_search_attribute
		if err := r.SetFormParam("group_search_attribute", joinedGroupSearchAttribute...); err != nil {
			return err
		}
	}

	if o.ID != nil {

		// form param id
		var frID string
		if o.ID != nil {
			frID = *o.ID
		}
		fID := frID
		if fID != "" {
			if err := r.SetFormParam("id", fID); err != nil {
				return err
			}
		}
	}

	if o.LocalRole != nil {

		// form param local_role
		var frLocalRole string
		if o.LocalRole != nil {
			frLocalRole = *o.LocalRole
		}
		fLocalRole := frLocalRole
		if fLocalRole != "" {
			if err := r.SetFormParam("local_role", fLocalRole); err != nil {
				return err
			}
		}
	}

	if o.Name != nil {

		// form param name
		var frName string
		if o.Name != nil {
			frName = *o.Name
		}
		fName := frName
		if fName != "" {
			if err := r.SetFormParam("name", fName); err != nil {
				return err
			}
		}
	}

	// form param path
	frPath := o.Path
	fPath := frPath
	if fPath != "" {
		if err := r.SetFormParam("path", fPath); err != nil {
			return err
		}
	}

	if o.RootDn != nil {

		// form param root_dn
		var frRootDn string
		if o.RootDn != nil {
			frRootDn = *o.RootDn
		}
		fRootDn := frRootDn
		if fRootDn != "" {
			if err := r.SetFormParam("root_dn", fRootDn); err != nil {
				return err
			}
		}
	}

	if o.UserFilter != nil {

		// form param user_filter
		var frUserFilter string
		if o.UserFilter != nil {
			frUserFilter = *o.UserFilter
		}
		fUserFilter := frUserFilter
		if fUserFilter != "" {
			if err := r.SetFormParam("user_filter", fUserFilter); err != nil {
				return err
			}
		}
	}

	if o.UserSearchAttribute != nil {

		// form param user_search_attribute
		var frUserSearchAttribute string
		if o.UserSearchAttribute != nil {
			frUserSearchAttribute = *o.UserSearchAttribute
		}
		fUserSearchAttribute := frUserSearchAttribute
		if fUserSearchAttribute != "" {
			if err := r.SetFormParam("user_search_attribute", fUserSearchAttribute); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamPostAPIV1AuthLdapConfigs binds the parameter group_search_attribute
func (o *PostAPIV1AuthLdapConfigsParams) bindParamGroupSearchAttribute(formats strfmt.Registry) []string {
	groupSearchAttributeIR := o.GroupSearchAttribute

	var groupSearchAttributeIC []string
	for _, groupSearchAttributeIIR := range groupSearchAttributeIR { // explode []string

		groupSearchAttributeIIV := groupSearchAttributeIIR // string as string
		groupSearchAttributeIC = append(groupSearchAttributeIC, groupSearchAttributeIIV)
	}

	// items.CollectionFormat: "csv"
	groupSearchAttributeIS := swag.JoinByFormat(groupSearchAttributeIC, "csv")

	return groupSearchAttributeIS
}
