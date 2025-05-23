// Code generated by go-swagger; DO NOT EDIT.

package plugins

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new plugins API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new plugins API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new plugins API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for plugins API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetAPIV1Plugins(params *GetAPIV1PluginsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsOK, error)

	GetAPIV1PluginsFlavors(params *GetAPIV1PluginsFlavorsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsFlavorsOK, error)

	GetAPIV1PluginsFlavorsID(params *GetAPIV1PluginsFlavorsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsFlavorsIDOK, error)

	GetAPIV1PluginsID(params *GetAPIV1PluginsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsIDOK, error)

	GetAPIV1PluginsTemplatesID(params *GetAPIV1PluginsTemplatesIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsTemplatesIDOK, error)

	PostAPIV1Plugins(params *PostAPIV1PluginsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAPIV1PluginsOK, error)

	PostAPIV1PluginsDelete(params *PostAPIV1PluginsDeleteParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAPIV1PluginsDeleteOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetAPIV1Plugins queries plugins
*/
func (a *Client) GetAPIV1Plugins(params *GetAPIV1PluginsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAPIV1PluginsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAPIV1Plugins",
		Method:             "GET",
		PathPattern:        "/api/v1/plugins",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAPIV1PluginsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAPIV1PluginsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAPIV1Plugins: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAPIV1PluginsFlavors retrieves all available flavors that are filtered by license
*/
func (a *Client) GetAPIV1PluginsFlavors(params *GetAPIV1PluginsFlavorsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsFlavorsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAPIV1PluginsFlavorsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAPIV1PluginsFlavors",
		Method:             "GET",
		PathPattern:        "/api/v1/plugins/flavors",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAPIV1PluginsFlavorsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAPIV1PluginsFlavorsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAPIV1PluginsFlavors: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAPIV1PluginsFlavorsID retrieves all flavors current l o c a supported
*/
func (a *Client) GetAPIV1PluginsFlavorsID(params *GetAPIV1PluginsFlavorsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsFlavorsIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAPIV1PluginsFlavorsIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAPIV1PluginsFlavorsID",
		Method:             "GET",
		PathPattern:        "/api/v1/plugins/flavors/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAPIV1PluginsFlavorsIDReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAPIV1PluginsFlavorsIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAPIV1PluginsFlavorsID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAPIV1PluginsID queries plugin by id
*/
func (a *Client) GetAPIV1PluginsID(params *GetAPIV1PluginsIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAPIV1PluginsIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAPIV1PluginsID",
		Method:             "GET",
		PathPattern:        "/api/v1/plugins/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAPIV1PluginsIDReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAPIV1PluginsIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAPIV1PluginsID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetAPIV1PluginsTemplatesID gets the template editing definition
*/
func (a *Client) GetAPIV1PluginsTemplatesID(params *GetAPIV1PluginsTemplatesIDParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIV1PluginsTemplatesIDOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAPIV1PluginsTemplatesIDParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetAPIV1PluginsTemplatesID",
		Method:             "GET",
		PathPattern:        "/api/v1/plugins/templates/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAPIV1PluginsTemplatesIDReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAPIV1PluginsTemplatesIDOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetAPIV1PluginsTemplatesID: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PostAPIV1Plugins enables a plugin
*/
func (a *Client) PostAPIV1Plugins(params *PostAPIV1PluginsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAPIV1PluginsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostAPIV1PluginsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostAPIV1Plugins",
		Method:             "POST",
		PathPattern:        "/api/v1/plugins",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostAPIV1PluginsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostAPIV1PluginsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostAPIV1Plugins: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PostAPIV1PluginsDelete removes a plugin
*/
func (a *Client) PostAPIV1PluginsDelete(params *PostAPIV1PluginsDeleteParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PostAPIV1PluginsDeleteOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPostAPIV1PluginsDeleteParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PostAPIV1PluginsDelete",
		Method:             "POST",
		PathPattern:        "/api/v1/plugins/delete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PostAPIV1PluginsDeleteReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PostAPIV1PluginsDeleteOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PostAPIV1PluginsDelete: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
