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
	"github.com/go-openapi/swag"
)

// NewGetAPIV1InventoryCloudServicesParams creates a new GetAPIV1InventoryCloudServicesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1InventoryCloudServicesParams() *GetAPIV1InventoryCloudServicesParams {
	return &GetAPIV1InventoryCloudServicesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1InventoryCloudServicesParamsWithTimeout creates a new GetAPIV1InventoryCloudServicesParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1InventoryCloudServicesParamsWithTimeout(timeout time.Duration) *GetAPIV1InventoryCloudServicesParams {
	return &GetAPIV1InventoryCloudServicesParams{
		timeout: timeout,
	}
}

// NewGetAPIV1InventoryCloudServicesParamsWithContext creates a new GetAPIV1InventoryCloudServicesParams object
// with the ability to set a context for a request.
func NewGetAPIV1InventoryCloudServicesParamsWithContext(ctx context.Context) *GetAPIV1InventoryCloudServicesParams {
	return &GetAPIV1InventoryCloudServicesParams{
		Context: ctx,
	}
}

// NewGetAPIV1InventoryCloudServicesParamsWithHTTPClient creates a new GetAPIV1InventoryCloudServicesParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1InventoryCloudServicesParamsWithHTTPClient(client *http.Client) *GetAPIV1InventoryCloudServicesParams {
	return &GetAPIV1InventoryCloudServicesParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1InventoryCloudServicesParams contains all the parameters to send to the API endpoint

	for the get API v1 inventory cloud services operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1InventoryCloudServicesParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* ConnectionCheck.

	   filter by connectionCheck
	*/
	ConnectionCheck *bool

	/* FilterContains.

	   Returns data that contains a specific pattern. Within the same filter query, data matches the query if the value of any one of the specified attributes contains any one of the specified patterns. the following example will return data which city contains shzj001 or shzj002, or county contains shzj001 or shzj002, example: [{"attributes":"city,country","values":"shzj001,shzj002"}]

	   Default: "[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]"
	*/
	FilterContains *string

	/* FilterEquals.

	   Returns data that exactly matches a specific pattern. Within the same filter query, data matches the query if the value of any one of the specified attributes exactly matches any one of the specified patterns. the following example will return data which city exactly matches shzj001 or shzj002, or county exactly matches shzj001 or shzj002, example: [{"attributes":"city,country","values":"shzj001,shzj002"}]

	   Default: "[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]"
	*/
	FilterEquals *string

	/* FilterNotEquals.

	   Returns data that not matches a specific pattern. Within the same filter query, data matches the query if the value of any one of the specified attributes exactly matches any one of the specified patterns. the following example will return data which city not match shzj001 or shzj002, or county not match shzj001 or shzj002, example: [{"attributes":"city,country","values":"shzj001,shzj002"}]

	   Default: "[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]"
	*/
	FilterNotEquals *string

	/* Limit.

	    , example: 10

	   Default: 10
	*/
	Limit *int64

	/* Name.

	   filter by name
	*/
	Name *string

	/* Offset.

	   , example: 0
	*/
	Offset *int64

	/* ParentService.

	   filter by parentService
	*/
	ParentService *string

	/* PlatformType.

	   filter by platformType
	*/
	PlatformType *string

	/* Protocol.

	   filter by protocol
	*/
	Protocol *string

	/* Role.

	   filter by role
	*/
	Role *string

	/* ServiceAddress.

	   filter by serviceAddress
	*/
	ServiceAddress *string

	/* SiteAssociation.

	   filter by siteAssociation
	*/
	SiteAssociation *string

	/* Sort.

	   returns data that sorted by specific rules. The following example sorts data first by created_time in descending order and then by id in ascending order., example: ["created_time,desc","id,asc"]

	   Default: "[\"created_time,desc\",\"id,asc\"]"
	*/
	Sort *string

	/* Status.

	   filter by status
	*/
	Status *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 inventory cloud services params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryCloudServicesParams) WithDefaults() *GetAPIV1InventoryCloudServicesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 inventory cloud services params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryCloudServicesParams) SetDefaults() {
	var (
		filterContainsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		filterEqualsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		filterNotEqualsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		limitDefault = int64(10)

		offsetDefault = int64(0)

		sortDefault = string("[\"created_time,desc\",\"id,asc\"]")
	)

	val := GetAPIV1InventoryCloudServicesParams{
		FilterContains:  &filterContainsDefault,
		FilterEquals:    &filterEqualsDefault,
		FilterNotEquals: &filterNotEqualsDefault,
		Limit:           &limitDefault,
		Offset:          &offsetDefault,
		Sort:            &sortDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithTimeout(timeout time.Duration) *GetAPIV1InventoryCloudServicesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithContext(ctx context.Context) *GetAPIV1InventoryCloudServicesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithHTTPClient(client *http.Client) *GetAPIV1InventoryCloudServicesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithAuthorization(authorization string) *GetAPIV1InventoryCloudServicesParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithConnectionCheck adds the connectionCheck to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithConnectionCheck(connectionCheck *bool) *GetAPIV1InventoryCloudServicesParams {
	o.SetConnectionCheck(connectionCheck)
	return o
}

// SetConnectionCheck adds the connectionCheck to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetConnectionCheck(connectionCheck *bool) {
	o.ConnectionCheck = connectionCheck
}

// WithFilterContains adds the filterContains to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithFilterContains(filterContains *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetFilterContains(filterContains)
	return o
}

// SetFilterContains adds the filterContains to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetFilterContains(filterContains *string) {
	o.FilterContains = filterContains
}

// WithFilterEquals adds the filterEquals to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithFilterEquals(filterEquals *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetFilterEquals(filterEquals)
	return o
}

// SetFilterEquals adds the filterEquals to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetFilterEquals(filterEquals *string) {
	o.FilterEquals = filterEquals
}

// WithFilterNotEquals adds the filterNotEquals to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithFilterNotEquals(filterNotEquals *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetFilterNotEquals(filterNotEquals)
	return o
}

// SetFilterNotEquals adds the filterNotEquals to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetFilterNotEquals(filterNotEquals *string) {
	o.FilterNotEquals = filterNotEquals
}

// WithLimit adds the limit to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithLimit(limit *int64) *GetAPIV1InventoryCloudServicesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithName adds the name to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithName(name *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetName(name *string) {
	o.Name = name
}

// WithOffset adds the offset to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithOffset(offset *int64) *GetAPIV1InventoryCloudServicesParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithParentService adds the parentService to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithParentService(parentService *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetParentService(parentService)
	return o
}

// SetParentService adds the parentService to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetParentService(parentService *string) {
	o.ParentService = parentService
}

// WithPlatformType adds the platformType to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithPlatformType(platformType *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetPlatformType(platformType)
	return o
}

// SetPlatformType adds the platformType to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetPlatformType(platformType *string) {
	o.PlatformType = platformType
}

// WithProtocol adds the protocol to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithProtocol(protocol *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetProtocol(protocol)
	return o
}

// SetProtocol adds the protocol to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetProtocol(protocol *string) {
	o.Protocol = protocol
}

// WithRole adds the role to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithRole(role *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetRole(role)
	return o
}

// SetRole adds the role to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetRole(role *string) {
	o.Role = role
}

// WithServiceAddress adds the serviceAddress to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithServiceAddress(serviceAddress *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetServiceAddress(serviceAddress)
	return o
}

// SetServiceAddress adds the serviceAddress to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetServiceAddress(serviceAddress *string) {
	o.ServiceAddress = serviceAddress
}

// WithSiteAssociation adds the siteAssociation to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithSiteAssociation(siteAssociation *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetSiteAssociation(siteAssociation)
	return o
}

// SetSiteAssociation adds the siteAssociation to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetSiteAssociation(siteAssociation *string) {
	o.SiteAssociation = siteAssociation
}

// WithSort adds the sort to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithSort(sort *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithStatus adds the status to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) WithStatus(status *string) *GetAPIV1InventoryCloudServicesParams {
	o.SetStatus(status)
	return o
}

// SetStatus adds the status to the get API v1 inventory cloud services params
func (o *GetAPIV1InventoryCloudServicesParams) SetStatus(status *string) {
	o.Status = status
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1InventoryCloudServicesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	if o.ConnectionCheck != nil {

		// query param connectionCheck
		var qrConnectionCheck bool

		if o.ConnectionCheck != nil {
			qrConnectionCheck = *o.ConnectionCheck
		}
		qConnectionCheck := swag.FormatBool(qrConnectionCheck)
		if qConnectionCheck != "" {

			if err := r.SetQueryParam("connectionCheck", qConnectionCheck); err != nil {
				return err
			}
		}
	}

	if o.FilterContains != nil {

		// query param filterContains
		var qrFilterContains string

		if o.FilterContains != nil {
			qrFilterContains = *o.FilterContains
		}
		qFilterContains := qrFilterContains
		if qFilterContains != "" {

			if err := r.SetQueryParam("filterContains", qFilterContains); err != nil {
				return err
			}
		}
	}

	if o.FilterEquals != nil {

		// query param filterEquals
		var qrFilterEquals string

		if o.FilterEquals != nil {
			qrFilterEquals = *o.FilterEquals
		}
		qFilterEquals := qrFilterEquals
		if qFilterEquals != "" {

			if err := r.SetQueryParam("filterEquals", qFilterEquals); err != nil {
				return err
			}
		}
	}

	if o.FilterNotEquals != nil {

		// query param filterNotEquals
		var qrFilterNotEquals string

		if o.FilterNotEquals != nil {
			qrFilterNotEquals = *o.FilterNotEquals
		}
		qFilterNotEquals := qrFilterNotEquals
		if qFilterNotEquals != "" {

			if err := r.SetQueryParam("filterNotEquals", qFilterNotEquals); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Name != nil {

		// query param name
		var qrName string

		if o.Name != nil {
			qrName = *o.Name
		}
		qName := qrName
		if qName != "" {

			if err := r.SetQueryParam("name", qName); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int64

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt64(qrOffset)
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if o.ParentService != nil {

		// query param parentService
		var qrParentService string

		if o.ParentService != nil {
			qrParentService = *o.ParentService
		}
		qParentService := qrParentService
		if qParentService != "" {

			if err := r.SetQueryParam("parentService", qParentService); err != nil {
				return err
			}
		}
	}

	if o.PlatformType != nil {

		// query param platformType
		var qrPlatformType string

		if o.PlatformType != nil {
			qrPlatformType = *o.PlatformType
		}
		qPlatformType := qrPlatformType
		if qPlatformType != "" {

			if err := r.SetQueryParam("platformType", qPlatformType); err != nil {
				return err
			}
		}
	}

	if o.Protocol != nil {

		// query param protocol
		var qrProtocol string

		if o.Protocol != nil {
			qrProtocol = *o.Protocol
		}
		qProtocol := qrProtocol
		if qProtocol != "" {

			if err := r.SetQueryParam("protocol", qProtocol); err != nil {
				return err
			}
		}
	}

	if o.Role != nil {

		// query param role
		var qrRole string

		if o.Role != nil {
			qrRole = *o.Role
		}
		qRole := qrRole
		if qRole != "" {

			if err := r.SetQueryParam("role", qRole); err != nil {
				return err
			}
		}
	}

	if o.ServiceAddress != nil {

		// query param serviceAddress
		var qrServiceAddress string

		if o.ServiceAddress != nil {
			qrServiceAddress = *o.ServiceAddress
		}
		qServiceAddress := qrServiceAddress
		if qServiceAddress != "" {

			if err := r.SetQueryParam("serviceAddress", qServiceAddress); err != nil {
				return err
			}
		}
	}

	if o.SiteAssociation != nil {

		// query param siteAssociation
		var qrSiteAssociation string

		if o.SiteAssociation != nil {
			qrSiteAssociation = *o.SiteAssociation
		}
		qSiteAssociation := qrSiteAssociation
		if qSiteAssociation != "" {

			if err := r.SetQueryParam("siteAssociation", qSiteAssociation); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if o.Status != nil {

		// query param status
		var qrStatus string

		if o.Status != nil {
			qrStatus = *o.Status
		}
		qStatus := qrStatus
		if qStatus != "" {

			if err := r.SetQueryParam("status", qStatus); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
