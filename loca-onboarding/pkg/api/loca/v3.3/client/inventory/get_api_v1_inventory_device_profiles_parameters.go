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

// NewGetAPIV1InventoryDeviceProfilesParams creates a new GetAPIV1InventoryDeviceProfilesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1InventoryDeviceProfilesParams() *GetAPIV1InventoryDeviceProfilesParams {
	return &GetAPIV1InventoryDeviceProfilesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1InventoryDeviceProfilesParamsWithTimeout creates a new GetAPIV1InventoryDeviceProfilesParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1InventoryDeviceProfilesParamsWithTimeout(timeout time.Duration) *GetAPIV1InventoryDeviceProfilesParams {
	return &GetAPIV1InventoryDeviceProfilesParams{
		timeout: timeout,
	}
}

// NewGetAPIV1InventoryDeviceProfilesParamsWithContext creates a new GetAPIV1InventoryDeviceProfilesParams object
// with the ability to set a context for a request.
func NewGetAPIV1InventoryDeviceProfilesParamsWithContext(ctx context.Context) *GetAPIV1InventoryDeviceProfilesParams {
	return &GetAPIV1InventoryDeviceProfilesParams{
		Context: ctx,
	}
}

// NewGetAPIV1InventoryDeviceProfilesParamsWithHTTPClient creates a new GetAPIV1InventoryDeviceProfilesParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1InventoryDeviceProfilesParamsWithHTTPClient(client *http.Client) *GetAPIV1InventoryDeviceProfilesParams {
	return &GetAPIV1InventoryDeviceProfilesParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1InventoryDeviceProfilesParams contains all the parameters to send to the API endpoint

	for the get API v1 inventory device profiles operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1InventoryDeviceProfilesParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

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

	/* Flavor.

	   filter by flavor name
	*/
	Flavor *string

	/* Limit.

	    , example: 10

	   Default: 10
	*/
	Limit *int64

	/* Name.

	   filter by device profile name
	*/
	Name *string

	/* Offset.

	   , example: 0
	*/
	Offset *int64

	/* Sort.

	   returns data that sorted by specific rules. The following example sorts data first by created_time in descending order and then by id in ascending order., example: ["created_time,desc","id,asc"]

	   Default: "[\"created_time,desc\",\"id,asc\"]"
	*/
	Sort *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 inventory device profiles params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryDeviceProfilesParams) WithDefaults() *GetAPIV1InventoryDeviceProfilesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 inventory device profiles params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventoryDeviceProfilesParams) SetDefaults() {
	var (
		filterContainsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		filterEqualsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		filterNotEqualsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		limitDefault = int64(10)

		offsetDefault = int64(0)

		sortDefault = string("[\"created_time,desc\",\"id,asc\"]")
	)

	val := GetAPIV1InventoryDeviceProfilesParams{
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

// WithTimeout adds the timeout to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithTimeout(timeout time.Duration) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithContext(ctx context.Context) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithHTTPClient(client *http.Client) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithAuthorization(authorization string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithFilterContains adds the filterContains to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithFilterContains(filterContains *string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetFilterContains(filterContains)
	return o
}

// SetFilterContains adds the filterContains to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetFilterContains(filterContains *string) {
	o.FilterContains = filterContains
}

// WithFilterEquals adds the filterEquals to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithFilterEquals(filterEquals *string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetFilterEquals(filterEquals)
	return o
}

// SetFilterEquals adds the filterEquals to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetFilterEquals(filterEquals *string) {
	o.FilterEquals = filterEquals
}

// WithFilterNotEquals adds the filterNotEquals to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithFilterNotEquals(filterNotEquals *string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetFilterNotEquals(filterNotEquals)
	return o
}

// SetFilterNotEquals adds the filterNotEquals to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetFilterNotEquals(filterNotEquals *string) {
	o.FilterNotEquals = filterNotEquals
}

// WithFlavor adds the flavor to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithFlavor(flavor *string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetFlavor(flavor)
	return o
}

// SetFlavor adds the flavor to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetFlavor(flavor *string) {
	o.Flavor = flavor
}

// WithLimit adds the limit to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithLimit(limit *int64) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithName adds the name to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithName(name *string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetName(name *string) {
	o.Name = name
}

// WithOffset adds the offset to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithOffset(offset *int64) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithSort adds the sort to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) WithSort(sort *string) *GetAPIV1InventoryDeviceProfilesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get API v1 inventory device profiles params
func (o *GetAPIV1InventoryDeviceProfilesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1InventoryDeviceProfilesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
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

	if o.Flavor != nil {

		// query param flavor
		var qrFlavor string

		if o.Flavor != nil {
			qrFlavor = *o.Flavor
		}
		qFlavor := qrFlavor
		if qFlavor != "" {

			if err := r.SetQueryParam("flavor", qFlavor); err != nil {
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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
