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

// NewGetAPIV1InventorySitesParams creates a new GetAPIV1InventorySitesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIV1InventorySitesParams() *GetAPIV1InventorySitesParams {
	return &GetAPIV1InventorySitesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIV1InventorySitesParamsWithTimeout creates a new GetAPIV1InventorySitesParams object
// with the ability to set a timeout on a request.
func NewGetAPIV1InventorySitesParamsWithTimeout(timeout time.Duration) *GetAPIV1InventorySitesParams {
	return &GetAPIV1InventorySitesParams{
		timeout: timeout,
	}
}

// NewGetAPIV1InventorySitesParamsWithContext creates a new GetAPIV1InventorySitesParams object
// with the ability to set a context for a request.
func NewGetAPIV1InventorySitesParamsWithContext(ctx context.Context) *GetAPIV1InventorySitesParams {
	return &GetAPIV1InventorySitesParams{
		Context: ctx,
	}
}

// NewGetAPIV1InventorySitesParamsWithHTTPClient creates a new GetAPIV1InventorySitesParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIV1InventorySitesParamsWithHTTPClient(client *http.Client) *GetAPIV1InventorySitesParams {
	return &GetAPIV1InventorySitesParams{
		HTTPClient: client,
	}
}

/*
GetAPIV1InventorySitesParams contains all the parameters to send to the API endpoint

	for the get API v1 inventory sites operation.

	Typically these are written to a http.Request.
*/
type GetAPIV1InventorySitesParams struct {

	/* Authorization.

	   Bearer $token
	*/
	Authorization string

	/* City.

	   filter by city of site
	*/
	City *string

	/* CloudType.

	   filter by cloud type of site
	*/
	CloudType *string

	/* Cluster.

	   filter by cluster of site
	*/
	Cluster *string

	/* Country.

	   filter by country of site
	*/
	Country *string

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

	/* Geo.

	   filter by geo of site
	*/
	Geo *string

	/* Limit.

	    , example: 10

	   Default: 10
	*/
	Limit *int64

	/* Name.

	   filter by name of site
	*/
	Name *string

	/* Offset.

	   , example: 0
	*/
	Offset *int64

	/* Province.

	   filter by province of site
	*/
	Province *string

	/* SanityCheckStatus.

	   filter by sanity check status of site
	*/
	SanityCheckStatus *string

	/* SiteCode.

	   filter by site code
	*/
	SiteCode *string

	/* Sort.

	   returns data that sorted by specific rules. The following example sorts data first by created_time in descending order and then by id in ascending order., example: ["created_time,desc","id,asc"]

	   Default: "[\"created_time,desc\",\"id,asc\"]"
	*/
	Sort *string

	/* Status.

	   filter by status of site
	*/
	Status *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get API v1 inventory sites params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventorySitesParams) WithDefaults() *GetAPIV1InventorySitesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get API v1 inventory sites params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIV1InventorySitesParams) SetDefaults() {
	var (
		filterContainsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		filterEqualsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		filterNotEqualsDefault = string("[{\"attributes\":\"city,country\",\"values\":\"shzj001,shzj002\"}]")

		limitDefault = int64(10)

		offsetDefault = int64(0)

		sortDefault = string("[\"created_time,desc\",\"id,asc\"]")
	)

	val := GetAPIV1InventorySitesParams{
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

// WithTimeout adds the timeout to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithTimeout(timeout time.Duration) *GetAPIV1InventorySitesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithContext(ctx context.Context) *GetAPIV1InventorySitesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithHTTPClient(client *http.Client) *GetAPIV1InventorySitesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAuthorization adds the authorization to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithAuthorization(authorization string) *GetAPIV1InventorySitesParams {
	o.SetAuthorization(authorization)
	return o
}

// SetAuthorization adds the authorization to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetAuthorization(authorization string) {
	o.Authorization = authorization
}

// WithCity adds the city to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithCity(city *string) *GetAPIV1InventorySitesParams {
	o.SetCity(city)
	return o
}

// SetCity adds the city to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetCity(city *string) {
	o.City = city
}

// WithCloudType adds the cloudType to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithCloudType(cloudType *string) *GetAPIV1InventorySitesParams {
	o.SetCloudType(cloudType)
	return o
}

// SetCloudType adds the cloudType to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetCloudType(cloudType *string) {
	o.CloudType = cloudType
}

// WithCluster adds the cluster to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithCluster(cluster *string) *GetAPIV1InventorySitesParams {
	o.SetCluster(cluster)
	return o
}

// SetCluster adds the cluster to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetCluster(cluster *string) {
	o.Cluster = cluster
}

// WithCountry adds the country to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithCountry(country *string) *GetAPIV1InventorySitesParams {
	o.SetCountry(country)
	return o
}

// SetCountry adds the country to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetCountry(country *string) {
	o.Country = country
}

// WithFilterContains adds the filterContains to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithFilterContains(filterContains *string) *GetAPIV1InventorySitesParams {
	o.SetFilterContains(filterContains)
	return o
}

// SetFilterContains adds the filterContains to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetFilterContains(filterContains *string) {
	o.FilterContains = filterContains
}

// WithFilterEquals adds the filterEquals to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithFilterEquals(filterEquals *string) *GetAPIV1InventorySitesParams {
	o.SetFilterEquals(filterEquals)
	return o
}

// SetFilterEquals adds the filterEquals to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetFilterEquals(filterEquals *string) {
	o.FilterEquals = filterEquals
}

// WithFilterNotEquals adds the filterNotEquals to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithFilterNotEquals(filterNotEquals *string) *GetAPIV1InventorySitesParams {
	o.SetFilterNotEquals(filterNotEquals)
	return o
}

// SetFilterNotEquals adds the filterNotEquals to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetFilterNotEquals(filterNotEquals *string) {
	o.FilterNotEquals = filterNotEquals
}

// WithGeo adds the geo to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithGeo(geo *string) *GetAPIV1InventorySitesParams {
	o.SetGeo(geo)
	return o
}

// SetGeo adds the geo to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetGeo(geo *string) {
	o.Geo = geo
}

// WithLimit adds the limit to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithLimit(limit *int64) *GetAPIV1InventorySitesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithName adds the name to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithName(name *string) *GetAPIV1InventorySitesParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetName(name *string) {
	o.Name = name
}

// WithOffset adds the offset to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithOffset(offset *int64) *GetAPIV1InventorySitesParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetOffset(offset *int64) {
	o.Offset = offset
}

// WithProvince adds the province to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithProvince(province *string) *GetAPIV1InventorySitesParams {
	o.SetProvince(province)
	return o
}

// SetProvince adds the province to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetProvince(province *string) {
	o.Province = province
}

// WithSanityCheckStatus adds the sanityCheckStatus to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithSanityCheckStatus(sanityCheckStatus *string) *GetAPIV1InventorySitesParams {
	o.SetSanityCheckStatus(sanityCheckStatus)
	return o
}

// SetSanityCheckStatus adds the sanityCheckStatus to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetSanityCheckStatus(sanityCheckStatus *string) {
	o.SanityCheckStatus = sanityCheckStatus
}

// WithSiteCode adds the siteCode to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithSiteCode(siteCode *string) *GetAPIV1InventorySitesParams {
	o.SetSiteCode(siteCode)
	return o
}

// SetSiteCode adds the siteCode to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetSiteCode(siteCode *string) {
	o.SiteCode = siteCode
}

// WithSort adds the sort to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithSort(sort *string) *GetAPIV1InventorySitesParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithStatus adds the status to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) WithStatus(status *string) *GetAPIV1InventorySitesParams {
	o.SetStatus(status)
	return o
}

// SetStatus adds the status to the get API v1 inventory sites params
func (o *GetAPIV1InventorySitesParams) SetStatus(status *string) {
	o.Status = status
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIV1InventorySitesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// header param Authorization
	if err := r.SetHeaderParam("Authorization", o.Authorization); err != nil {
		return err
	}

	if o.City != nil {

		// query param city
		var qrCity string

		if o.City != nil {
			qrCity = *o.City
		}
		qCity := qrCity
		if qCity != "" {

			if err := r.SetQueryParam("city", qCity); err != nil {
				return err
			}
		}
	}

	if o.CloudType != nil {

		// query param cloudType
		var qrCloudType string

		if o.CloudType != nil {
			qrCloudType = *o.CloudType
		}
		qCloudType := qrCloudType
		if qCloudType != "" {

			if err := r.SetQueryParam("cloudType", qCloudType); err != nil {
				return err
			}
		}
	}

	if o.Cluster != nil {

		// query param cluster
		var qrCluster string

		if o.Cluster != nil {
			qrCluster = *o.Cluster
		}
		qCluster := qrCluster
		if qCluster != "" {

			if err := r.SetQueryParam("cluster", qCluster); err != nil {
				return err
			}
		}
	}

	if o.Country != nil {

		// query param country
		var qrCountry string

		if o.Country != nil {
			qrCountry = *o.Country
		}
		qCountry := qrCountry
		if qCountry != "" {

			if err := r.SetQueryParam("country", qCountry); err != nil {
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

	if o.Geo != nil {

		// query param geo
		var qrGeo string

		if o.Geo != nil {
			qrGeo = *o.Geo
		}
		qGeo := qrGeo
		if qGeo != "" {

			if err := r.SetQueryParam("geo", qGeo); err != nil {
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

	if o.Province != nil {

		// query param province
		var qrProvince string

		if o.Province != nil {
			qrProvince = *o.Province
		}
		qProvince := qrProvince
		if qProvince != "" {

			if err := r.SetQueryParam("province", qProvince); err != nil {
				return err
			}
		}
	}

	if o.SanityCheckStatus != nil {

		// query param sanityCheckStatus
		var qrSanityCheckStatus string

		if o.SanityCheckStatus != nil {
			qrSanityCheckStatus = *o.SanityCheckStatus
		}
		qSanityCheckStatus := qrSanityCheckStatus
		if qSanityCheckStatus != "" {

			if err := r.SetQueryParam("sanityCheckStatus", qSanityCheckStatus); err != nil {
				return err
			}
		}
	}

	if o.SiteCode != nil {

		// query param siteCode
		var qrSiteCode string

		if o.SiteCode != nil {
			qrSiteCode = *o.SiteCode
		}
		qSiteCode := qrSiteCode
		if qSiteCode != "" {

			if err := r.SetQueryParam("siteCode", qSiteCode); err != nil {
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
