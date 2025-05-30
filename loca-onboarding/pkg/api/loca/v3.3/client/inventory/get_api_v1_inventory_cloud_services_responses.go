// Code generated by go-swagger; DO NOT EDIT.

package inventory

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
)

// GetAPIV1InventoryCloudServicesReader is a Reader for the GetAPIV1InventoryCloudServices structure.
type GetAPIV1InventoryCloudServicesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1InventoryCloudServicesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1InventoryCloudServicesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1InventoryCloudServicesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1InventoryCloudServicesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1InventoryCloudServicesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/inventory/cloud-services] GetAPIV1InventoryCloudServices", response, response.Code())
	}
}

// NewGetAPIV1InventoryCloudServicesOK creates a GetAPIV1InventoryCloudServicesOK with default headers values
func NewGetAPIV1InventoryCloudServicesOK() *GetAPIV1InventoryCloudServicesOK {
	return &GetAPIV1InventoryCloudServicesOK{}
}

/*
GetAPIV1InventoryCloudServicesOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1InventoryCloudServicesOK struct {
	Payload *model.DtoCloudServiceListResponse
}

// IsSuccess returns true when this get Api v1 inventory cloud services o k response has a 2xx status code
func (o *GetAPIV1InventoryCloudServicesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 inventory cloud services o k response has a 3xx status code
func (o *GetAPIV1InventoryCloudServicesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory cloud services o k response has a 4xx status code
func (o *GetAPIV1InventoryCloudServicesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory cloud services o k response has a 5xx status code
func (o *GetAPIV1InventoryCloudServicesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory cloud services o k response a status code equal to that given
func (o *GetAPIV1InventoryCloudServicesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 inventory cloud services o k response
func (o *GetAPIV1InventoryCloudServicesOK) Code() int {
	return 200
}

func (o *GetAPIV1InventoryCloudServicesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesOK %s", 200, payload)
}

func (o *GetAPIV1InventoryCloudServicesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesOK %s", 200, payload)
}

func (o *GetAPIV1InventoryCloudServicesOK) GetPayload() *model.DtoCloudServiceListResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryCloudServicesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoCloudServiceListResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryCloudServicesBadRequest creates a GetAPIV1InventoryCloudServicesBadRequest with default headers values
func NewGetAPIV1InventoryCloudServicesBadRequest() *GetAPIV1InventoryCloudServicesBadRequest {
	return &GetAPIV1InventoryCloudServicesBadRequest{}
}

/*
GetAPIV1InventoryCloudServicesBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1InventoryCloudServicesBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory cloud services bad request response has a 2xx status code
func (o *GetAPIV1InventoryCloudServicesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory cloud services bad request response has a 3xx status code
func (o *GetAPIV1InventoryCloudServicesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory cloud services bad request response has a 4xx status code
func (o *GetAPIV1InventoryCloudServicesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory cloud services bad request response has a 5xx status code
func (o *GetAPIV1InventoryCloudServicesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory cloud services bad request response a status code equal to that given
func (o *GetAPIV1InventoryCloudServicesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 inventory cloud services bad request response
func (o *GetAPIV1InventoryCloudServicesBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1InventoryCloudServicesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventoryCloudServicesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventoryCloudServicesBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryCloudServicesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryCloudServicesUnauthorized creates a GetAPIV1InventoryCloudServicesUnauthorized with default headers values
func NewGetAPIV1InventoryCloudServicesUnauthorized() *GetAPIV1InventoryCloudServicesUnauthorized {
	return &GetAPIV1InventoryCloudServicesUnauthorized{}
}

/*
GetAPIV1InventoryCloudServicesUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1InventoryCloudServicesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory cloud services unauthorized response has a 2xx status code
func (o *GetAPIV1InventoryCloudServicesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory cloud services unauthorized response has a 3xx status code
func (o *GetAPIV1InventoryCloudServicesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory cloud services unauthorized response has a 4xx status code
func (o *GetAPIV1InventoryCloudServicesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory cloud services unauthorized response has a 5xx status code
func (o *GetAPIV1InventoryCloudServicesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory cloud services unauthorized response a status code equal to that given
func (o *GetAPIV1InventoryCloudServicesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 inventory cloud services unauthorized response
func (o *GetAPIV1InventoryCloudServicesUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1InventoryCloudServicesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventoryCloudServicesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventoryCloudServicesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryCloudServicesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryCloudServicesInternalServerError creates a GetAPIV1InventoryCloudServicesInternalServerError with default headers values
func NewGetAPIV1InventoryCloudServicesInternalServerError() *GetAPIV1InventoryCloudServicesInternalServerError {
	return &GetAPIV1InventoryCloudServicesInternalServerError{}
}

/*
GetAPIV1InventoryCloudServicesInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1InventoryCloudServicesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory cloud services internal server error response has a 2xx status code
func (o *GetAPIV1InventoryCloudServicesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory cloud services internal server error response has a 3xx status code
func (o *GetAPIV1InventoryCloudServicesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory cloud services internal server error response has a 4xx status code
func (o *GetAPIV1InventoryCloudServicesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory cloud services internal server error response has a 5xx status code
func (o *GetAPIV1InventoryCloudServicesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 inventory cloud services internal server error response a status code equal to that given
func (o *GetAPIV1InventoryCloudServicesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 inventory cloud services internal server error response
func (o *GetAPIV1InventoryCloudServicesInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1InventoryCloudServicesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventoryCloudServicesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/cloud-services][%d] getApiV1InventoryCloudServicesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventoryCloudServicesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryCloudServicesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
