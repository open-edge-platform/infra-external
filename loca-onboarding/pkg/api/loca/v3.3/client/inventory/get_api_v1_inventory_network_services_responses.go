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

// GetAPIV1InventoryNetworkServicesReader is a Reader for the GetAPIV1InventoryNetworkServices structure.
type GetAPIV1InventoryNetworkServicesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1InventoryNetworkServicesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1InventoryNetworkServicesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1InventoryNetworkServicesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1InventoryNetworkServicesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1InventoryNetworkServicesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/inventory/network-services] GetAPIV1InventoryNetworkServices", response, response.Code())
	}
}

// NewGetAPIV1InventoryNetworkServicesOK creates a GetAPIV1InventoryNetworkServicesOK with default headers values
func NewGetAPIV1InventoryNetworkServicesOK() *GetAPIV1InventoryNetworkServicesOK {
	return &GetAPIV1InventoryNetworkServicesOK{}
}

/*
GetAPIV1InventoryNetworkServicesOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1InventoryNetworkServicesOK struct {
	Payload *model.DtoNetworkServiceListResponse
}

// IsSuccess returns true when this get Api v1 inventory network services o k response has a 2xx status code
func (o *GetAPIV1InventoryNetworkServicesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 inventory network services o k response has a 3xx status code
func (o *GetAPIV1InventoryNetworkServicesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory network services o k response has a 4xx status code
func (o *GetAPIV1InventoryNetworkServicesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory network services o k response has a 5xx status code
func (o *GetAPIV1InventoryNetworkServicesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory network services o k response a status code equal to that given
func (o *GetAPIV1InventoryNetworkServicesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 inventory network services o k response
func (o *GetAPIV1InventoryNetworkServicesOK) Code() int {
	return 200
}

func (o *GetAPIV1InventoryNetworkServicesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesOK %s", 200, payload)
}

func (o *GetAPIV1InventoryNetworkServicesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesOK %s", 200, payload)
}

func (o *GetAPIV1InventoryNetworkServicesOK) GetPayload() *model.DtoNetworkServiceListResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryNetworkServicesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoNetworkServiceListResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryNetworkServicesBadRequest creates a GetAPIV1InventoryNetworkServicesBadRequest with default headers values
func NewGetAPIV1InventoryNetworkServicesBadRequest() *GetAPIV1InventoryNetworkServicesBadRequest {
	return &GetAPIV1InventoryNetworkServicesBadRequest{}
}

/*
GetAPIV1InventoryNetworkServicesBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1InventoryNetworkServicesBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory network services bad request response has a 2xx status code
func (o *GetAPIV1InventoryNetworkServicesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory network services bad request response has a 3xx status code
func (o *GetAPIV1InventoryNetworkServicesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory network services bad request response has a 4xx status code
func (o *GetAPIV1InventoryNetworkServicesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory network services bad request response has a 5xx status code
func (o *GetAPIV1InventoryNetworkServicesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory network services bad request response a status code equal to that given
func (o *GetAPIV1InventoryNetworkServicesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 inventory network services bad request response
func (o *GetAPIV1InventoryNetworkServicesBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1InventoryNetworkServicesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventoryNetworkServicesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventoryNetworkServicesBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryNetworkServicesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryNetworkServicesUnauthorized creates a GetAPIV1InventoryNetworkServicesUnauthorized with default headers values
func NewGetAPIV1InventoryNetworkServicesUnauthorized() *GetAPIV1InventoryNetworkServicesUnauthorized {
	return &GetAPIV1InventoryNetworkServicesUnauthorized{}
}

/*
GetAPIV1InventoryNetworkServicesUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1InventoryNetworkServicesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory network services unauthorized response has a 2xx status code
func (o *GetAPIV1InventoryNetworkServicesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory network services unauthorized response has a 3xx status code
func (o *GetAPIV1InventoryNetworkServicesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory network services unauthorized response has a 4xx status code
func (o *GetAPIV1InventoryNetworkServicesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory network services unauthorized response has a 5xx status code
func (o *GetAPIV1InventoryNetworkServicesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory network services unauthorized response a status code equal to that given
func (o *GetAPIV1InventoryNetworkServicesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 inventory network services unauthorized response
func (o *GetAPIV1InventoryNetworkServicesUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1InventoryNetworkServicesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventoryNetworkServicesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventoryNetworkServicesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryNetworkServicesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryNetworkServicesInternalServerError creates a GetAPIV1InventoryNetworkServicesInternalServerError with default headers values
func NewGetAPIV1InventoryNetworkServicesInternalServerError() *GetAPIV1InventoryNetworkServicesInternalServerError {
	return &GetAPIV1InventoryNetworkServicesInternalServerError{}
}

/*
GetAPIV1InventoryNetworkServicesInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1InventoryNetworkServicesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory network services internal server error response has a 2xx status code
func (o *GetAPIV1InventoryNetworkServicesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory network services internal server error response has a 3xx status code
func (o *GetAPIV1InventoryNetworkServicesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory network services internal server error response has a 4xx status code
func (o *GetAPIV1InventoryNetworkServicesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory network services internal server error response has a 5xx status code
func (o *GetAPIV1InventoryNetworkServicesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 inventory network services internal server error response a status code equal to that given
func (o *GetAPIV1InventoryNetworkServicesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 inventory network services internal server error response
func (o *GetAPIV1InventoryNetworkServicesInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1InventoryNetworkServicesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventoryNetworkServicesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/network-services][%d] getApiV1InventoryNetworkServicesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventoryNetworkServicesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryNetworkServicesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
