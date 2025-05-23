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

// GetAPIV1InventorySitesReader is a Reader for the GetAPIV1InventorySites structure.
type GetAPIV1InventorySitesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1InventorySitesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1InventorySitesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1InventorySitesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1InventorySitesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1InventorySitesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/inventory/sites] GetAPIV1InventorySites", response, response.Code())
	}
}

// NewGetAPIV1InventorySitesOK creates a GetAPIV1InventorySitesOK with default headers values
func NewGetAPIV1InventorySitesOK() *GetAPIV1InventorySitesOK {
	return &GetAPIV1InventorySitesOK{}
}

/*
GetAPIV1InventorySitesOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1InventorySitesOK struct {
	Payload *model.DtoSitesQueryResponse
}

// IsSuccess returns true when this get Api v1 inventory sites o k response has a 2xx status code
func (o *GetAPIV1InventorySitesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 inventory sites o k response has a 3xx status code
func (o *GetAPIV1InventorySitesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites o k response has a 4xx status code
func (o *GetAPIV1InventorySitesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory sites o k response has a 5xx status code
func (o *GetAPIV1InventorySitesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory sites o k response a status code equal to that given
func (o *GetAPIV1InventorySitesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 inventory sites o k response
func (o *GetAPIV1InventorySitesOK) Code() int {
	return 200
}

func (o *GetAPIV1InventorySitesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesOK %s", 200, payload)
}

func (o *GetAPIV1InventorySitesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesOK %s", 200, payload)
}

func (o *GetAPIV1InventorySitesOK) GetPayload() *model.DtoSitesQueryResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoSitesQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventorySitesBadRequest creates a GetAPIV1InventorySitesBadRequest with default headers values
func NewGetAPIV1InventorySitesBadRequest() *GetAPIV1InventorySitesBadRequest {
	return &GetAPIV1InventorySitesBadRequest{}
}

/*
GetAPIV1InventorySitesBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1InventorySitesBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory sites bad request response has a 2xx status code
func (o *GetAPIV1InventorySitesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory sites bad request response has a 3xx status code
func (o *GetAPIV1InventorySitesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites bad request response has a 4xx status code
func (o *GetAPIV1InventorySitesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory sites bad request response has a 5xx status code
func (o *GetAPIV1InventorySitesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory sites bad request response a status code equal to that given
func (o *GetAPIV1InventorySitesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 inventory sites bad request response
func (o *GetAPIV1InventorySitesBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1InventorySitesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventorySitesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventorySitesBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventorySitesUnauthorized creates a GetAPIV1InventorySitesUnauthorized with default headers values
func NewGetAPIV1InventorySitesUnauthorized() *GetAPIV1InventorySitesUnauthorized {
	return &GetAPIV1InventorySitesUnauthorized{}
}

/*
GetAPIV1InventorySitesUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1InventorySitesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory sites unauthorized response has a 2xx status code
func (o *GetAPIV1InventorySitesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory sites unauthorized response has a 3xx status code
func (o *GetAPIV1InventorySitesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites unauthorized response has a 4xx status code
func (o *GetAPIV1InventorySitesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory sites unauthorized response has a 5xx status code
func (o *GetAPIV1InventorySitesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory sites unauthorized response a status code equal to that given
func (o *GetAPIV1InventorySitesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 inventory sites unauthorized response
func (o *GetAPIV1InventorySitesUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1InventorySitesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventorySitesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventorySitesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventorySitesInternalServerError creates a GetAPIV1InventorySitesInternalServerError with default headers values
func NewGetAPIV1InventorySitesInternalServerError() *GetAPIV1InventorySitesInternalServerError {
	return &GetAPIV1InventorySitesInternalServerError{}
}

/*
GetAPIV1InventorySitesInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1InventorySitesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory sites internal server error response has a 2xx status code
func (o *GetAPIV1InventorySitesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory sites internal server error response has a 3xx status code
func (o *GetAPIV1InventorySitesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites internal server error response has a 4xx status code
func (o *GetAPIV1InventorySitesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory sites internal server error response has a 5xx status code
func (o *GetAPIV1InventorySitesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 inventory sites internal server error response a status code equal to that given
func (o *GetAPIV1InventorySitesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 inventory sites internal server error response
func (o *GetAPIV1InventorySitesInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1InventorySitesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventorySitesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites][%d] getApiV1InventorySitesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventorySitesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
