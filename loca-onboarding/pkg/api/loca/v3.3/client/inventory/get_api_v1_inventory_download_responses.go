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

// GetAPIV1InventoryDownloadReader is a Reader for the GetAPIV1InventoryDownload structure.
type GetAPIV1InventoryDownloadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1InventoryDownloadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1InventoryDownloadOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1InventoryDownloadBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1InventoryDownloadUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1InventoryDownloadInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/inventory/download] GetAPIV1InventoryDownload", response, response.Code())
	}
}

// NewGetAPIV1InventoryDownloadOK creates a GetAPIV1InventoryDownloadOK with default headers values
func NewGetAPIV1InventoryDownloadOK() *GetAPIV1InventoryDownloadOK {
	return &GetAPIV1InventoryDownloadOK{}
}

/*
GetAPIV1InventoryDownloadOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1InventoryDownloadOK struct {
	Payload interface{}
}

// IsSuccess returns true when this get Api v1 inventory download o k response has a 2xx status code
func (o *GetAPIV1InventoryDownloadOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 inventory download o k response has a 3xx status code
func (o *GetAPIV1InventoryDownloadOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory download o k response has a 4xx status code
func (o *GetAPIV1InventoryDownloadOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory download o k response has a 5xx status code
func (o *GetAPIV1InventoryDownloadOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory download o k response a status code equal to that given
func (o *GetAPIV1InventoryDownloadOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 inventory download o k response
func (o *GetAPIV1InventoryDownloadOK) Code() int {
	return 200
}

func (o *GetAPIV1InventoryDownloadOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadOK %s", 200, payload)
}

func (o *GetAPIV1InventoryDownloadOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadOK %s", 200, payload)
}

func (o *GetAPIV1InventoryDownloadOK) GetPayload() interface{} {
	return o.Payload
}

func (o *GetAPIV1InventoryDownloadOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryDownloadBadRequest creates a GetAPIV1InventoryDownloadBadRequest with default headers values
func NewGetAPIV1InventoryDownloadBadRequest() *GetAPIV1InventoryDownloadBadRequest {
	return &GetAPIV1InventoryDownloadBadRequest{}
}

/*
GetAPIV1InventoryDownloadBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1InventoryDownloadBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory download bad request response has a 2xx status code
func (o *GetAPIV1InventoryDownloadBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory download bad request response has a 3xx status code
func (o *GetAPIV1InventoryDownloadBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory download bad request response has a 4xx status code
func (o *GetAPIV1InventoryDownloadBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory download bad request response has a 5xx status code
func (o *GetAPIV1InventoryDownloadBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory download bad request response a status code equal to that given
func (o *GetAPIV1InventoryDownloadBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 inventory download bad request response
func (o *GetAPIV1InventoryDownloadBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1InventoryDownloadBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventoryDownloadBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadBadRequest %s", 400, payload)
}

func (o *GetAPIV1InventoryDownloadBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryDownloadBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryDownloadUnauthorized creates a GetAPIV1InventoryDownloadUnauthorized with default headers values
func NewGetAPIV1InventoryDownloadUnauthorized() *GetAPIV1InventoryDownloadUnauthorized {
	return &GetAPIV1InventoryDownloadUnauthorized{}
}

/*
GetAPIV1InventoryDownloadUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1InventoryDownloadUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory download unauthorized response has a 2xx status code
func (o *GetAPIV1InventoryDownloadUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory download unauthorized response has a 3xx status code
func (o *GetAPIV1InventoryDownloadUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory download unauthorized response has a 4xx status code
func (o *GetAPIV1InventoryDownloadUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory download unauthorized response has a 5xx status code
func (o *GetAPIV1InventoryDownloadUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory download unauthorized response a status code equal to that given
func (o *GetAPIV1InventoryDownloadUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 inventory download unauthorized response
func (o *GetAPIV1InventoryDownloadUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1InventoryDownloadUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventoryDownloadUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventoryDownloadUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryDownloadUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventoryDownloadInternalServerError creates a GetAPIV1InventoryDownloadInternalServerError with default headers values
func NewGetAPIV1InventoryDownloadInternalServerError() *GetAPIV1InventoryDownloadInternalServerError {
	return &GetAPIV1InventoryDownloadInternalServerError{}
}

/*
GetAPIV1InventoryDownloadInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1InventoryDownloadInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory download internal server error response has a 2xx status code
func (o *GetAPIV1InventoryDownloadInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory download internal server error response has a 3xx status code
func (o *GetAPIV1InventoryDownloadInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory download internal server error response has a 4xx status code
func (o *GetAPIV1InventoryDownloadInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory download internal server error response has a 5xx status code
func (o *GetAPIV1InventoryDownloadInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 inventory download internal server error response a status code equal to that given
func (o *GetAPIV1InventoryDownloadInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 inventory download internal server error response
func (o *GetAPIV1InventoryDownloadInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1InventoryDownloadInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventoryDownloadInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/download][%d] getApiV1InventoryDownloadInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventoryDownloadInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventoryDownloadInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
