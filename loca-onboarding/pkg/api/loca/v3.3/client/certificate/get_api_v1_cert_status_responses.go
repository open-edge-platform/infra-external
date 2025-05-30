// Code generated by go-swagger; DO NOT EDIT.

package certificate

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

// GetAPIV1CertStatusReader is a Reader for the GetAPIV1CertStatus structure.
type GetAPIV1CertStatusReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1CertStatusReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1CertStatusOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1CertStatusBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1CertStatusUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1CertStatusInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/cert/status] GetAPIV1CertStatus", response, response.Code())
	}
}

// NewGetAPIV1CertStatusOK creates a GetAPIV1CertStatusOK with default headers values
func NewGetAPIV1CertStatusOK() *GetAPIV1CertStatusOK {
	return &GetAPIV1CertStatusOK{}
}

/*
GetAPIV1CertStatusOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1CertStatusOK struct {
	Payload *model.DtoCertStatusResponse
}

// IsSuccess returns true when this get Api v1 cert status o k response has a 2xx status code
func (o *GetAPIV1CertStatusOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 cert status o k response has a 3xx status code
func (o *GetAPIV1CertStatusOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 cert status o k response has a 4xx status code
func (o *GetAPIV1CertStatusOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 cert status o k response has a 5xx status code
func (o *GetAPIV1CertStatusOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 cert status o k response a status code equal to that given
func (o *GetAPIV1CertStatusOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 cert status o k response
func (o *GetAPIV1CertStatusOK) Code() int {
	return 200
}

func (o *GetAPIV1CertStatusOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusOK %s", 200, payload)
}

func (o *GetAPIV1CertStatusOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusOK %s", 200, payload)
}

func (o *GetAPIV1CertStatusOK) GetPayload() *model.DtoCertStatusResponse {
	return o.Payload
}

func (o *GetAPIV1CertStatusOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoCertStatusResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1CertStatusBadRequest creates a GetAPIV1CertStatusBadRequest with default headers values
func NewGetAPIV1CertStatusBadRequest() *GetAPIV1CertStatusBadRequest {
	return &GetAPIV1CertStatusBadRequest{}
}

/*
GetAPIV1CertStatusBadRequest describes a response with status code 400, with default header values.

failure
*/
type GetAPIV1CertStatusBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 cert status bad request response has a 2xx status code
func (o *GetAPIV1CertStatusBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 cert status bad request response has a 3xx status code
func (o *GetAPIV1CertStatusBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 cert status bad request response has a 4xx status code
func (o *GetAPIV1CertStatusBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 cert status bad request response has a 5xx status code
func (o *GetAPIV1CertStatusBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 cert status bad request response a status code equal to that given
func (o *GetAPIV1CertStatusBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 cert status bad request response
func (o *GetAPIV1CertStatusBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1CertStatusBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusBadRequest %s", 400, payload)
}

func (o *GetAPIV1CertStatusBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusBadRequest %s", 400, payload)
}

func (o *GetAPIV1CertStatusBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1CertStatusBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1CertStatusUnauthorized creates a GetAPIV1CertStatusUnauthorized with default headers values
func NewGetAPIV1CertStatusUnauthorized() *GetAPIV1CertStatusUnauthorized {
	return &GetAPIV1CertStatusUnauthorized{}
}

/*
GetAPIV1CertStatusUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1CertStatusUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 cert status unauthorized response has a 2xx status code
func (o *GetAPIV1CertStatusUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 cert status unauthorized response has a 3xx status code
func (o *GetAPIV1CertStatusUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 cert status unauthorized response has a 4xx status code
func (o *GetAPIV1CertStatusUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 cert status unauthorized response has a 5xx status code
func (o *GetAPIV1CertStatusUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 cert status unauthorized response a status code equal to that given
func (o *GetAPIV1CertStatusUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 cert status unauthorized response
func (o *GetAPIV1CertStatusUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1CertStatusUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusUnauthorized %s", 401, payload)
}

func (o *GetAPIV1CertStatusUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusUnauthorized %s", 401, payload)
}

func (o *GetAPIV1CertStatusUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1CertStatusUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1CertStatusInternalServerError creates a GetAPIV1CertStatusInternalServerError with default headers values
func NewGetAPIV1CertStatusInternalServerError() *GetAPIV1CertStatusInternalServerError {
	return &GetAPIV1CertStatusInternalServerError{}
}

/*
GetAPIV1CertStatusInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1CertStatusInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 cert status internal server error response has a 2xx status code
func (o *GetAPIV1CertStatusInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 cert status internal server error response has a 3xx status code
func (o *GetAPIV1CertStatusInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 cert status internal server error response has a 4xx status code
func (o *GetAPIV1CertStatusInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 cert status internal server error response has a 5xx status code
func (o *GetAPIV1CertStatusInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 cert status internal server error response a status code equal to that given
func (o *GetAPIV1CertStatusInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 cert status internal server error response
func (o *GetAPIV1CertStatusInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1CertStatusInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusInternalServerError %s", 500, payload)
}

func (o *GetAPIV1CertStatusInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/cert/status][%d] getApiV1CertStatusInternalServerError %s", 500, payload)
}

func (o *GetAPIV1CertStatusInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1CertStatusInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
