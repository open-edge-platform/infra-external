// Code generated by go-swagger; DO NOT EDIT.

package licenses

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

// GetAPIV1LicensesReader is a Reader for the GetAPIV1Licenses structure.
type GetAPIV1LicensesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1LicensesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1LicensesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1LicensesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1LicensesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1LicensesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/licenses] GetAPIV1Licenses", response, response.Code())
	}
}

// NewGetAPIV1LicensesOK creates a GetAPIV1LicensesOK with default headers values
func NewGetAPIV1LicensesOK() *GetAPIV1LicensesOK {
	return &GetAPIV1LicensesOK{}
}

/*
GetAPIV1LicensesOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1LicensesOK struct {
	Payload *model.DtoLicensesQueryResponse
}

// IsSuccess returns true when this get Api v1 licenses o k response has a 2xx status code
func (o *GetAPIV1LicensesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 licenses o k response has a 3xx status code
func (o *GetAPIV1LicensesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 licenses o k response has a 4xx status code
func (o *GetAPIV1LicensesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 licenses o k response has a 5xx status code
func (o *GetAPIV1LicensesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 licenses o k response a status code equal to that given
func (o *GetAPIV1LicensesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 licenses o k response
func (o *GetAPIV1LicensesOK) Code() int {
	return 200
}

func (o *GetAPIV1LicensesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesOK %s", 200, payload)
}

func (o *GetAPIV1LicensesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesOK %s", 200, payload)
}

func (o *GetAPIV1LicensesOK) GetPayload() *model.DtoLicensesQueryResponse {
	return o.Payload
}

func (o *GetAPIV1LicensesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoLicensesQueryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1LicensesBadRequest creates a GetAPIV1LicensesBadRequest with default headers values
func NewGetAPIV1LicensesBadRequest() *GetAPIV1LicensesBadRequest {
	return &GetAPIV1LicensesBadRequest{}
}

/*
GetAPIV1LicensesBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1LicensesBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 licenses bad request response has a 2xx status code
func (o *GetAPIV1LicensesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 licenses bad request response has a 3xx status code
func (o *GetAPIV1LicensesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 licenses bad request response has a 4xx status code
func (o *GetAPIV1LicensesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 licenses bad request response has a 5xx status code
func (o *GetAPIV1LicensesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 licenses bad request response a status code equal to that given
func (o *GetAPIV1LicensesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 licenses bad request response
func (o *GetAPIV1LicensesBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1LicensesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesBadRequest %s", 400, payload)
}

func (o *GetAPIV1LicensesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesBadRequest %s", 400, payload)
}

func (o *GetAPIV1LicensesBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1LicensesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1LicensesUnauthorized creates a GetAPIV1LicensesUnauthorized with default headers values
func NewGetAPIV1LicensesUnauthorized() *GetAPIV1LicensesUnauthorized {
	return &GetAPIV1LicensesUnauthorized{}
}

/*
GetAPIV1LicensesUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1LicensesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 licenses unauthorized response has a 2xx status code
func (o *GetAPIV1LicensesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 licenses unauthorized response has a 3xx status code
func (o *GetAPIV1LicensesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 licenses unauthorized response has a 4xx status code
func (o *GetAPIV1LicensesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 licenses unauthorized response has a 5xx status code
func (o *GetAPIV1LicensesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 licenses unauthorized response a status code equal to that given
func (o *GetAPIV1LicensesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 licenses unauthorized response
func (o *GetAPIV1LicensesUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1LicensesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1LicensesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1LicensesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1LicensesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1LicensesInternalServerError creates a GetAPIV1LicensesInternalServerError with default headers values
func NewGetAPIV1LicensesInternalServerError() *GetAPIV1LicensesInternalServerError {
	return &GetAPIV1LicensesInternalServerError{}
}

/*
GetAPIV1LicensesInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1LicensesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 licenses internal server error response has a 2xx status code
func (o *GetAPIV1LicensesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 licenses internal server error response has a 3xx status code
func (o *GetAPIV1LicensesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 licenses internal server error response has a 4xx status code
func (o *GetAPIV1LicensesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 licenses internal server error response has a 5xx status code
func (o *GetAPIV1LicensesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 licenses internal server error response a status code equal to that given
func (o *GetAPIV1LicensesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 licenses internal server error response
func (o *GetAPIV1LicensesInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1LicensesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1LicensesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/licenses][%d] getApiV1LicensesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1LicensesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1LicensesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
