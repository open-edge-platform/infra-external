// Code generated by go-swagger; DO NOT EDIT.

package plugins

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

// GetAPIV1PluginsIDReader is a Reader for the GetAPIV1PluginsID structure.
type GetAPIV1PluginsIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1PluginsIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1PluginsIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1PluginsIDBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1PluginsIDUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/plugins/{id}] GetAPIV1PluginsID", response, response.Code())
	}
}

// NewGetAPIV1PluginsIDOK creates a GetAPIV1PluginsIDOK with default headers values
func NewGetAPIV1PluginsIDOK() *GetAPIV1PluginsIDOK {
	return &GetAPIV1PluginsIDOK{}
}

/*
GetAPIV1PluginsIDOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1PluginsIDOK struct {
	Payload *model.DtoPluginResponse
}

// IsSuccess returns true when this get Api v1 plugins Id o k response has a 2xx status code
func (o *GetAPIV1PluginsIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 plugins Id o k response has a 3xx status code
func (o *GetAPIV1PluginsIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 plugins Id o k response has a 4xx status code
func (o *GetAPIV1PluginsIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 plugins Id o k response has a 5xx status code
func (o *GetAPIV1PluginsIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 plugins Id o k response a status code equal to that given
func (o *GetAPIV1PluginsIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 plugins Id o k response
func (o *GetAPIV1PluginsIDOK) Code() int {
	return 200
}

func (o *GetAPIV1PluginsIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/plugins/{id}][%d] getApiV1PluginsIdOK %s", 200, payload)
}

func (o *GetAPIV1PluginsIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/plugins/{id}][%d] getApiV1PluginsIdOK %s", 200, payload)
}

func (o *GetAPIV1PluginsIDOK) GetPayload() *model.DtoPluginResponse {
	return o.Payload
}

func (o *GetAPIV1PluginsIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoPluginResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1PluginsIDBadRequest creates a GetAPIV1PluginsIDBadRequest with default headers values
func NewGetAPIV1PluginsIDBadRequest() *GetAPIV1PluginsIDBadRequest {
	return &GetAPIV1PluginsIDBadRequest{}
}

/*
GetAPIV1PluginsIDBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1PluginsIDBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 plugins Id bad request response has a 2xx status code
func (o *GetAPIV1PluginsIDBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 plugins Id bad request response has a 3xx status code
func (o *GetAPIV1PluginsIDBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 plugins Id bad request response has a 4xx status code
func (o *GetAPIV1PluginsIDBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 plugins Id bad request response has a 5xx status code
func (o *GetAPIV1PluginsIDBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 plugins Id bad request response a status code equal to that given
func (o *GetAPIV1PluginsIDBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 plugins Id bad request response
func (o *GetAPIV1PluginsIDBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1PluginsIDBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/plugins/{id}][%d] getApiV1PluginsIdBadRequest %s", 400, payload)
}

func (o *GetAPIV1PluginsIDBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/plugins/{id}][%d] getApiV1PluginsIdBadRequest %s", 400, payload)
}

func (o *GetAPIV1PluginsIDBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1PluginsIDBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1PluginsIDUnauthorized creates a GetAPIV1PluginsIDUnauthorized with default headers values
func NewGetAPIV1PluginsIDUnauthorized() *GetAPIV1PluginsIDUnauthorized {
	return &GetAPIV1PluginsIDUnauthorized{}
}

/*
GetAPIV1PluginsIDUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1PluginsIDUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 plugins Id unauthorized response has a 2xx status code
func (o *GetAPIV1PluginsIDUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 plugins Id unauthorized response has a 3xx status code
func (o *GetAPIV1PluginsIDUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 plugins Id unauthorized response has a 4xx status code
func (o *GetAPIV1PluginsIDUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 plugins Id unauthorized response has a 5xx status code
func (o *GetAPIV1PluginsIDUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 plugins Id unauthorized response a status code equal to that given
func (o *GetAPIV1PluginsIDUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 plugins Id unauthorized response
func (o *GetAPIV1PluginsIDUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1PluginsIDUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/plugins/{id}][%d] getApiV1PluginsIdUnauthorized %s", 401, payload)
}

func (o *GetAPIV1PluginsIDUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/plugins/{id}][%d] getApiV1PluginsIdUnauthorized %s", 401, payload)
}

func (o *GetAPIV1PluginsIDUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1PluginsIDUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
