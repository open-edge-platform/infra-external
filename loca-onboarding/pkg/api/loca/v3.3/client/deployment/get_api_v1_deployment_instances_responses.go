// Code generated by go-swagger; DO NOT EDIT.

package deployment

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

// GetAPIV1DeploymentInstancesReader is a Reader for the GetAPIV1DeploymentInstances structure.
type GetAPIV1DeploymentInstancesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1DeploymentInstancesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1DeploymentInstancesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1DeploymentInstancesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1DeploymentInstancesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1DeploymentInstancesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/deployment/instances] GetAPIV1DeploymentInstances", response, response.Code())
	}
}

// NewGetAPIV1DeploymentInstancesOK creates a GetAPIV1DeploymentInstancesOK with default headers values
func NewGetAPIV1DeploymentInstancesOK() *GetAPIV1DeploymentInstancesOK {
	return &GetAPIV1DeploymentInstancesOK{}
}

/*
GetAPIV1DeploymentInstancesOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1DeploymentInstancesOK struct {
	Payload *model.DtoInstancesQryResponse
}

// IsSuccess returns true when this get Api v1 deployment instances o k response has a 2xx status code
func (o *GetAPIV1DeploymentInstancesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 deployment instances o k response has a 3xx status code
func (o *GetAPIV1DeploymentInstancesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment instances o k response has a 4xx status code
func (o *GetAPIV1DeploymentInstancesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 deployment instances o k response has a 5xx status code
func (o *GetAPIV1DeploymentInstancesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 deployment instances o k response a status code equal to that given
func (o *GetAPIV1DeploymentInstancesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 deployment instances o k response
func (o *GetAPIV1DeploymentInstancesOK) Code() int {
	return 200
}

func (o *GetAPIV1DeploymentInstancesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesOK %s", 200, payload)
}

func (o *GetAPIV1DeploymentInstancesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesOK %s", 200, payload)
}

func (o *GetAPIV1DeploymentInstancesOK) GetPayload() *model.DtoInstancesQryResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentInstancesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoInstancesQryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1DeploymentInstancesBadRequest creates a GetAPIV1DeploymentInstancesBadRequest with default headers values
func NewGetAPIV1DeploymentInstancesBadRequest() *GetAPIV1DeploymentInstancesBadRequest {
	return &GetAPIV1DeploymentInstancesBadRequest{}
}

/*
GetAPIV1DeploymentInstancesBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1DeploymentInstancesBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 deployment instances bad request response has a 2xx status code
func (o *GetAPIV1DeploymentInstancesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 deployment instances bad request response has a 3xx status code
func (o *GetAPIV1DeploymentInstancesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment instances bad request response has a 4xx status code
func (o *GetAPIV1DeploymentInstancesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 deployment instances bad request response has a 5xx status code
func (o *GetAPIV1DeploymentInstancesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 deployment instances bad request response a status code equal to that given
func (o *GetAPIV1DeploymentInstancesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 deployment instances bad request response
func (o *GetAPIV1DeploymentInstancesBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1DeploymentInstancesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesBadRequest %s", 400, payload)
}

func (o *GetAPIV1DeploymentInstancesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesBadRequest %s", 400, payload)
}

func (o *GetAPIV1DeploymentInstancesBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentInstancesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1DeploymentInstancesUnauthorized creates a GetAPIV1DeploymentInstancesUnauthorized with default headers values
func NewGetAPIV1DeploymentInstancesUnauthorized() *GetAPIV1DeploymentInstancesUnauthorized {
	return &GetAPIV1DeploymentInstancesUnauthorized{}
}

/*
GetAPIV1DeploymentInstancesUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1DeploymentInstancesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 deployment instances unauthorized response has a 2xx status code
func (o *GetAPIV1DeploymentInstancesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 deployment instances unauthorized response has a 3xx status code
func (o *GetAPIV1DeploymentInstancesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment instances unauthorized response has a 4xx status code
func (o *GetAPIV1DeploymentInstancesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 deployment instances unauthorized response has a 5xx status code
func (o *GetAPIV1DeploymentInstancesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 deployment instances unauthorized response a status code equal to that given
func (o *GetAPIV1DeploymentInstancesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 deployment instances unauthorized response
func (o *GetAPIV1DeploymentInstancesUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1DeploymentInstancesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1DeploymentInstancesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1DeploymentInstancesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentInstancesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1DeploymentInstancesInternalServerError creates a GetAPIV1DeploymentInstancesInternalServerError with default headers values
func NewGetAPIV1DeploymentInstancesInternalServerError() *GetAPIV1DeploymentInstancesInternalServerError {
	return &GetAPIV1DeploymentInstancesInternalServerError{}
}

/*
GetAPIV1DeploymentInstancesInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1DeploymentInstancesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 deployment instances internal server error response has a 2xx status code
func (o *GetAPIV1DeploymentInstancesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 deployment instances internal server error response has a 3xx status code
func (o *GetAPIV1DeploymentInstancesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment instances internal server error response has a 4xx status code
func (o *GetAPIV1DeploymentInstancesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 deployment instances internal server error response has a 5xx status code
func (o *GetAPIV1DeploymentInstancesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 deployment instances internal server error response a status code equal to that given
func (o *GetAPIV1DeploymentInstancesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 deployment instances internal server error response
func (o *GetAPIV1DeploymentInstancesInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1DeploymentInstancesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1DeploymentInstancesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/instances][%d] getApiV1DeploymentInstancesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1DeploymentInstancesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentInstancesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
