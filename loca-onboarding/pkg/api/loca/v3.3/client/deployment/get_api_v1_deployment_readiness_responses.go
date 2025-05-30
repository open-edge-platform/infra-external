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

// GetAPIV1DeploymentReadinessReader is a Reader for the GetAPIV1DeploymentReadiness structure.
type GetAPIV1DeploymentReadinessReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1DeploymentReadinessReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1DeploymentReadinessOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewGetAPIV1DeploymentReadinessBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewGetAPIV1DeploymentReadinessUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1DeploymentReadinessInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/deployment/readiness] GetAPIV1DeploymentReadiness", response, response.Code())
	}
}

// NewGetAPIV1DeploymentReadinessOK creates a GetAPIV1DeploymentReadinessOK with default headers values
func NewGetAPIV1DeploymentReadinessOK() *GetAPIV1DeploymentReadinessOK {
	return &GetAPIV1DeploymentReadinessOK{}
}

/*
GetAPIV1DeploymentReadinessOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1DeploymentReadinessOK struct {
	Payload *model.DtoReadinessesQryResponse
}

// IsSuccess returns true when this get Api v1 deployment readiness o k response has a 2xx status code
func (o *GetAPIV1DeploymentReadinessOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 deployment readiness o k response has a 3xx status code
func (o *GetAPIV1DeploymentReadinessOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment readiness o k response has a 4xx status code
func (o *GetAPIV1DeploymentReadinessOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 deployment readiness o k response has a 5xx status code
func (o *GetAPIV1DeploymentReadinessOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 deployment readiness o k response a status code equal to that given
func (o *GetAPIV1DeploymentReadinessOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 deployment readiness o k response
func (o *GetAPIV1DeploymentReadinessOK) Code() int {
	return 200
}

func (o *GetAPIV1DeploymentReadinessOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessOK %s", 200, payload)
}

func (o *GetAPIV1DeploymentReadinessOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessOK %s", 200, payload)
}

func (o *GetAPIV1DeploymentReadinessOK) GetPayload() *model.DtoReadinessesQryResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentReadinessOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoReadinessesQryResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1DeploymentReadinessBadRequest creates a GetAPIV1DeploymentReadinessBadRequest with default headers values
func NewGetAPIV1DeploymentReadinessBadRequest() *GetAPIV1DeploymentReadinessBadRequest {
	return &GetAPIV1DeploymentReadinessBadRequest{}
}

/*
GetAPIV1DeploymentReadinessBadRequest describes a response with status code 400, with default header values.

bad request
*/
type GetAPIV1DeploymentReadinessBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 deployment readiness bad request response has a 2xx status code
func (o *GetAPIV1DeploymentReadinessBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 deployment readiness bad request response has a 3xx status code
func (o *GetAPIV1DeploymentReadinessBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment readiness bad request response has a 4xx status code
func (o *GetAPIV1DeploymentReadinessBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 deployment readiness bad request response has a 5xx status code
func (o *GetAPIV1DeploymentReadinessBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 deployment readiness bad request response a status code equal to that given
func (o *GetAPIV1DeploymentReadinessBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the get Api v1 deployment readiness bad request response
func (o *GetAPIV1DeploymentReadinessBadRequest) Code() int {
	return 400
}

func (o *GetAPIV1DeploymentReadinessBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessBadRequest %s", 400, payload)
}

func (o *GetAPIV1DeploymentReadinessBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessBadRequest %s", 400, payload)
}

func (o *GetAPIV1DeploymentReadinessBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentReadinessBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1DeploymentReadinessUnauthorized creates a GetAPIV1DeploymentReadinessUnauthorized with default headers values
func NewGetAPIV1DeploymentReadinessUnauthorized() *GetAPIV1DeploymentReadinessUnauthorized {
	return &GetAPIV1DeploymentReadinessUnauthorized{}
}

/*
GetAPIV1DeploymentReadinessUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type GetAPIV1DeploymentReadinessUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 deployment readiness unauthorized response has a 2xx status code
func (o *GetAPIV1DeploymentReadinessUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 deployment readiness unauthorized response has a 3xx status code
func (o *GetAPIV1DeploymentReadinessUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment readiness unauthorized response has a 4xx status code
func (o *GetAPIV1DeploymentReadinessUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 deployment readiness unauthorized response has a 5xx status code
func (o *GetAPIV1DeploymentReadinessUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 deployment readiness unauthorized response a status code equal to that given
func (o *GetAPIV1DeploymentReadinessUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 deployment readiness unauthorized response
func (o *GetAPIV1DeploymentReadinessUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1DeploymentReadinessUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessUnauthorized %s", 401, payload)
}

func (o *GetAPIV1DeploymentReadinessUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessUnauthorized %s", 401, payload)
}

func (o *GetAPIV1DeploymentReadinessUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentReadinessUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1DeploymentReadinessInternalServerError creates a GetAPIV1DeploymentReadinessInternalServerError with default headers values
func NewGetAPIV1DeploymentReadinessInternalServerError() *GetAPIV1DeploymentReadinessInternalServerError {
	return &GetAPIV1DeploymentReadinessInternalServerError{}
}

/*
GetAPIV1DeploymentReadinessInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1DeploymentReadinessInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 deployment readiness internal server error response has a 2xx status code
func (o *GetAPIV1DeploymentReadinessInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 deployment readiness internal server error response has a 3xx status code
func (o *GetAPIV1DeploymentReadinessInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 deployment readiness internal server error response has a 4xx status code
func (o *GetAPIV1DeploymentReadinessInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 deployment readiness internal server error response has a 5xx status code
func (o *GetAPIV1DeploymentReadinessInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 deployment readiness internal server error response a status code equal to that given
func (o *GetAPIV1DeploymentReadinessInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 deployment readiness internal server error response
func (o *GetAPIV1DeploymentReadinessInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1DeploymentReadinessInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessInternalServerError %s", 500, payload)
}

func (o *GetAPIV1DeploymentReadinessInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/deployment/readiness][%d] getApiV1DeploymentReadinessInternalServerError %s", 500, payload)
}

func (o *GetAPIV1DeploymentReadinessInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1DeploymentReadinessInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
