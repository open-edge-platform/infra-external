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

// PostAPIV1DeploymentOsDeployReader is a Reader for the PostAPIV1DeploymentOsDeploy structure.
type PostAPIV1DeploymentOsDeployReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1DeploymentOsDeployReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAPIV1DeploymentOsDeployCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1DeploymentOsDeployBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1DeploymentOsDeployUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1DeploymentOsDeployInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/deployment/os/deploy] PostAPIV1DeploymentOsDeploy", response, response.Code())
	}
}

// NewPostAPIV1DeploymentOsDeployCreated creates a PostAPIV1DeploymentOsDeployCreated with default headers values
func NewPostAPIV1DeploymentOsDeployCreated() *PostAPIV1DeploymentOsDeployCreated {
	return &PostAPIV1DeploymentOsDeployCreated{}
}

/*
PostAPIV1DeploymentOsDeployCreated describes a response with status code 201, with default header values.

success
*/
type PostAPIV1DeploymentOsDeployCreated struct {
	Payload *model.DtoCreatedWorkflowResponse
}

// IsSuccess returns true when this post Api v1 deployment os deploy created response has a 2xx status code
func (o *PostAPIV1DeploymentOsDeployCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 deployment os deploy created response has a 3xx status code
func (o *PostAPIV1DeploymentOsDeployCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 deployment os deploy created response has a 4xx status code
func (o *PostAPIV1DeploymentOsDeployCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 deployment os deploy created response has a 5xx status code
func (o *PostAPIV1DeploymentOsDeployCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 deployment os deploy created response a status code equal to that given
func (o *PostAPIV1DeploymentOsDeployCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post Api v1 deployment os deploy created response
func (o *PostAPIV1DeploymentOsDeployCreated) Code() int {
	return 201
}

func (o *PostAPIV1DeploymentOsDeployCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployCreated %s", 201, payload)
}

func (o *PostAPIV1DeploymentOsDeployCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployCreated %s", 201, payload)
}

func (o *PostAPIV1DeploymentOsDeployCreated) GetPayload() *model.DtoCreatedWorkflowResponse {
	return o.Payload
}

func (o *PostAPIV1DeploymentOsDeployCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoCreatedWorkflowResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1DeploymentOsDeployBadRequest creates a PostAPIV1DeploymentOsDeployBadRequest with default headers values
func NewPostAPIV1DeploymentOsDeployBadRequest() *PostAPIV1DeploymentOsDeployBadRequest {
	return &PostAPIV1DeploymentOsDeployBadRequest{}
}

/*
PostAPIV1DeploymentOsDeployBadRequest describes a response with status code 400, with default header values.

bad request
*/
type PostAPIV1DeploymentOsDeployBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 deployment os deploy bad request response has a 2xx status code
func (o *PostAPIV1DeploymentOsDeployBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 deployment os deploy bad request response has a 3xx status code
func (o *PostAPIV1DeploymentOsDeployBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 deployment os deploy bad request response has a 4xx status code
func (o *PostAPIV1DeploymentOsDeployBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 deployment os deploy bad request response has a 5xx status code
func (o *PostAPIV1DeploymentOsDeployBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 deployment os deploy bad request response a status code equal to that given
func (o *PostAPIV1DeploymentOsDeployBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 deployment os deploy bad request response
func (o *PostAPIV1DeploymentOsDeployBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1DeploymentOsDeployBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployBadRequest %s", 400, payload)
}

func (o *PostAPIV1DeploymentOsDeployBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployBadRequest %s", 400, payload)
}

func (o *PostAPIV1DeploymentOsDeployBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1DeploymentOsDeployBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1DeploymentOsDeployUnauthorized creates a PostAPIV1DeploymentOsDeployUnauthorized with default headers values
func NewPostAPIV1DeploymentOsDeployUnauthorized() *PostAPIV1DeploymentOsDeployUnauthorized {
	return &PostAPIV1DeploymentOsDeployUnauthorized{}
}

/*
PostAPIV1DeploymentOsDeployUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1DeploymentOsDeployUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 deployment os deploy unauthorized response has a 2xx status code
func (o *PostAPIV1DeploymentOsDeployUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 deployment os deploy unauthorized response has a 3xx status code
func (o *PostAPIV1DeploymentOsDeployUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 deployment os deploy unauthorized response has a 4xx status code
func (o *PostAPIV1DeploymentOsDeployUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 deployment os deploy unauthorized response has a 5xx status code
func (o *PostAPIV1DeploymentOsDeployUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 deployment os deploy unauthorized response a status code equal to that given
func (o *PostAPIV1DeploymentOsDeployUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 deployment os deploy unauthorized response
func (o *PostAPIV1DeploymentOsDeployUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1DeploymentOsDeployUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployUnauthorized %s", 401, payload)
}

func (o *PostAPIV1DeploymentOsDeployUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployUnauthorized %s", 401, payload)
}

func (o *PostAPIV1DeploymentOsDeployUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1DeploymentOsDeployUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1DeploymentOsDeployInternalServerError creates a PostAPIV1DeploymentOsDeployInternalServerError with default headers values
func NewPostAPIV1DeploymentOsDeployInternalServerError() *PostAPIV1DeploymentOsDeployInternalServerError {
	return &PostAPIV1DeploymentOsDeployInternalServerError{}
}

/*
PostAPIV1DeploymentOsDeployInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1DeploymentOsDeployInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 deployment os deploy internal server error response has a 2xx status code
func (o *PostAPIV1DeploymentOsDeployInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 deployment os deploy internal server error response has a 3xx status code
func (o *PostAPIV1DeploymentOsDeployInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 deployment os deploy internal server error response has a 4xx status code
func (o *PostAPIV1DeploymentOsDeployInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 deployment os deploy internal server error response has a 5xx status code
func (o *PostAPIV1DeploymentOsDeployInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 deployment os deploy internal server error response a status code equal to that given
func (o *PostAPIV1DeploymentOsDeployInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 deployment os deploy internal server error response
func (o *PostAPIV1DeploymentOsDeployInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1DeploymentOsDeployInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployInternalServerError %s", 500, payload)
}

func (o *PostAPIV1DeploymentOsDeployInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/deployment/os/deploy][%d] postApiV1DeploymentOsDeployInternalServerError %s", 500, payload)
}

func (o *PostAPIV1DeploymentOsDeployInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1DeploymentOsDeployInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
