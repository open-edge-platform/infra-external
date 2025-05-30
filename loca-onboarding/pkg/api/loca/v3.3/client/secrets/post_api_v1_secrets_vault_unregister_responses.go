// Code generated by go-swagger; DO NOT EDIT.

package secrets

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

// PostAPIV1SecretsVaultUnregisterReader is a Reader for the PostAPIV1SecretsVaultUnregister structure.
type PostAPIV1SecretsVaultUnregisterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1SecretsVaultUnregisterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAPIV1SecretsVaultUnregisterCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1SecretsVaultUnregisterBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1SecretsVaultUnregisterInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/secrets/vault/unregister] PostAPIV1SecretsVaultUnregister", response, response.Code())
	}
}

// NewPostAPIV1SecretsVaultUnregisterCreated creates a PostAPIV1SecretsVaultUnregisterCreated with default headers values
func NewPostAPIV1SecretsVaultUnregisterCreated() *PostAPIV1SecretsVaultUnregisterCreated {
	return &PostAPIV1SecretsVaultUnregisterCreated{}
}

/*
PostAPIV1SecretsVaultUnregisterCreated describes a response with status code 201, with default header values.

success
*/
type PostAPIV1SecretsVaultUnregisterCreated struct {
	Payload *model.DtoWorkflowResponse
}

// IsSuccess returns true when this post Api v1 secrets vault unregister created response has a 2xx status code
func (o *PostAPIV1SecretsVaultUnregisterCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 secrets vault unregister created response has a 3xx status code
func (o *PostAPIV1SecretsVaultUnregisterCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets vault unregister created response has a 4xx status code
func (o *PostAPIV1SecretsVaultUnregisterCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 secrets vault unregister created response has a 5xx status code
func (o *PostAPIV1SecretsVaultUnregisterCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 secrets vault unregister created response a status code equal to that given
func (o *PostAPIV1SecretsVaultUnregisterCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post Api v1 secrets vault unregister created response
func (o *PostAPIV1SecretsVaultUnregisterCreated) Code() int {
	return 201
}

func (o *PostAPIV1SecretsVaultUnregisterCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/vault/unregister][%d] postApiV1SecretsVaultUnregisterCreated %s", 201, payload)
}

func (o *PostAPIV1SecretsVaultUnregisterCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/vault/unregister][%d] postApiV1SecretsVaultUnregisterCreated %s", 201, payload)
}

func (o *PostAPIV1SecretsVaultUnregisterCreated) GetPayload() *model.DtoWorkflowResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsVaultUnregisterCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoWorkflowResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1SecretsVaultUnregisterBadRequest creates a PostAPIV1SecretsVaultUnregisterBadRequest with default headers values
func NewPostAPIV1SecretsVaultUnregisterBadRequest() *PostAPIV1SecretsVaultUnregisterBadRequest {
	return &PostAPIV1SecretsVaultUnregisterBadRequest{}
}

/*
PostAPIV1SecretsVaultUnregisterBadRequest describes a response with status code 400, with default header values.

fail
*/
type PostAPIV1SecretsVaultUnregisterBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 secrets vault unregister bad request response has a 2xx status code
func (o *PostAPIV1SecretsVaultUnregisterBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 secrets vault unregister bad request response has a 3xx status code
func (o *PostAPIV1SecretsVaultUnregisterBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets vault unregister bad request response has a 4xx status code
func (o *PostAPIV1SecretsVaultUnregisterBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 secrets vault unregister bad request response has a 5xx status code
func (o *PostAPIV1SecretsVaultUnregisterBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 secrets vault unregister bad request response a status code equal to that given
func (o *PostAPIV1SecretsVaultUnregisterBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 secrets vault unregister bad request response
func (o *PostAPIV1SecretsVaultUnregisterBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1SecretsVaultUnregisterBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/vault/unregister][%d] postApiV1SecretsVaultUnregisterBadRequest %s", 400, payload)
}

func (o *PostAPIV1SecretsVaultUnregisterBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/vault/unregister][%d] postApiV1SecretsVaultUnregisterBadRequest %s", 400, payload)
}

func (o *PostAPIV1SecretsVaultUnregisterBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsVaultUnregisterBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1SecretsVaultUnregisterInternalServerError creates a PostAPIV1SecretsVaultUnregisterInternalServerError with default headers values
func NewPostAPIV1SecretsVaultUnregisterInternalServerError() *PostAPIV1SecretsVaultUnregisterInternalServerError {
	return &PostAPIV1SecretsVaultUnregisterInternalServerError{}
}

/*
PostAPIV1SecretsVaultUnregisterInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1SecretsVaultUnregisterInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 secrets vault unregister internal server error response has a 2xx status code
func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 secrets vault unregister internal server error response has a 3xx status code
func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets vault unregister internal server error response has a 4xx status code
func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 secrets vault unregister internal server error response has a 5xx status code
func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 secrets vault unregister internal server error response a status code equal to that given
func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 secrets vault unregister internal server error response
func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/vault/unregister][%d] postApiV1SecretsVaultUnregisterInternalServerError %s", 500, payload)
}

func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/vault/unregister][%d] postApiV1SecretsVaultUnregisterInternalServerError %s", 500, payload)
}

func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsVaultUnregisterInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
