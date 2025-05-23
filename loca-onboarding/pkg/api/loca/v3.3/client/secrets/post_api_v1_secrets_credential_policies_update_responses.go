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

// PostAPIV1SecretsCredentialPoliciesUpdateReader is a Reader for the PostAPIV1SecretsCredentialPoliciesUpdate structure.
type PostAPIV1SecretsCredentialPoliciesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1SecretsCredentialPoliciesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAPIV1SecretsCredentialPoliciesUpdateCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1SecretsCredentialPoliciesUpdateBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1SecretsCredentialPoliciesUpdateUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1SecretsCredentialPoliciesUpdateInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/secrets/credential-policies/update] PostAPIV1SecretsCredentialPoliciesUpdate", response, response.Code())
	}
}

// NewPostAPIV1SecretsCredentialPoliciesUpdateCreated creates a PostAPIV1SecretsCredentialPoliciesUpdateCreated with default headers values
func NewPostAPIV1SecretsCredentialPoliciesUpdateCreated() *PostAPIV1SecretsCredentialPoliciesUpdateCreated {
	return &PostAPIV1SecretsCredentialPoliciesUpdateCreated{}
}

/*
PostAPIV1SecretsCredentialPoliciesUpdateCreated describes a response with status code 201, with default header values.

success
*/
type PostAPIV1SecretsCredentialPoliciesUpdateCreated struct {
	Payload *model.DtoUpdateCredentialpoliciesResponse
}

// IsSuccess returns true when this post Api v1 secrets credential policies update created response has a 2xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 secrets credential policies update created response has a 3xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets credential policies update created response has a 4xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 secrets credential policies update created response has a 5xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 secrets credential policies update created response a status code equal to that given
func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post Api v1 secrets credential policies update created response
func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) Code() int {
	return 201
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateCreated %s", 201, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateCreated %s", 201, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) GetPayload() *model.DtoUpdateCredentialpoliciesResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoUpdateCredentialpoliciesResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1SecretsCredentialPoliciesUpdateBadRequest creates a PostAPIV1SecretsCredentialPoliciesUpdateBadRequest with default headers values
func NewPostAPIV1SecretsCredentialPoliciesUpdateBadRequest() *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest {
	return &PostAPIV1SecretsCredentialPoliciesUpdateBadRequest{}
}

/*
PostAPIV1SecretsCredentialPoliciesUpdateBadRequest describes a response with status code 400, with default header values.

bad request
*/
type PostAPIV1SecretsCredentialPoliciesUpdateBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 secrets credential policies update bad request response has a 2xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 secrets credential policies update bad request response has a 3xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets credential policies update bad request response has a 4xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 secrets credential policies update bad request response has a 5xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 secrets credential policies update bad request response a status code equal to that given
func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 secrets credential policies update bad request response
func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateBadRequest %s", 400, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateBadRequest %s", 400, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1SecretsCredentialPoliciesUpdateUnauthorized creates a PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized with default headers values
func NewPostAPIV1SecretsCredentialPoliciesUpdateUnauthorized() *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized {
	return &PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized{}
}

/*
PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 secrets credential policies update unauthorized response has a 2xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 secrets credential policies update unauthorized response has a 3xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets credential policies update unauthorized response has a 4xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 secrets credential policies update unauthorized response has a 5xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 secrets credential policies update unauthorized response a status code equal to that given
func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 secrets credential policies update unauthorized response
func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateUnauthorized %s", 401, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateUnauthorized %s", 401, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1SecretsCredentialPoliciesUpdateInternalServerError creates a PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError with default headers values
func NewPostAPIV1SecretsCredentialPoliciesUpdateInternalServerError() *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError {
	return &PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError{}
}

/*
PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 secrets credential policies update internal server error response has a 2xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 secrets credential policies update internal server error response has a 3xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 secrets credential policies update internal server error response has a 4xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 secrets credential policies update internal server error response has a 5xx status code
func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 secrets credential policies update internal server error response a status code equal to that given
func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 secrets credential policies update internal server error response
func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateInternalServerError %s", 500, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/secrets/credential-policies/update][%d] postApiV1SecretsCredentialPoliciesUpdateInternalServerError %s", 500, payload)
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1SecretsCredentialPoliciesUpdateInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
