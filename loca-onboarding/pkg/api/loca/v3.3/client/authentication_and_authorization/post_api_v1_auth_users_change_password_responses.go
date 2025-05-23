// Code generated by go-swagger; DO NOT EDIT.

package authentication_and_authorization

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

// PostAPIV1AuthUsersChangePasswordReader is a Reader for the PostAPIV1AuthUsersChangePassword structure.
type PostAPIV1AuthUsersChangePasswordReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1AuthUsersChangePasswordReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostAPIV1AuthUsersChangePasswordOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1AuthUsersChangePasswordBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1AuthUsersChangePasswordUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1AuthUsersChangePasswordInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/auth/users/changePassword] PostAPIV1AuthUsersChangePassword", response, response.Code())
	}
}

// NewPostAPIV1AuthUsersChangePasswordOK creates a PostAPIV1AuthUsersChangePasswordOK with default headers values
func NewPostAPIV1AuthUsersChangePasswordOK() *PostAPIV1AuthUsersChangePasswordOK {
	return &PostAPIV1AuthUsersChangePasswordOK{}
}

/*
PostAPIV1AuthUsersChangePasswordOK describes a response with status code 200, with default header values.

success
*/
type PostAPIV1AuthUsersChangePasswordOK struct {
	Payload *model.DtoResponseCUD
}

// IsSuccess returns true when this post Api v1 auth users change password o k response has a 2xx status code
func (o *PostAPIV1AuthUsersChangePasswordOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 auth users change password o k response has a 3xx status code
func (o *PostAPIV1AuthUsersChangePasswordOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 auth users change password o k response has a 4xx status code
func (o *PostAPIV1AuthUsersChangePasswordOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 auth users change password o k response has a 5xx status code
func (o *PostAPIV1AuthUsersChangePasswordOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 auth users change password o k response a status code equal to that given
func (o *PostAPIV1AuthUsersChangePasswordOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post Api v1 auth users change password o k response
func (o *PostAPIV1AuthUsersChangePasswordOK) Code() int {
	return 200
}

func (o *PostAPIV1AuthUsersChangePasswordOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordOK %s", 200, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordOK %s", 200, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordOK) GetPayload() *model.DtoResponseCUD {
	return o.Payload
}

func (o *PostAPIV1AuthUsersChangePasswordOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoResponseCUD)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1AuthUsersChangePasswordBadRequest creates a PostAPIV1AuthUsersChangePasswordBadRequest with default headers values
func NewPostAPIV1AuthUsersChangePasswordBadRequest() *PostAPIV1AuthUsersChangePasswordBadRequest {
	return &PostAPIV1AuthUsersChangePasswordBadRequest{}
}

/*
PostAPIV1AuthUsersChangePasswordBadRequest describes a response with status code 400, with default header values.

bad request
*/
type PostAPIV1AuthUsersChangePasswordBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 auth users change password bad request response has a 2xx status code
func (o *PostAPIV1AuthUsersChangePasswordBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 auth users change password bad request response has a 3xx status code
func (o *PostAPIV1AuthUsersChangePasswordBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 auth users change password bad request response has a 4xx status code
func (o *PostAPIV1AuthUsersChangePasswordBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 auth users change password bad request response has a 5xx status code
func (o *PostAPIV1AuthUsersChangePasswordBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 auth users change password bad request response a status code equal to that given
func (o *PostAPIV1AuthUsersChangePasswordBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 auth users change password bad request response
func (o *PostAPIV1AuthUsersChangePasswordBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1AuthUsersChangePasswordBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordBadRequest %s", 400, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordBadRequest %s", 400, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1AuthUsersChangePasswordBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1AuthUsersChangePasswordUnauthorized creates a PostAPIV1AuthUsersChangePasswordUnauthorized with default headers values
func NewPostAPIV1AuthUsersChangePasswordUnauthorized() *PostAPIV1AuthUsersChangePasswordUnauthorized {
	return &PostAPIV1AuthUsersChangePasswordUnauthorized{}
}

/*
PostAPIV1AuthUsersChangePasswordUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1AuthUsersChangePasswordUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 auth users change password unauthorized response has a 2xx status code
func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 auth users change password unauthorized response has a 3xx status code
func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 auth users change password unauthorized response has a 4xx status code
func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 auth users change password unauthorized response has a 5xx status code
func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 auth users change password unauthorized response a status code equal to that given
func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 auth users change password unauthorized response
func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordUnauthorized %s", 401, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordUnauthorized %s", 401, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1AuthUsersChangePasswordUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1AuthUsersChangePasswordInternalServerError creates a PostAPIV1AuthUsersChangePasswordInternalServerError with default headers values
func NewPostAPIV1AuthUsersChangePasswordInternalServerError() *PostAPIV1AuthUsersChangePasswordInternalServerError {
	return &PostAPIV1AuthUsersChangePasswordInternalServerError{}
}

/*
PostAPIV1AuthUsersChangePasswordInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1AuthUsersChangePasswordInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 auth users change password internal server error response has a 2xx status code
func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 auth users change password internal server error response has a 3xx status code
func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 auth users change password internal server error response has a 4xx status code
func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 auth users change password internal server error response has a 5xx status code
func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 auth users change password internal server error response a status code equal to that given
func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 auth users change password internal server error response
func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordInternalServerError %s", 500, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/auth/users/changePassword][%d] postApiV1AuthUsersChangePasswordInternalServerError %s", 500, payload)
}

func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1AuthUsersChangePasswordInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
