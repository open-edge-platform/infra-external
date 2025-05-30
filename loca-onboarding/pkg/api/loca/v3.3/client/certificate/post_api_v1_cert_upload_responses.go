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

// PostAPIV1CertUploadReader is a Reader for the PostAPIV1CertUpload structure.
type PostAPIV1CertUploadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1CertUploadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostAPIV1CertUploadOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1CertUploadBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1CertUploadUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewPostAPIV1CertUploadTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1CertUploadInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/cert/upload] PostAPIV1CertUpload", response, response.Code())
	}
}

// NewPostAPIV1CertUploadOK creates a PostAPIV1CertUploadOK with default headers values
func NewPostAPIV1CertUploadOK() *PostAPIV1CertUploadOK {
	return &PostAPIV1CertUploadOK{}
}

/*
PostAPIV1CertUploadOK describes a response with status code 200, with default header values.

success
*/
type PostAPIV1CertUploadOK struct {
	Payload interface{}
}

// IsSuccess returns true when this post Api v1 cert upload o k response has a 2xx status code
func (o *PostAPIV1CertUploadOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 cert upload o k response has a 3xx status code
func (o *PostAPIV1CertUploadOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 cert upload o k response has a 4xx status code
func (o *PostAPIV1CertUploadOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 cert upload o k response has a 5xx status code
func (o *PostAPIV1CertUploadOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 cert upload o k response a status code equal to that given
func (o *PostAPIV1CertUploadOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post Api v1 cert upload o k response
func (o *PostAPIV1CertUploadOK) Code() int {
	return 200
}

func (o *PostAPIV1CertUploadOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadOK %s", 200, payload)
}

func (o *PostAPIV1CertUploadOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadOK %s", 200, payload)
}

func (o *PostAPIV1CertUploadOK) GetPayload() interface{} {
	return o.Payload
}

func (o *PostAPIV1CertUploadOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1CertUploadBadRequest creates a PostAPIV1CertUploadBadRequest with default headers values
func NewPostAPIV1CertUploadBadRequest() *PostAPIV1CertUploadBadRequest {
	return &PostAPIV1CertUploadBadRequest{}
}

/*
PostAPIV1CertUploadBadRequest describes a response with status code 400, with default header values.

failure
*/
type PostAPIV1CertUploadBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 cert upload bad request response has a 2xx status code
func (o *PostAPIV1CertUploadBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 cert upload bad request response has a 3xx status code
func (o *PostAPIV1CertUploadBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 cert upload bad request response has a 4xx status code
func (o *PostAPIV1CertUploadBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 cert upload bad request response has a 5xx status code
func (o *PostAPIV1CertUploadBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 cert upload bad request response a status code equal to that given
func (o *PostAPIV1CertUploadBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 cert upload bad request response
func (o *PostAPIV1CertUploadBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1CertUploadBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadBadRequest %s", 400, payload)
}

func (o *PostAPIV1CertUploadBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadBadRequest %s", 400, payload)
}

func (o *PostAPIV1CertUploadBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1CertUploadBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1CertUploadUnauthorized creates a PostAPIV1CertUploadUnauthorized with default headers values
func NewPostAPIV1CertUploadUnauthorized() *PostAPIV1CertUploadUnauthorized {
	return &PostAPIV1CertUploadUnauthorized{}
}

/*
PostAPIV1CertUploadUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1CertUploadUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 cert upload unauthorized response has a 2xx status code
func (o *PostAPIV1CertUploadUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 cert upload unauthorized response has a 3xx status code
func (o *PostAPIV1CertUploadUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 cert upload unauthorized response has a 4xx status code
func (o *PostAPIV1CertUploadUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 cert upload unauthorized response has a 5xx status code
func (o *PostAPIV1CertUploadUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 cert upload unauthorized response a status code equal to that given
func (o *PostAPIV1CertUploadUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 cert upload unauthorized response
func (o *PostAPIV1CertUploadUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1CertUploadUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadUnauthorized %s", 401, payload)
}

func (o *PostAPIV1CertUploadUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadUnauthorized %s", 401, payload)
}

func (o *PostAPIV1CertUploadUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1CertUploadUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1CertUploadTooManyRequests creates a PostAPIV1CertUploadTooManyRequests with default headers values
func NewPostAPIV1CertUploadTooManyRequests() *PostAPIV1CertUploadTooManyRequests {
	return &PostAPIV1CertUploadTooManyRequests{}
}

/*
PostAPIV1CertUploadTooManyRequests describes a response with status code 429, with default header values.

too many requests in importing certificate
*/
type PostAPIV1CertUploadTooManyRequests struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 cert upload too many requests response has a 2xx status code
func (o *PostAPIV1CertUploadTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 cert upload too many requests response has a 3xx status code
func (o *PostAPIV1CertUploadTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 cert upload too many requests response has a 4xx status code
func (o *PostAPIV1CertUploadTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 cert upload too many requests response has a 5xx status code
func (o *PostAPIV1CertUploadTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 cert upload too many requests response a status code equal to that given
func (o *PostAPIV1CertUploadTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the post Api v1 cert upload too many requests response
func (o *PostAPIV1CertUploadTooManyRequests) Code() int {
	return 429
}

func (o *PostAPIV1CertUploadTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadTooManyRequests %s", 429, payload)
}

func (o *PostAPIV1CertUploadTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadTooManyRequests %s", 429, payload)
}

func (o *PostAPIV1CertUploadTooManyRequests) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1CertUploadTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1CertUploadInternalServerError creates a PostAPIV1CertUploadInternalServerError with default headers values
func NewPostAPIV1CertUploadInternalServerError() *PostAPIV1CertUploadInternalServerError {
	return &PostAPIV1CertUploadInternalServerError{}
}

/*
PostAPIV1CertUploadInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1CertUploadInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 cert upload internal server error response has a 2xx status code
func (o *PostAPIV1CertUploadInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 cert upload internal server error response has a 3xx status code
func (o *PostAPIV1CertUploadInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 cert upload internal server error response has a 4xx status code
func (o *PostAPIV1CertUploadInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 cert upload internal server error response has a 5xx status code
func (o *PostAPIV1CertUploadInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 cert upload internal server error response a status code equal to that given
func (o *PostAPIV1CertUploadInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 cert upload internal server error response
func (o *PostAPIV1CertUploadInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1CertUploadInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadInternalServerError %s", 500, payload)
}

func (o *PostAPIV1CertUploadInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/cert/upload][%d] postApiV1CertUploadInternalServerError %s", 500, payload)
}

func (o *PostAPIV1CertUploadInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1CertUploadInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
