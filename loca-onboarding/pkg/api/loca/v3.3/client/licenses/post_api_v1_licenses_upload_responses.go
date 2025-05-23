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

// PostAPIV1LicensesUploadReader is a Reader for the PostAPIV1LicensesUpload structure.
type PostAPIV1LicensesUploadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1LicensesUploadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAPIV1LicensesUploadCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1LicensesUploadBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1LicensesUploadUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1LicensesUploadInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/licenses/upload] PostAPIV1LicensesUpload", response, response.Code())
	}
}

// NewPostAPIV1LicensesUploadCreated creates a PostAPIV1LicensesUploadCreated with default headers values
func NewPostAPIV1LicensesUploadCreated() *PostAPIV1LicensesUploadCreated {
	return &PostAPIV1LicensesUploadCreated{}
}

/*
PostAPIV1LicensesUploadCreated describes a response with status code 201, with default header values.

success
*/
type PostAPIV1LicensesUploadCreated struct {
	Payload *model.DtoLicenseUploadResponse
}

// IsSuccess returns true when this post Api v1 licenses upload created response has a 2xx status code
func (o *PostAPIV1LicensesUploadCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 licenses upload created response has a 3xx status code
func (o *PostAPIV1LicensesUploadCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 licenses upload created response has a 4xx status code
func (o *PostAPIV1LicensesUploadCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 licenses upload created response has a 5xx status code
func (o *PostAPIV1LicensesUploadCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 licenses upload created response a status code equal to that given
func (o *PostAPIV1LicensesUploadCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post Api v1 licenses upload created response
func (o *PostAPIV1LicensesUploadCreated) Code() int {
	return 201
}

func (o *PostAPIV1LicensesUploadCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadCreated %s", 201, payload)
}

func (o *PostAPIV1LicensesUploadCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadCreated %s", 201, payload)
}

func (o *PostAPIV1LicensesUploadCreated) GetPayload() *model.DtoLicenseUploadResponse {
	return o.Payload
}

func (o *PostAPIV1LicensesUploadCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoLicenseUploadResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1LicensesUploadBadRequest creates a PostAPIV1LicensesUploadBadRequest with default headers values
func NewPostAPIV1LicensesUploadBadRequest() *PostAPIV1LicensesUploadBadRequest {
	return &PostAPIV1LicensesUploadBadRequest{}
}

/*
PostAPIV1LicensesUploadBadRequest describes a response with status code 400, with default header values.

bad request
*/
type PostAPIV1LicensesUploadBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 licenses upload bad request response has a 2xx status code
func (o *PostAPIV1LicensesUploadBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 licenses upload bad request response has a 3xx status code
func (o *PostAPIV1LicensesUploadBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 licenses upload bad request response has a 4xx status code
func (o *PostAPIV1LicensesUploadBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 licenses upload bad request response has a 5xx status code
func (o *PostAPIV1LicensesUploadBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 licenses upload bad request response a status code equal to that given
func (o *PostAPIV1LicensesUploadBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 licenses upload bad request response
func (o *PostAPIV1LicensesUploadBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1LicensesUploadBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadBadRequest %s", 400, payload)
}

func (o *PostAPIV1LicensesUploadBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadBadRequest %s", 400, payload)
}

func (o *PostAPIV1LicensesUploadBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1LicensesUploadBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1LicensesUploadUnauthorized creates a PostAPIV1LicensesUploadUnauthorized with default headers values
func NewPostAPIV1LicensesUploadUnauthorized() *PostAPIV1LicensesUploadUnauthorized {
	return &PostAPIV1LicensesUploadUnauthorized{}
}

/*
PostAPIV1LicensesUploadUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1LicensesUploadUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 licenses upload unauthorized response has a 2xx status code
func (o *PostAPIV1LicensesUploadUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 licenses upload unauthorized response has a 3xx status code
func (o *PostAPIV1LicensesUploadUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 licenses upload unauthorized response has a 4xx status code
func (o *PostAPIV1LicensesUploadUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 licenses upload unauthorized response has a 5xx status code
func (o *PostAPIV1LicensesUploadUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 licenses upload unauthorized response a status code equal to that given
func (o *PostAPIV1LicensesUploadUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 licenses upload unauthorized response
func (o *PostAPIV1LicensesUploadUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1LicensesUploadUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadUnauthorized %s", 401, payload)
}

func (o *PostAPIV1LicensesUploadUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadUnauthorized %s", 401, payload)
}

func (o *PostAPIV1LicensesUploadUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1LicensesUploadUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1LicensesUploadInternalServerError creates a PostAPIV1LicensesUploadInternalServerError with default headers values
func NewPostAPIV1LicensesUploadInternalServerError() *PostAPIV1LicensesUploadInternalServerError {
	return &PostAPIV1LicensesUploadInternalServerError{}
}

/*
PostAPIV1LicensesUploadInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1LicensesUploadInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 licenses upload internal server error response has a 2xx status code
func (o *PostAPIV1LicensesUploadInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 licenses upload internal server error response has a 3xx status code
func (o *PostAPIV1LicensesUploadInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 licenses upload internal server error response has a 4xx status code
func (o *PostAPIV1LicensesUploadInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 licenses upload internal server error response has a 5xx status code
func (o *PostAPIV1LicensesUploadInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 licenses upload internal server error response a status code equal to that given
func (o *PostAPIV1LicensesUploadInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 licenses upload internal server error response
func (o *PostAPIV1LicensesUploadInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1LicensesUploadInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadInternalServerError %s", 500, payload)
}

func (o *PostAPIV1LicensesUploadInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/licenses/upload][%d] postApiV1LicensesUploadInternalServerError %s", 500, payload)
}

func (o *PostAPIV1LicensesUploadInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1LicensesUploadInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
