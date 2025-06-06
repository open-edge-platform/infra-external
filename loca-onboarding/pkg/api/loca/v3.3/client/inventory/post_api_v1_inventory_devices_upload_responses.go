// Code generated by go-swagger; DO NOT EDIT.

package inventory

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

// PostAPIV1InventoryDevicesUploadReader is a Reader for the PostAPIV1InventoryDevicesUpload structure.
type PostAPIV1InventoryDevicesUploadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1InventoryDevicesUploadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAPIV1InventoryDevicesUploadCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1InventoryDevicesUploadBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1InventoryDevicesUploadUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1InventoryDevicesUploadInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/inventory/devices/upload] PostAPIV1InventoryDevicesUpload", response, response.Code())
	}
}

// NewPostAPIV1InventoryDevicesUploadCreated creates a PostAPIV1InventoryDevicesUploadCreated with default headers values
func NewPostAPIV1InventoryDevicesUploadCreated() *PostAPIV1InventoryDevicesUploadCreated {
	return &PostAPIV1InventoryDevicesUploadCreated{}
}

/*
PostAPIV1InventoryDevicesUploadCreated describes a response with status code 201, with default header values.

success
*/
type PostAPIV1InventoryDevicesUploadCreated struct {
	Payload *model.DtoResponseCUD
}

// IsSuccess returns true when this post Api v1 inventory devices upload created response has a 2xx status code
func (o *PostAPIV1InventoryDevicesUploadCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 inventory devices upload created response has a 3xx status code
func (o *PostAPIV1InventoryDevicesUploadCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory devices upload created response has a 4xx status code
func (o *PostAPIV1InventoryDevicesUploadCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 inventory devices upload created response has a 5xx status code
func (o *PostAPIV1InventoryDevicesUploadCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory devices upload created response a status code equal to that given
func (o *PostAPIV1InventoryDevicesUploadCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post Api v1 inventory devices upload created response
func (o *PostAPIV1InventoryDevicesUploadCreated) Code() int {
	return 201
}

func (o *PostAPIV1InventoryDevicesUploadCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadCreated %s", 201, payload)
}

func (o *PostAPIV1InventoryDevicesUploadCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadCreated %s", 201, payload)
}

func (o *PostAPIV1InventoryDevicesUploadCreated) GetPayload() *model.DtoResponseCUD {
	return o.Payload
}

func (o *PostAPIV1InventoryDevicesUploadCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoResponseCUD)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryDevicesUploadBadRequest creates a PostAPIV1InventoryDevicesUploadBadRequest with default headers values
func NewPostAPIV1InventoryDevicesUploadBadRequest() *PostAPIV1InventoryDevicesUploadBadRequest {
	return &PostAPIV1InventoryDevicesUploadBadRequest{}
}

/*
PostAPIV1InventoryDevicesUploadBadRequest describes a response with status code 400, with default header values.

bad request
*/
type PostAPIV1InventoryDevicesUploadBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory devices upload bad request response has a 2xx status code
func (o *PostAPIV1InventoryDevicesUploadBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory devices upload bad request response has a 3xx status code
func (o *PostAPIV1InventoryDevicesUploadBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory devices upload bad request response has a 4xx status code
func (o *PostAPIV1InventoryDevicesUploadBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 inventory devices upload bad request response has a 5xx status code
func (o *PostAPIV1InventoryDevicesUploadBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory devices upload bad request response a status code equal to that given
func (o *PostAPIV1InventoryDevicesUploadBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 inventory devices upload bad request response
func (o *PostAPIV1InventoryDevicesUploadBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1InventoryDevicesUploadBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadBadRequest %s", 400, payload)
}

func (o *PostAPIV1InventoryDevicesUploadBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadBadRequest %s", 400, payload)
}

func (o *PostAPIV1InventoryDevicesUploadBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryDevicesUploadBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryDevicesUploadUnauthorized creates a PostAPIV1InventoryDevicesUploadUnauthorized with default headers values
func NewPostAPIV1InventoryDevicesUploadUnauthorized() *PostAPIV1InventoryDevicesUploadUnauthorized {
	return &PostAPIV1InventoryDevicesUploadUnauthorized{}
}

/*
PostAPIV1InventoryDevicesUploadUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1InventoryDevicesUploadUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory devices upload unauthorized response has a 2xx status code
func (o *PostAPIV1InventoryDevicesUploadUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory devices upload unauthorized response has a 3xx status code
func (o *PostAPIV1InventoryDevicesUploadUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory devices upload unauthorized response has a 4xx status code
func (o *PostAPIV1InventoryDevicesUploadUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 inventory devices upload unauthorized response has a 5xx status code
func (o *PostAPIV1InventoryDevicesUploadUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory devices upload unauthorized response a status code equal to that given
func (o *PostAPIV1InventoryDevicesUploadUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 inventory devices upload unauthorized response
func (o *PostAPIV1InventoryDevicesUploadUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1InventoryDevicesUploadUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadUnauthorized %s", 401, payload)
}

func (o *PostAPIV1InventoryDevicesUploadUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadUnauthorized %s", 401, payload)
}

func (o *PostAPIV1InventoryDevicesUploadUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryDevicesUploadUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryDevicesUploadInternalServerError creates a PostAPIV1InventoryDevicesUploadInternalServerError with default headers values
func NewPostAPIV1InventoryDevicesUploadInternalServerError() *PostAPIV1InventoryDevicesUploadInternalServerError {
	return &PostAPIV1InventoryDevicesUploadInternalServerError{}
}

/*
PostAPIV1InventoryDevicesUploadInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1InventoryDevicesUploadInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory devices upload internal server error response has a 2xx status code
func (o *PostAPIV1InventoryDevicesUploadInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory devices upload internal server error response has a 3xx status code
func (o *PostAPIV1InventoryDevicesUploadInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory devices upload internal server error response has a 4xx status code
func (o *PostAPIV1InventoryDevicesUploadInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 inventory devices upload internal server error response has a 5xx status code
func (o *PostAPIV1InventoryDevicesUploadInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 inventory devices upload internal server error response a status code equal to that given
func (o *PostAPIV1InventoryDevicesUploadInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 inventory devices upload internal server error response
func (o *PostAPIV1InventoryDevicesUploadInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1InventoryDevicesUploadInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadInternalServerError %s", 500, payload)
}

func (o *PostAPIV1InventoryDevicesUploadInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/devices/upload][%d] postApiV1InventoryDevicesUploadInternalServerError %s", 500, payload)
}

func (o *PostAPIV1InventoryDevicesUploadInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryDevicesUploadInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
