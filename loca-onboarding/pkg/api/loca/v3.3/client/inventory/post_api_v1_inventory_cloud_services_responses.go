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

// PostAPIV1InventoryCloudServicesReader is a Reader for the PostAPIV1InventoryCloudServices structure.
type PostAPIV1InventoryCloudServicesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1InventoryCloudServicesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 201:
		result := NewPostAPIV1InventoryCloudServicesCreated()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1InventoryCloudServicesBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1InventoryCloudServicesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1InventoryCloudServicesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/inventory/cloud-services] PostAPIV1InventoryCloudServices", response, response.Code())
	}
}

// NewPostAPIV1InventoryCloudServicesCreated creates a PostAPIV1InventoryCloudServicesCreated with default headers values
func NewPostAPIV1InventoryCloudServicesCreated() *PostAPIV1InventoryCloudServicesCreated {
	return &PostAPIV1InventoryCloudServicesCreated{}
}

/*
PostAPIV1InventoryCloudServicesCreated describes a response with status code 201, with default header values.

Cloud services created successfully
*/
type PostAPIV1InventoryCloudServicesCreated struct {
	Payload *model.DtoCloudServicesCreatedResponse
}

// IsSuccess returns true when this post Api v1 inventory cloud services created response has a 2xx status code
func (o *PostAPIV1InventoryCloudServicesCreated) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 inventory cloud services created response has a 3xx status code
func (o *PostAPIV1InventoryCloudServicesCreated) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory cloud services created response has a 4xx status code
func (o *PostAPIV1InventoryCloudServicesCreated) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 inventory cloud services created response has a 5xx status code
func (o *PostAPIV1InventoryCloudServicesCreated) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory cloud services created response a status code equal to that given
func (o *PostAPIV1InventoryCloudServicesCreated) IsCode(code int) bool {
	return code == 201
}

// Code gets the status code for the post Api v1 inventory cloud services created response
func (o *PostAPIV1InventoryCloudServicesCreated) Code() int {
	return 201
}

func (o *PostAPIV1InventoryCloudServicesCreated) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesCreated %s", 201, payload)
}

func (o *PostAPIV1InventoryCloudServicesCreated) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesCreated %s", 201, payload)
}

func (o *PostAPIV1InventoryCloudServicesCreated) GetPayload() *model.DtoCloudServicesCreatedResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryCloudServicesCreated) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoCloudServicesCreatedResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryCloudServicesBadRequest creates a PostAPIV1InventoryCloudServicesBadRequest with default headers values
func NewPostAPIV1InventoryCloudServicesBadRequest() *PostAPIV1InventoryCloudServicesBadRequest {
	return &PostAPIV1InventoryCloudServicesBadRequest{}
}

/*
PostAPIV1InventoryCloudServicesBadRequest describes a response with status code 400, with default header values.

Bad request
*/
type PostAPIV1InventoryCloudServicesBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory cloud services bad request response has a 2xx status code
func (o *PostAPIV1InventoryCloudServicesBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory cloud services bad request response has a 3xx status code
func (o *PostAPIV1InventoryCloudServicesBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory cloud services bad request response has a 4xx status code
func (o *PostAPIV1InventoryCloudServicesBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 inventory cloud services bad request response has a 5xx status code
func (o *PostAPIV1InventoryCloudServicesBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory cloud services bad request response a status code equal to that given
func (o *PostAPIV1InventoryCloudServicesBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 inventory cloud services bad request response
func (o *PostAPIV1InventoryCloudServicesBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1InventoryCloudServicesBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesBadRequest %s", 400, payload)
}

func (o *PostAPIV1InventoryCloudServicesBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesBadRequest %s", 400, payload)
}

func (o *PostAPIV1InventoryCloudServicesBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryCloudServicesBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryCloudServicesUnauthorized creates a PostAPIV1InventoryCloudServicesUnauthorized with default headers values
func NewPostAPIV1InventoryCloudServicesUnauthorized() *PostAPIV1InventoryCloudServicesUnauthorized {
	return &PostAPIV1InventoryCloudServicesUnauthorized{}
}

/*
PostAPIV1InventoryCloudServicesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type PostAPIV1InventoryCloudServicesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory cloud services unauthorized response has a 2xx status code
func (o *PostAPIV1InventoryCloudServicesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory cloud services unauthorized response has a 3xx status code
func (o *PostAPIV1InventoryCloudServicesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory cloud services unauthorized response has a 4xx status code
func (o *PostAPIV1InventoryCloudServicesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 inventory cloud services unauthorized response has a 5xx status code
func (o *PostAPIV1InventoryCloudServicesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory cloud services unauthorized response a status code equal to that given
func (o *PostAPIV1InventoryCloudServicesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 inventory cloud services unauthorized response
func (o *PostAPIV1InventoryCloudServicesUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1InventoryCloudServicesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesUnauthorized %s", 401, payload)
}

func (o *PostAPIV1InventoryCloudServicesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesUnauthorized %s", 401, payload)
}

func (o *PostAPIV1InventoryCloudServicesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryCloudServicesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryCloudServicesInternalServerError creates a PostAPIV1InventoryCloudServicesInternalServerError with default headers values
func NewPostAPIV1InventoryCloudServicesInternalServerError() *PostAPIV1InventoryCloudServicesInternalServerError {
	return &PostAPIV1InventoryCloudServicesInternalServerError{}
}

/*
PostAPIV1InventoryCloudServicesInternalServerError describes a response with status code 500, with default header values.

Internal server error
*/
type PostAPIV1InventoryCloudServicesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory cloud services internal server error response has a 2xx status code
func (o *PostAPIV1InventoryCloudServicesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory cloud services internal server error response has a 3xx status code
func (o *PostAPIV1InventoryCloudServicesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory cloud services internal server error response has a 4xx status code
func (o *PostAPIV1InventoryCloudServicesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 inventory cloud services internal server error response has a 5xx status code
func (o *PostAPIV1InventoryCloudServicesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 inventory cloud services internal server error response a status code equal to that given
func (o *PostAPIV1InventoryCloudServicesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 inventory cloud services internal server error response
func (o *PostAPIV1InventoryCloudServicesInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1InventoryCloudServicesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesInternalServerError %s", 500, payload)
}

func (o *PostAPIV1InventoryCloudServicesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/cloud-services][%d] postApiV1InventoryCloudServicesInternalServerError %s", 500, payload)
}

func (o *PostAPIV1InventoryCloudServicesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryCloudServicesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
