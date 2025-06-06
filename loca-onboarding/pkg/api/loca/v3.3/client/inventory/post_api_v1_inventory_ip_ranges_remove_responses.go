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

// PostAPIV1InventoryIPRangesRemoveReader is a Reader for the PostAPIV1InventoryIPRangesRemove structure.
type PostAPIV1InventoryIPRangesRemoveReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1InventoryIPRangesRemoveReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostAPIV1InventoryIPRangesRemoveOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1InventoryIPRangesRemoveBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPostAPIV1InventoryIPRangesRemoveUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1InventoryIPRangesRemoveInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/inventory/ip-ranges/remove] PostAPIV1InventoryIPRangesRemove", response, response.Code())
	}
}

// NewPostAPIV1InventoryIPRangesRemoveOK creates a PostAPIV1InventoryIPRangesRemoveOK with default headers values
func NewPostAPIV1InventoryIPRangesRemoveOK() *PostAPIV1InventoryIPRangesRemoveOK {
	return &PostAPIV1InventoryIPRangesRemoveOK{}
}

/*
PostAPIV1InventoryIPRangesRemoveOK describes a response with status code 200, with default header values.

success
*/
type PostAPIV1InventoryIPRangesRemoveOK struct {
	Payload *model.DtoResponseCUD
}

// IsSuccess returns true when this post Api v1 inventory Ip ranges remove o k response has a 2xx status code
func (o *PostAPIV1InventoryIPRangesRemoveOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 inventory Ip ranges remove o k response has a 3xx status code
func (o *PostAPIV1InventoryIPRangesRemoveOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory Ip ranges remove o k response has a 4xx status code
func (o *PostAPIV1InventoryIPRangesRemoveOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 inventory Ip ranges remove o k response has a 5xx status code
func (o *PostAPIV1InventoryIPRangesRemoveOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory Ip ranges remove o k response a status code equal to that given
func (o *PostAPIV1InventoryIPRangesRemoveOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post Api v1 inventory Ip ranges remove o k response
func (o *PostAPIV1InventoryIPRangesRemoveOK) Code() int {
	return 200
}

func (o *PostAPIV1InventoryIPRangesRemoveOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveOK %s", 200, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveOK %s", 200, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveOK) GetPayload() *model.DtoResponseCUD {
	return o.Payload
}

func (o *PostAPIV1InventoryIPRangesRemoveOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoResponseCUD)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryIPRangesRemoveBadRequest creates a PostAPIV1InventoryIPRangesRemoveBadRequest with default headers values
func NewPostAPIV1InventoryIPRangesRemoveBadRequest() *PostAPIV1InventoryIPRangesRemoveBadRequest {
	return &PostAPIV1InventoryIPRangesRemoveBadRequest{}
}

/*
PostAPIV1InventoryIPRangesRemoveBadRequest describes a response with status code 400, with default header values.

bad request
*/
type PostAPIV1InventoryIPRangesRemoveBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory Ip ranges remove bad request response has a 2xx status code
func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory Ip ranges remove bad request response has a 3xx status code
func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory Ip ranges remove bad request response has a 4xx status code
func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 inventory Ip ranges remove bad request response has a 5xx status code
func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory Ip ranges remove bad request response a status code equal to that given
func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 inventory Ip ranges remove bad request response
func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveBadRequest %s", 400, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveBadRequest %s", 400, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryIPRangesRemoveBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryIPRangesRemoveUnauthorized creates a PostAPIV1InventoryIPRangesRemoveUnauthorized with default headers values
func NewPostAPIV1InventoryIPRangesRemoveUnauthorized() *PostAPIV1InventoryIPRangesRemoveUnauthorized {
	return &PostAPIV1InventoryIPRangesRemoveUnauthorized{}
}

/*
PostAPIV1InventoryIPRangesRemoveUnauthorized describes a response with status code 401, with default header values.

auth fail
*/
type PostAPIV1InventoryIPRangesRemoveUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory Ip ranges remove unauthorized response has a 2xx status code
func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory Ip ranges remove unauthorized response has a 3xx status code
func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory Ip ranges remove unauthorized response has a 4xx status code
func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 inventory Ip ranges remove unauthorized response has a 5xx status code
func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 inventory Ip ranges remove unauthorized response a status code equal to that given
func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the post Api v1 inventory Ip ranges remove unauthorized response
func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) Code() int {
	return 401
}

func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveUnauthorized %s", 401, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveUnauthorized %s", 401, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryIPRangesRemoveUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1InventoryIPRangesRemoveInternalServerError creates a PostAPIV1InventoryIPRangesRemoveInternalServerError with default headers values
func NewPostAPIV1InventoryIPRangesRemoveInternalServerError() *PostAPIV1InventoryIPRangesRemoveInternalServerError {
	return &PostAPIV1InventoryIPRangesRemoveInternalServerError{}
}

/*
PostAPIV1InventoryIPRangesRemoveInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1InventoryIPRangesRemoveInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 inventory Ip ranges remove internal server error response has a 2xx status code
func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 inventory Ip ranges remove internal server error response has a 3xx status code
func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 inventory Ip ranges remove internal server error response has a 4xx status code
func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 inventory Ip ranges remove internal server error response has a 5xx status code
func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 inventory Ip ranges remove internal server error response a status code equal to that given
func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 inventory Ip ranges remove internal server error response
func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveInternalServerError %s", 500, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/inventory/ip-ranges/remove][%d] postApiV1InventoryIpRangesRemoveInternalServerError %s", 500, payload)
}

func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1InventoryIPRangesRemoveInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
