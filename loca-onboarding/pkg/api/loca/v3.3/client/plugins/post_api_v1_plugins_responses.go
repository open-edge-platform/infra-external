// Code generated by go-swagger; DO NOT EDIT.

package plugins

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

// PostAPIV1PluginsReader is a Reader for the PostAPIV1Plugins structure.
type PostAPIV1PluginsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PostAPIV1PluginsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPostAPIV1PluginsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPostAPIV1PluginsBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewPostAPIV1PluginsInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /api/v1/plugins] PostAPIV1Plugins", response, response.Code())
	}
}

// NewPostAPIV1PluginsOK creates a PostAPIV1PluginsOK with default headers values
func NewPostAPIV1PluginsOK() *PostAPIV1PluginsOK {
	return &PostAPIV1PluginsOK{}
}

/*
PostAPIV1PluginsOK describes a response with status code 200, with default header values.

success
*/
type PostAPIV1PluginsOK struct {
	Payload *model.DtoResponseBase
}

// IsSuccess returns true when this post Api v1 plugins o k response has a 2xx status code
func (o *PostAPIV1PluginsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this post Api v1 plugins o k response has a 3xx status code
func (o *PostAPIV1PluginsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 plugins o k response has a 4xx status code
func (o *PostAPIV1PluginsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 plugins o k response has a 5xx status code
func (o *PostAPIV1PluginsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 plugins o k response a status code equal to that given
func (o *PostAPIV1PluginsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the post Api v1 plugins o k response
func (o *PostAPIV1PluginsOK) Code() int {
	return 200
}

func (o *PostAPIV1PluginsOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/plugins][%d] postApiV1PluginsOK %s", 200, payload)
}

func (o *PostAPIV1PluginsOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/plugins][%d] postApiV1PluginsOK %s", 200, payload)
}

func (o *PostAPIV1PluginsOK) GetPayload() *model.DtoResponseBase {
	return o.Payload
}

func (o *PostAPIV1PluginsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoResponseBase)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1PluginsBadRequest creates a PostAPIV1PluginsBadRequest with default headers values
func NewPostAPIV1PluginsBadRequest() *PostAPIV1PluginsBadRequest {
	return &PostAPIV1PluginsBadRequest{}
}

/*
PostAPIV1PluginsBadRequest describes a response with status code 400, with default header values.

auth fail
*/
type PostAPIV1PluginsBadRequest struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 plugins bad request response has a 2xx status code
func (o *PostAPIV1PluginsBadRequest) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 plugins bad request response has a 3xx status code
func (o *PostAPIV1PluginsBadRequest) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 plugins bad request response has a 4xx status code
func (o *PostAPIV1PluginsBadRequest) IsClientError() bool {
	return true
}

// IsServerError returns true when this post Api v1 plugins bad request response has a 5xx status code
func (o *PostAPIV1PluginsBadRequest) IsServerError() bool {
	return false
}

// IsCode returns true when this post Api v1 plugins bad request response a status code equal to that given
func (o *PostAPIV1PluginsBadRequest) IsCode(code int) bool {
	return code == 400
}

// Code gets the status code for the post Api v1 plugins bad request response
func (o *PostAPIV1PluginsBadRequest) Code() int {
	return 400
}

func (o *PostAPIV1PluginsBadRequest) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/plugins][%d] postApiV1PluginsBadRequest %s", 400, payload)
}

func (o *PostAPIV1PluginsBadRequest) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/plugins][%d] postApiV1PluginsBadRequest %s", 400, payload)
}

func (o *PostAPIV1PluginsBadRequest) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1PluginsBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPostAPIV1PluginsInternalServerError creates a PostAPIV1PluginsInternalServerError with default headers values
func NewPostAPIV1PluginsInternalServerError() *PostAPIV1PluginsInternalServerError {
	return &PostAPIV1PluginsInternalServerError{}
}

/*
PostAPIV1PluginsInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type PostAPIV1PluginsInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this post Api v1 plugins internal server error response has a 2xx status code
func (o *PostAPIV1PluginsInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this post Api v1 plugins internal server error response has a 3xx status code
func (o *PostAPIV1PluginsInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this post Api v1 plugins internal server error response has a 4xx status code
func (o *PostAPIV1PluginsInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this post Api v1 plugins internal server error response has a 5xx status code
func (o *PostAPIV1PluginsInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this post Api v1 plugins internal server error response a status code equal to that given
func (o *PostAPIV1PluginsInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the post Api v1 plugins internal server error response
func (o *PostAPIV1PluginsInternalServerError) Code() int {
	return 500
}

func (o *PostAPIV1PluginsInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/plugins][%d] postApiV1PluginsInternalServerError %s", 500, payload)
}

func (o *PostAPIV1PluginsInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /api/v1/plugins][%d] postApiV1PluginsInternalServerError %s", 500, payload)
}

func (o *PostAPIV1PluginsInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *PostAPIV1PluginsInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
