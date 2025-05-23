// Code generated by go-swagger; DO NOT EDIT.

package release

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

// GetAPIV1LocaAboutReader is a Reader for the GetAPIV1LocaAbout structure.
type GetAPIV1LocaAboutReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1LocaAboutReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1LocaAboutOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewGetAPIV1LocaAboutInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/loca/about] GetAPIV1LocaAbout", response, response.Code())
	}
}

// NewGetAPIV1LocaAboutOK creates a GetAPIV1LocaAboutOK with default headers values
func NewGetAPIV1LocaAboutOK() *GetAPIV1LocaAboutOK {
	return &GetAPIV1LocaAboutOK{}
}

/*
GetAPIV1LocaAboutOK describes a response with status code 200, with default header values.

success
*/
type GetAPIV1LocaAboutOK struct {
	Payload *model.DtoVersionResponse
}

// IsSuccess returns true when this get Api v1 loca about o k response has a 2xx status code
func (o *GetAPIV1LocaAboutOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 loca about o k response has a 3xx status code
func (o *GetAPIV1LocaAboutOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 loca about o k response has a 4xx status code
func (o *GetAPIV1LocaAboutOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 loca about o k response has a 5xx status code
func (o *GetAPIV1LocaAboutOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 loca about o k response a status code equal to that given
func (o *GetAPIV1LocaAboutOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 loca about o k response
func (o *GetAPIV1LocaAboutOK) Code() int {
	return 200
}

func (o *GetAPIV1LocaAboutOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/loca/about][%d] getApiV1LocaAboutOK %s", 200, payload)
}

func (o *GetAPIV1LocaAboutOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/loca/about][%d] getApiV1LocaAboutOK %s", 200, payload)
}

func (o *GetAPIV1LocaAboutOK) GetPayload() *model.DtoVersionResponse {
	return o.Payload
}

func (o *GetAPIV1LocaAboutOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoVersionResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1LocaAboutInternalServerError creates a GetAPIV1LocaAboutInternalServerError with default headers values
func NewGetAPIV1LocaAboutInternalServerError() *GetAPIV1LocaAboutInternalServerError {
	return &GetAPIV1LocaAboutInternalServerError{}
}

/*
GetAPIV1LocaAboutInternalServerError describes a response with status code 500, with default header values.

internal error
*/
type GetAPIV1LocaAboutInternalServerError struct {
	Payload *model.CommonRestfulResponse
}

// IsSuccess returns true when this get Api v1 loca about internal server error response has a 2xx status code
func (o *GetAPIV1LocaAboutInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 loca about internal server error response has a 3xx status code
func (o *GetAPIV1LocaAboutInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 loca about internal server error response has a 4xx status code
func (o *GetAPIV1LocaAboutInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 loca about internal server error response has a 5xx status code
func (o *GetAPIV1LocaAboutInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 loca about internal server error response a status code equal to that given
func (o *GetAPIV1LocaAboutInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 loca about internal server error response
func (o *GetAPIV1LocaAboutInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1LocaAboutInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/loca/about][%d] getApiV1LocaAboutInternalServerError %s", 500, payload)
}

func (o *GetAPIV1LocaAboutInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/loca/about][%d] getApiV1LocaAboutInternalServerError %s", 500, payload)
}

func (o *GetAPIV1LocaAboutInternalServerError) GetPayload() *model.CommonRestfulResponse {
	return o.Payload
}

func (o *GetAPIV1LocaAboutInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.CommonRestfulResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
