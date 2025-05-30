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

// GetAPIV1InventorySitesMetadataRulesReader is a Reader for the GetAPIV1InventorySitesMetadataRules structure.
type GetAPIV1InventorySitesMetadataRulesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetAPIV1InventorySitesMetadataRulesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetAPIV1InventorySitesMetadataRulesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetAPIV1InventorySitesMetadataRulesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewGetAPIV1InventorySitesMetadataRulesInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /api/v1/inventory/sites/metadata-rules] GetAPIV1InventorySitesMetadataRules", response, response.Code())
	}
}

// NewGetAPIV1InventorySitesMetadataRulesOK creates a GetAPIV1InventorySitesMetadataRulesOK with default headers values
func NewGetAPIV1InventorySitesMetadataRulesOK() *GetAPIV1InventorySitesMetadataRulesOK {
	return &GetAPIV1InventorySitesMetadataRulesOK{}
}

/*
GetAPIV1InventorySitesMetadataRulesOK describes a response with status code 200, with default header values.

Successfully retrieved site metadata rules
*/
type GetAPIV1InventorySitesMetadataRulesOK struct {
	Payload *model.DtoDtoSettingRuleListResponse
}

// IsSuccess returns true when this get Api v1 inventory sites metadata rules o k response has a 2xx status code
func (o *GetAPIV1InventorySitesMetadataRulesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get Api v1 inventory sites metadata rules o k response has a 3xx status code
func (o *GetAPIV1InventorySitesMetadataRulesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites metadata rules o k response has a 4xx status code
func (o *GetAPIV1InventorySitesMetadataRulesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory sites metadata rules o k response has a 5xx status code
func (o *GetAPIV1InventorySitesMetadataRulesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory sites metadata rules o k response a status code equal to that given
func (o *GetAPIV1InventorySitesMetadataRulesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get Api v1 inventory sites metadata rules o k response
func (o *GetAPIV1InventorySitesMetadataRulesOK) Code() int {
	return 200
}

func (o *GetAPIV1InventorySitesMetadataRulesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites/metadata-rules][%d] getApiV1InventorySitesMetadataRulesOK %s", 200, payload)
}

func (o *GetAPIV1InventorySitesMetadataRulesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites/metadata-rules][%d] getApiV1InventorySitesMetadataRulesOK %s", 200, payload)
}

func (o *GetAPIV1InventorySitesMetadataRulesOK) GetPayload() *model.DtoDtoSettingRuleListResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesMetadataRulesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoDtoSettingRuleListResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventorySitesMetadataRulesUnauthorized creates a GetAPIV1InventorySitesMetadataRulesUnauthorized with default headers values
func NewGetAPIV1InventorySitesMetadataRulesUnauthorized() *GetAPIV1InventorySitesMetadataRulesUnauthorized {
	return &GetAPIV1InventorySitesMetadataRulesUnauthorized{}
}

/*
GetAPIV1InventorySitesMetadataRulesUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetAPIV1InventorySitesMetadataRulesUnauthorized struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory sites metadata rules unauthorized response has a 2xx status code
func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory sites metadata rules unauthorized response has a 3xx status code
func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites metadata rules unauthorized response has a 4xx status code
func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get Api v1 inventory sites metadata rules unauthorized response has a 5xx status code
func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get Api v1 inventory sites metadata rules unauthorized response a status code equal to that given
func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get Api v1 inventory sites metadata rules unauthorized response
func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) Code() int {
	return 401
}

func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites/metadata-rules][%d] getApiV1InventorySitesMetadataRulesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites/metadata-rules][%d] getApiV1InventorySitesMetadataRulesUnauthorized %s", 401, payload)
}

func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesMetadataRulesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetAPIV1InventorySitesMetadataRulesInternalServerError creates a GetAPIV1InventorySitesMetadataRulesInternalServerError with default headers values
func NewGetAPIV1InventorySitesMetadataRulesInternalServerError() *GetAPIV1InventorySitesMetadataRulesInternalServerError {
	return &GetAPIV1InventorySitesMetadataRulesInternalServerError{}
}

/*
GetAPIV1InventorySitesMetadataRulesInternalServerError describes a response with status code 500, with default header values.

Internal server error
*/
type GetAPIV1InventorySitesMetadataRulesInternalServerError struct {
	Payload *model.DtoErrResponse
}

// IsSuccess returns true when this get Api v1 inventory sites metadata rules internal server error response has a 2xx status code
func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get Api v1 inventory sites metadata rules internal server error response has a 3xx status code
func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get Api v1 inventory sites metadata rules internal server error response has a 4xx status code
func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get Api v1 inventory sites metadata rules internal server error response has a 5xx status code
func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get Api v1 inventory sites metadata rules internal server error response a status code equal to that given
func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) IsCode(code int) bool {
	return code == 500
}

// Code gets the status code for the get Api v1 inventory sites metadata rules internal server error response
func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) Code() int {
	return 500
}

func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites/metadata-rules][%d] getApiV1InventorySitesMetadataRulesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /api/v1/inventory/sites/metadata-rules][%d] getApiV1InventorySitesMetadataRulesInternalServerError %s", 500, payload)
}

func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) GetPayload() *model.DtoErrResponse {
	return o.Payload
}

func (o *GetAPIV1InventorySitesMetadataRulesInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(model.DtoErrResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
