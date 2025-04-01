# LOC-A client code generation

To generate [client/model](../pkg/api/loca/) folder, run [swagger-gen](../Makefile) target from root folder of the repo.
However, the LOC-A swagger specification contains several manual fixes to endpoints/APIs, which got reported to Lenovo and
in the meanwhile we manually fixed them in the swagger file:

1. `/api/v1/inventory/repository/upload` - added correct content type for request and paramType for `file`
2. `/api/v1/auth/login` - added correct return struct with `token` and `refresh_token`
3. `dto.CreateTemplateRequest.properties` - added missing `kind` field
4. `dto.CreateUpdateTemplateDevice.properties` - added missing `kind` field
5. `/api/v1/inventory/devices/remove` - added correct return status code `201` for successful deletion
6. `/api/v1/inventory/devices/{id}/update` - added correct return status code `200` for successful device update
7. `/api/v1/auth/refresh-token` - removed `token` from the path and added correct properties for `data` in UserRefreshTokenResponse
8. `/api/v1/secrets/credential-policies` - POST changed response code from 201 to 200
9. `/api/v1/deployment/instances/deploy` - added correct return status code `200` for successful instance deploy
10. `/api/v1/inventory/sites/remove` - POST changed response code from `200` to `201`
11. `/api/v1/inventory/cloud-services/remove` - POST changed response code from `200` to `201`
