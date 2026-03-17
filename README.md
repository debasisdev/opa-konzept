When a user requests the battery status endpoint, your API Gateway (like Kong or AWS API Gateway) pauses the request, decodes the user's Role JWT, and sends a JSON payload to OPA.

It needs to look something like this:

```json
{
  "input": {
    "request": {
      "method": "GET",
      "matched_route": "/api/v1/brands/{brand}/vehicles/*/battery-status",
      "path_params": {
        "brand": "porsche",
        "vin": "WP0123456789"
      },
      "headers": {
        "X-VWG-Use-Case": "predictive_maintenance"
      }
    },
    "token": {
      "tenant_id": "porsche",
      "roles": ["Global_Diagnostic_Tech", "Standard_Employee"],
      "data_clearance": "confidential",
      "region": "EU"
    }
  }
}
```

To run the OPA evaluation against this payload, use:

```bash
opa eval -i input.json -d gw.json -d authz.rego "data.vwg.authz.allow"
```