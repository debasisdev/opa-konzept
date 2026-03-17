package vwg.authz_test

import rego.v1
import data.vwg.authz.allow

# -----------------------------------------------------------------------------
# 1. MOCK POLICY DATA (Simulates rules.json)
# -----------------------------------------------------------------------------
mock_policy_data := {
    "rules": [
        {
            "endpoint_pattern": "/api/v1/brands/{brand}/vehicles/*/battery-status",
            "methods": ["GET"],
            "rbac": {
                "logic": "ANY",
                "roles": ["App_FleetMon_Admin", "Global_Diagnostic_Tech", "Dealer_Service_Agent"]
            },
            "tenant_isolation": {
                "enabled": true,
                "enforcement_type": "strict_match",
                "url_parameter": "brand",
                "expected_token_claim": "tenant_id"
            },
            "abac": {
                "match_all": [
                    { "attribute": "data_clearance", "operator": "EQ", "value": "confidential" },
                    { "attribute": "region", "operator": "EQ", "value": "EU" }
                ]
            },
            "use_case_constraints": {
                "header_key": "X-VWG-Use-Case",
                "allowed_values": ["predictive_maintenance", "remote_roadside_assistance"]
            }
        }
    ]
}

# -----------------------------------------------------------------------------
# 2. MOCK REQUEST INPUT (The Happy Path)
# -----------------------------------------------------------------------------
valid_input := {
    "request": {
        "method": "GET",
        "matched_route": "/api/v1/brands/{brand}/vehicles/*/battery-status",
        "path_params": { "brand": "porsche", "vin": "WP0123456789" },
        "headers": { "X-VWG-Use-Case": "predictive_maintenance" }
    },
    "token": {
        "tenant_id": "porsche",
        "roles": ["Global_Diagnostic_Tech"],
        "data_clearance": "confidential",
        "region": "EU"
    }
}

# -----------------------------------------------------------------------------
# 3. TEST CASES
# -----------------------------------------------------------------------------

test_allow_valid_request if {
    # Notice we now inject BOTH the input AND the mocked JSON data
    allow with input as valid_input
          with data.rules as mock_policy_data
}

test_deny_cross_tenant_access if {
    invalid_tenant_input := {
        "request": valid_input.request,
        "token": {
            "tenant_id": "audi", 
            "roles": valid_input.token.roles,
            "data_clearance": valid_input.token.data_clearance,
            "region": valid_input.token.region
        }
    }
    not allow with input as invalid_tenant_input
              with data.rules as mock_policy_data
}

test_deny_missing_role if {
    invalid_role_input := {
        "request": valid_input.request,
        "token": {
            "tenant_id": valid_input.token.tenant_id,
            "roles": ["Marketing_Manager"], 
            "data_clearance": valid_input.token.data_clearance,
            "region": valid_input.token.region
        }
    }
    not allow with input as invalid_role_input
              with data.rules as mock_policy_data
}

test_deny_wrong_region if {
    invalid_region_input := {
        "request": valid_input.request,
        "token": {
            "tenant_id": valid_input.token.tenant_id,
            "roles": valid_input.token.roles,
            "data_clearance": valid_input.token.data_clearance,
            "region": "US" 
        }
    }
    not allow with input as invalid_region_input
              with data.rules as mock_policy_data
}

test_deny_unapproved_use_case if {
    invalid_header_input := {
        "request": {
            "method": valid_input.request.method,
            "matched_route": valid_input.request.matched_route,
            "path_params": valid_input.request.path_params,
            "headers": { "X-VWG-Use-Case": "marketing_analytics" } 
        },
        "token": valid_input.token
    }
    not allow with input as invalid_header_input
              with data.rules as mock_policy_data
}