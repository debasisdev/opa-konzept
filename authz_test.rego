package vwg.authz_test

import rego.v1

# Import the 'allow' rule from our main policy file
import data.vwg.authz.allow

# -----------------------------------------------------------------------------
# BASE MOCK DATA
# -----------------------------------------------------------------------------
# This is a perfectly valid request that should always result in 'true'
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
# TEST CASES
# -----------------------------------------------------------------------------

# TEST 1: The Happy Path
# Expectation: ALLOW
test_allow_valid_request if {
    # We use the 'with' keyword to inject our mock data as the 'input'
    allow with input as valid_input
}

# TEST 2: Tenant Isolation Check
# Scenario: An Audi employee tries to access Porsche vehicle data.
# Expectation: DENY (not allow)
test_deny_cross_tenant_access if {
    invalid_tenant_input := {
        "request": valid_input.request,
        "token": {
            "tenant_id": "audi",  # <--- CHANGED
            "roles": valid_input.token.roles,
            "data_clearance": valid_input.token.data_clearance,
            "region": valid_input.token.region
        }
    }
    # Notice the 'not'. The test passes if 'allow' evaluates to false.
    not allow with input as invalid_tenant_input
}

# TEST 3: RBAC Check
# Scenario: A Porsche employee from Marketing tries to run diagnostics.
# Expectation: DENY
test_deny_missing_role if {
    invalid_role_input := {
        "request": valid_input.request,
        "token": {
            "tenant_id": valid_input.token.tenant_id,
            "roles": ["Marketing_Manager"], # <--- CHANGED
            "data_clearance": valid_input.token.data_clearance,
            "region": valid_input.token.region
        }
    }
    not allow with input as invalid_role_input
}

# TEST 4: ABAC Check (Geofencing)
# Scenario: A US-based technician tries to pull EU vehicle data.
# Expectation: DENY
test_deny_wrong_region if {
    invalid_region_input := {
        "request": valid_input.request,
        "token": {
            "tenant_id": valid_input.token.tenant_id,
            "roles": valid_input.token.roles,
            "data_clearance": valid_input.token.data_clearance,
            "region": "US" # <--- CHANGED
        }
    }
    not allow with input as invalid_region_input
}

# TEST 5: Purpose-Bound Use-Case Check
# Scenario: App requests data for marketing instead of predictive maintenance.
# Expectation: DENY
test_deny_unapproved_use_case if {
    invalid_header_input := {
        "request": {
            "method": valid_input.request.method,
            "matched_route": valid_input.request.matched_route,
            "path_params": valid_input.request.path_params,
            "headers": { "X-VWG-Use-Case": "marketing_analytics" } # <--- CHANGED
        },
        "token": valid_input.token
    }
    not allow with input as invalid_header_input
}