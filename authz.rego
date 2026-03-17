package vwg.authz

# 1. Use the modern Rego v1 syntax instead of future keywords
import rego.v1

# Default to deny
default allow := false

# The main evaluation block
# 2. Added the mandatory 'if' keyword here
allow if {
    # 1. FIND THE RULE: Loop through the JSON rules to find the matching endpoint and method
    some rule in data.policy.rules
    input.request.matched_route == rule.endpoint_pattern
    input.request.method in rule.methods

    # 2. RBAC CHECK: Does the user have at least one allowed role?
    some user_role in input.token.roles
    user_role in rule.rbac.roles

    # 3. TENANT ISOLATION CHECK
    # Look up the required parameter ("brand") and the required claim ("tenant_id") from the JSON
    url_param_key := rule.tenant_isolation.url_parameter
    token_claim_key := rule.tenant_isolation.expected_token_claim
    
    # Compare the actual values provided in the input
    input.request.path_params[url_param_key] == input.token[token_claim_key]

    # 4. ABAC CHECK: Iterate through the "match_all" array in the JSON
    every condition in rule.abac.match_all {
        # Currently, your JSON uses "EQ" (Equals). You can expand this later for "GTE", "IN", etc.
        condition.operator == "EQ"
        
        # Check if the user's token attribute exactly matches the required value in the JSON
        input.token[condition.attribute] == condition.value
    }

    # 5. USE-CASE CHECK
    header_name := rule.use_case_constraints.header_key
    input.request.headers[header_name] in rule.use_case_constraints.allowed_values
}