package vwg.mcp_authz

import rego.v1

default allow := false

# The MCP Evaluation Engine
allow if {
    # 1. FIND THE TOOL RULE in our new mcp_rules.json
    some rule in data.mcp_rules.rules
    input.request.tool_name == rule.tool_name

    # 2. RBAC CHECK
    some user_role in input.token.roles
    user_role in rule.rbac.roles

    # 3. TENANT ISOLATION CHECK (AI Prompt Injection Defense)
    # Even if the LLM is tricked into asking for an Audi VIN, 
    # if the human's token is Porsche, OPA blocks it here.
    arg_key := rule.tenant_isolation.argument_key
    claim_key := rule.tenant_isolation.expected_token_claim
    
    # We check the arguments the AI provided against the human's token
    input.request.arguments[arg_key] == input.token[claim_key]

    # 4. ABAC CHECK
    every condition in rule.abac.match_all {
        condition.operator == "EQ"
        input.token[condition.attribute] == condition.value
    }
}