import yaml
import json

def convert_mcp_to_policy(yaml_file_path, output_json_path):
    print(f"Loading MCP spec from: {yaml_file_path}...")
    
    # Load the YAML file
    try:
        with open(yaml_file_path, 'r') as file:
            spec = yaml.safe_load(file)
    except Exception as e:
        print(f"Failed to read YAML: {e}")
        return

    # Initialize the target JSON structure
    policy_doc = {
        "policy_type": "mcp_server",
        "version": "1.0",
        "rules": []
    }

    # Iterate through the MCP 'tools' array instead of OAS 'paths'
    for tool in spec.get("tools", []):
        
        # Skip if there's no x-mcp-authz block
        if "x-mcp-authz" not in tool:
            continue
            
        authz = tool["x-mcp-authz"]
        
        # 1. Base Rule Definition
        rule = {
            "tool_name": tool.get("name")
        }

        # 2. RBAC Mapping
        if "allowed_kira_roles" in authz:
            rule["rbac"] = {
                "logic": "ANY",
                "roles": authz["allowed_kira_roles"]
            }

        # 3. Tenant Isolation Mapping
        if "tenant_context" in authz:
            tc = authz["tenant_context"]
            if tc.get("require_jwt_match"):
                rule["tenant_isolation"] = {
                    "enabled": True,
                    "enforcement_type": "strict_match",
                    "argument_key": tc.get("argument_name"), # Uses argument_name instead of path_param
                    "expected_token_claim": tc.get("jwt_claim")
                }

        # 4. ABAC Mapping (Converts simple YAML attributes to JSON Operators)
        if "required_attributes" in authz:
            match_all_array = []
            for attr_key, attr_val in authz["required_attributes"].items():
                match_all_array.append({
                    "attribute": attr_key,
                    "operator": "EQ",  # Defaulting to an exact match
                    "value": attr_val
                })
            rule["abac"] = {
                "match_all": match_all_array
            }

        # Append the constructed rule
        policy_doc["rules"].append(rule)
        print(f"Extracted rule for tool: {tool.get('name')}")

    # Save to JSON
    with open(output_json_path, 'w') as outfile:
        json.dump(policy_doc, outfile, indent=2)
        
    print(f"\nSuccessfully generated MCP policy rules at: {output_json_path}")

if __name__ == "__main__":
    # Ensure you are pointing to the correct mcp.yaml file
    convert_mcp_to_policy("owner/mcp.yaml", "mcp_rules.json")