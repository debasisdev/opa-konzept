import yaml
import json
import re

def convert_oas_to_policy(yaml_file_path, output_json_path):
    print(f"Loading OpenAPI spec from: {yaml_file_path}...")
    
    # Load the YAML file
    try:
        with open(yaml_file_path, 'r') as file:
            spec = yaml.safe_load(file)
    except Exception as e:
        print(f"Failed to read YAML: {e}")
        return

    # Initialize the target JSON structure
    policy_doc = {
        "api_group": "vehicle_telemetry_services", # You can make this dynamic based on OAS tags
        "version": "1.0",
        "rules": []
    }

    # Iterate through the OpenAPI paths and methods
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            
            # Skip if there's no x-authz block or it's a non-HTTP method property
            if method not in ['get', 'post', 'put', 'patch', 'delete'] or "x-authz" not in details:
                continue
                
            authz = details["x-authz"]
            
            # 1. Format the Endpoint Pattern
            # We want to keep the tenant param (e.g., {brand}) but turn others (e.g., {vin}) into *
            tenant_param = authz.get("tenant_context", {}).get("path_param", "")
            endpoint_pattern = path
            
            # Find all {parameters} in the URL
            url_params = re.findall(r'\{([^}]+)\}', path)
            for param in url_params:
                if param != tenant_param:
                    endpoint_pattern = endpoint_pattern.replace(f"{{{param}}}", "*")

            # Initialize the rule block
            rule = {
                "endpoint_pattern": endpoint_pattern,
                "methods": [method.upper()]
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
                        "url_parameter": tc.get("path_param"),
                        "expected_token_claim": tc.get("jwt_claim")
                    }

            # 4. ABAC Mapping (Converts simple YAML attributes to JSON Operators)
            if "required_attributes" in authz:
                match_all_array = []
                for attr_key, attr_val in authz["required_attributes"].items():
                    match_all_array.append({
                        "attribute": attr_key,
                        "operator": "EQ",  # Defaulting to an exact match (Equals)
                        "value": attr_val
                    })
                rule["abac"] = {
                    "match_all": match_all_array
                }

            # 5. Use-Case Constraints Mapping
            if "allowed_use_cases" in authz:
                rule["use_case_constraints"] = {
                    "header_key": "X-VWG-Use-Case", # Assuming standard corporate header
                    "allowed_values": authz["allowed_use_cases"]
                }

            # Append the constructed rule
            policy_doc["rules"].append(rule)

    # Save to JSON
    with open(output_json_path, 'w') as outfile:
        json.dump(policy_doc, outfile, indent=2)
        
    print(f"Successfully generated policy rules at: {output_json_path}")

if __name__ == "__main__":
    # Ensure you have 'oas.yaml' in the same directory, or update the paths below.
    convert_oas_to_policy("oas.yaml", "rules/rules.json")