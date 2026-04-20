package terraform.azure.iam

import future.keywords.in

# POLICY: No Owner Role Assignment at Subscription Scope
# CONTROL: Least Privilege (CIS Azure 1.23 / NIST AC-6)
# DESCRIPTION: The Owner role grants full control over all Azure resources
#              including the ability to assign roles. Assigning Owner at the
#              subscription scope is overly permissive and should be avoided
#              in favor of more targeted role assignments.

# Owner role definition ID (built-in, consistent across all Azure tenants)
owner_role_id := "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"

    config := resource.change.after

    # Check for Owner role by definition ID or name
    contains(config.role_definition_id, owner_role_id)

    # At subscription scope (scope is just the subscription resource ID)
    regex.match(`^/subscriptions/[^/]+$`, config.scope)

    msg := sprintf(
        "POLICY VIOLATION [CIS-AZURE-1.23]: Owner role must not be assigned at subscription scope. Use a more targeted scope or a less permissive role. Resource: %s",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_role_assignment"

    config := resource.change.after

    config.role_definition_name == "Owner"
    regex.match(`^/subscriptions/[^/]+$`, config.scope)

    msg := sprintf(
        "POLICY VIOLATION [CIS-AZURE-1.23]: Owner role must not be assigned at subscription scope. Use a more targeted scope or a less permissive role. Resource: %s",
        [resource.address]
    )
}
