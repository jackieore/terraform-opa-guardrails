package terraform.azure.storage

import future.keywords.in

# POLICY: Azure Storage — HTTPS Traffic Only
# CONTROL: Data in Transit Protection (CIS Azure 3.1 / NIST SC-8)
# DESCRIPTION: Azure storage accounts must enforce HTTPS-only traffic.
#              Allowing HTTP exposes data to interception during transmission.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"

    # https_traffic_only_enabled must be explicitly true
    not resource.change.after.https_traffic_only_enabled == true

    msg := sprintf(
        "POLICY VIOLATION [CIS-AZURE-3.1]: Storage account must have 'https_traffic_only_enabled' set to true. Resource: %s",
        [resource.address]
    )
}

# Also enforce minimum TLS version
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"

    tls := resource.change.after.min_tls_version
    not tls in ["TLS1_2", "TLS1_3"]

    msg := sprintf(
        "POLICY VIOLATION [CIS-AZURE-3.2]: Storage account minimum TLS version must be TLS1_2 or higher. Found: '%s'. Resource: %s",
        [tls, resource.address]
    )
}
