package terraform.gcp.iam

import future.keywords.in

# POLICY: No User-Managed Service Account Keys
# CONTROL: Credential Security (CIS GCP 1.4 / NIST IA-5)
# DESCRIPTION: User-managed service account keys are long-lived credentials
#              that are difficult to rotate and easy to leak. Prefer
#              short-lived credentials via Workload Identity Federation
#              or instance metadata instead.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_service_account_key"

    # key_type USER_MANAGED is the dangerous type (SYSTEM_MANAGED is fine)
    resource.change.after.key_type == "USER_MANAGED"

    msg := sprintf(
        "POLICY VIOLATION [CIS-GCP-1.4]: User-managed service account keys must not be created. Use Workload Identity Federation or instance metadata for authentication. Resource: %s",
        [resource.address]
    )
}

# Also flag if key_type is not set (defaults to USER_MANAGED in provider)
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_service_account_key"

    not resource.change.after.key_type

    msg := sprintf(
        "POLICY VIOLATION [CIS-GCP-1.4]: Service account key type not specified — defaults to USER_MANAGED. Explicitly set key_type or remove this resource entirely. Resource: %s",
        [resource.address]
    )
}
