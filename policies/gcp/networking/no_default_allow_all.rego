package terraform.gcp.networking

import future.keywords.in

# POLICY: No Firewall Rules Allowing All Traffic (0.0.0.0/0)
# CONTROL: Network Boundary Protection (CIS GCP 3.6 / NIST SC-7)
# DESCRIPTION: GCP firewall rules must not allow unrestricted inbound access
#              from the internet. Open firewall rules expose resources to
#              unauthorized access and reconnaissance.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"

    config := resource.change.after
    config.direction == "INGRESS"

    source_range := config.source_ranges[_]
    source_range == "0.0.0.0/0"

    msg := sprintf(
        "POLICY VIOLATION [CIS-GCP-3.6]: Firewall rule allows ingress from 0.0.0.0/0. Restrict source_ranges to known CIDR blocks. Resource: %s",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"

    config := resource.change.after
    config.direction == "INGRESS"

    source_range := config.source_ranges[_]
    source_range == "::/0"

    msg := sprintf(
        "POLICY VIOLATION [CIS-GCP-3.6]: Firewall rule allows ingress from ::/0 (all IPv6). Restrict source_ranges to known CIDR blocks. Resource: %s",
        [resource.address]
    )
}

# Catch rules with no direction set (defaults to INGRESS) + open range
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "google_compute_firewall"

    config := resource.change.after
    not config.direction

    source_range := config.source_ranges[_]
    source_range in ["0.0.0.0/0", "::/0"]

    msg := sprintf(
        "POLICY VIOLATION [CIS-GCP-3.6]: Firewall rule (direction defaults to INGRESS) allows traffic from open CIDR '%s'. Restrict source_ranges. Resource: %s",
        [source_range, resource.address]
    )
}
