package terraform.aws.networking

import future.keywords.in

# POLICY: No Open Ingress (0.0.0.0/0 or ::/0)
# CONTROL: Network Boundary Protection (CIS AWS 5.2 / NIST SC-7)
# DESCRIPTION: Security groups must not allow inbound traffic from any IP
#              address. Open ingress rules expose resources to the public
#              internet and are a common attack vector.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"

    ingress := resource.change.after.ingress[_]
    cidr := ingress.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-5.2]: Security group allows ingress from 0.0.0.0/0 on port(s) %v. Restrict to known CIDR ranges. Resource: %s",
        [ingress.from_port, resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"

    ingress := resource.change.after.ingress[_]
    cidr := ingress.ipv6_cidr_blocks[_]
    cidr == "::/0"

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-5.2]: Security group allows ingress from ::/0 (all IPv6) on port(s) %v. Restrict to known CIDR ranges. Resource: %s",
        [ingress.from_port, resource.address]
    )
}

# Also catch aws_security_group_rule resources defined separately
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.after.type == "ingress"

    cidr := resource.change.after.cidr_blocks[_]
    cidr == "0.0.0.0/0"

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-5.2]: Security group rule allows ingress from 0.0.0.0/0. Restrict to known CIDR ranges. Resource: %s",
        [resource.address]
    )
}
