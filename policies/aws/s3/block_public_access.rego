package terraform.aws.s3

import future.keywords.in

# POLICY: S3 Public Access Must Be Blocked
# CONTROL: Data Exposure Prevention (CIS AWS 2.1.5 / NIST AC-3)
# DESCRIPTION: All S3 buckets must have all four public access block settings
#              enabled. Public S3 buckets are a leading cause of data breaches
#              in cloud environments.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"

    config := resource.change.after

    # All four settings must be explicitly true
    not config.block_public_acls == true

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-2.1.5]: S3 bucket 'block_public_acls' must be set to true. Resource: %s",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"

    config := resource.change.after
    not config.block_public_policy == true

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-2.1.5]: S3 bucket 'block_public_policy' must be set to true. Resource: %s",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"

    config := resource.change.after
    not config.ignore_public_acls == true

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-2.1.5]: S3 bucket 'ignore_public_acls' must be set to true. Resource: %s",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"

    config := resource.change.after
    not config.restrict_public_buckets == true

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-2.1.5]: S3 bucket 'restrict_public_buckets' must be set to true. Resource: %s",
        [resource.address]
    )
}
