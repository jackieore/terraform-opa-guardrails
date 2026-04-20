package terraform.aws.s3

import future.keywords.in

# POLICY: S3 Encryption Required
# CONTROL: Data Protection at Rest (CIS AWS 2.1.1 / NIST SC-28)
# DESCRIPTION: All S3 buckets must have server-side encryption enabled.
#              Unencrypted buckets risk exposing sensitive data if access
#              controls are misconfigured or bypassed.

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"

    # Check that no encryption configuration exists
    not has_encryption(resource)

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-2.1.1]: S3 bucket has no server-side encryption configured. Add an aws_s3_bucket_server_side_encryption_configuration resource. Resource: %s",
        [resource.address]
    )
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"

    rules := resource.change.after.rule[_]
    apply := rules.apply_server_side_encryption_by_default[_]

    # SSE-S3 and SSE-KMS are both acceptable; reject anything else or missing
    not apply.sse_algorithm in ["aws:kms", "AES256"]

    msg := sprintf(
        "POLICY VIOLATION [CIS-AWS-2.1.1]: S3 bucket encryption uses an unsupported algorithm. Use 'aws:kms' or 'AES256'. Resource: %s",
        [resource.address]
    )
}

# Helper: check if a separate encryption config resource references this bucket
has_encryption(bucket_resource) {
    enc := input.resource_changes[_]
    enc.type == "aws_s3_bucket_server_side_encryption_configuration"
    enc.change.after.bucket == bucket_resource.change.after.bucket
}
