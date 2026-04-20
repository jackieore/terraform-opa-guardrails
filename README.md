# 🛡️ terraform-opa-guardrails
 
A multi-cloud library of **preventative OPA/Rego policies** for Terraform — designed to catch misconfigurations before they reach production.
 
These policies enforce security controls at plan time, shifting security left into the development workflow rather than detecting issues after deployment.
 
---
 
## 📋 Table of Contents
 
- [Why Preventative Policies](#why-preventative-policies)
- [Policy Library](#policy-library)
- [Quick Start](#quick-start)
- [CI/CD Integration](#cicd-integration)
- [Policy Structure](#policy-structure)
- [Framework Alignment](#framework-alignment)
- [Contributing](#contributing)
---
 
## Why Preventative Policies
 
Reactive security finds problems after they exist. Preventative policies stop them from being introduced in the first place.
 
By evaluating Terraform plans against OPA/Rego policies in CI/CD:
 
- Misconfigurations are **blocked before deployment**, not discovered after
- Security requirements become **enforceable code**, not documentation
- Engineers receive **fast, specific feedback** early in the development cycle
- Compliance evidence is generated **automatically** as part of the pipeline
---
 
## Policy Library
 
### ☁️ AWS
 
| Policy | File | Control |
|--------|------|---------|
| No wildcard IAM actions | `policies/aws/iam/no_wildcard_actions.rego` | Least privilege |
| S3 encryption required | `policies/aws/s3/encryption_required.rego` | Data protection |
| S3 public access blocked | `policies/aws/s3/block_public_access.rego` | Data exposure |
| No open ingress (0.0.0.0/0) | `policies/aws/networking/no_open_ingress.rego` | Network security |
 
### 🔷 Azure
 
| Policy | File | Control |
|--------|------|---------|
| HTTPS only on storage | `policies/azure/storage/https_only.rego` | Data in transit |
| No broad RBAC assignments | `policies/azure/iam/no_owner_at_subscription.rego` | Least privilege |
 
### 🟡 GCP
 
| Policy | File | Control |
|--------|------|---------|
| No service account admin keys | `policies/gcp/iam/no_sa_admin_keys.rego` | Credential security |
| Firewall: no default allow-all | `policies/gcp/networking/no_default_allow_all.rego` | Network security |
 
---
 
## Quick Start
 
### Prerequisites
 
```bash
# Install OPA
brew install opa        # macOS
# or
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa && mv opa /usr/local/bin/
```
 
### Run All Tests
 
```bash
opa test ./policies -v
```
 
### Evaluate a Policy Against a Terraform Plan
 
```bash
# Generate a Terraform plan as JSON
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
 
# Evaluate against a policy
opa eval \
  --input tfplan.json \
  --data policies/aws/iam/no_wildcard_actions.rego \
  "data.terraform.aws.iam.deny"
```
 
---
 
## CI/CD Integration
 
Add this GitHub Actions workflow to enforce policies on every pull request:
 
```yaml
# .github/workflows/opa-policy-check.yml
name: OPA Policy Check
 
on:
  pull_request:
    paths:
      - '**.tf'
 
jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
 
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v2
 
      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
          chmod +x opa && sudo mv opa /usr/local/bin/
 
      - name: Terraform Init & Plan
        run: |
          terraform init
          terraform plan -out=tfplan.binary
          terraform show -json tfplan.binary > tfplan.json
 
      - name: Run OPA Tests
        run: opa test ./policies -v
 
      - name: Evaluate Policies Against Plan
        run: |
          opa eval \
            --input tfplan.json \
            --data policies/ \
            --format pretty \
            "data.terraform.deny"
```
 
---
 
## Policy Structure
 
Each policy follows a consistent pattern:
 
```
policies/
  {cloud}/
    {domain}/
      {policy_name}.rego       # Policy logic
      {policy_name}_test.rego  # Unit tests
```
 
### Policy Template
 
```rego
package terraform.{cloud}.{domain}
 
import future.keywords.in
 
# Deny rule with descriptive message
deny[msg] {
    # Access Terraform resource from plan
    resource := input.resource_changes[_]
    resource.type == "{resource_type}"
    
    # Define violation condition
    {condition}
    
    # Return human-readable message
    msg := sprintf("POLICY VIOLATION [%s]: {description}. Resource: %s",
        ["{CONTROL_ID}", resource.address])
}
```
 
---
 
## Framework Alignment
 
Policies in this library map to industry security frameworks:
 
| Policy | CIS Benchmark | NIST 800-53 |
|--------|--------------|-------------|
| No wildcard IAM | CIS AWS 1.16 | AC-6 (Least Privilege) |
| S3 encryption required | CIS AWS 2.1.1 | SC-28 (Protection at Rest) |
| S3 public access blocked | CIS AWS 2.1.5 | AC-3 (Access Enforcement) |
| No open ingress | CIS AWS 5.2 | SC-7 (Boundary Protection) |
| HTTPS only (Azure) | CIS Azure 3.1 | SC-8 (Transmission Confidentiality) |
| No SA admin keys (GCP) | CIS GCP 1.4 | IA-5 (Authenticator Management) |
 
---
 
## About
 
Built by [Jacqueline Ore](https://jackieore.com) — Cloud Security Engineer focused on DevSecOps, IAM, and secure infrastructure at scale.
 
[![LinkedIn](https://img.shields.io/badge/LinkedIn-jackieore-blue)](https://linkedin.com/in/jackieore)
[![GitHub](https://img.shields.io/badge/GitHub-jackieore-black)](https://github.com/jackieore)