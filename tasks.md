# Implementation Plan: AWS Cyber Recovery — Protected Recovery Environment (PRE)

## Overview

This plan breaks down the PRE implementation into eleven sequential epics that build from the AWS Organization foundation through to full audit trail and compliance monitoring. Each epic produces code and configuration that is immediately wired into the previous epic's outputs. All Terraform modules are sourced from the ISO Environment GitHub repository and executed via the Azure DevOps pipeline runner; no Terraform state is stored in the PRE account.

The implementation language is **Terraform (HCL)** for all infrastructure-as-code, **Python 3.12** for all Lambda functions, and **pytest-hypothesis** for property-based tests executed in the ISO Terraform runner environment.

---

## Tasks

- [ ] 1. Foundation — AWS Organizations, PRE Account Structure, and SCPs
  - [ ] 1.1 Create CyberRecovery Organizational Unit and account baseline
    - Create `OU=CyberRecovery` under the existing AWS Organizations root structure if not already present; Account A (Prod+PRE), Account B (IRE), and Account C (ISO) are all enrolled in this OU
    - **Note**: There is no separate "PRE account" to enroll — Prod VPC (`eu-west-1`, `10.0.0.0/16`) and PRE/DR VPC (`eu-central-1`, `10.1.0.0/16`) both reside in Account A; the OU membership already covers Account A as a whole
    - Enable AWS CloudTrail multi-region trail and AWS Config recorder in Account A covering all regions, including both `eu-west-1` (Prod) and `eu-central-1` (PRE), as a prerequisite for all subsequent resources
    - Apply resource tags `Environment=PRE` to all PRE VPC resources and `Environment=Prod` to all Prod VPC resources within Account A for disambiguation in CloudWatch filters, Config rules, and IAM conditions
    - _Requirements: 3.1, 3.4, 3.5_

  - [ ] 1.2 Implement Service Control Policies and attach to CyberRecovery OU
    - **Note**: Since Prod VPC and PRE VPC reside in the same Account A, `PRE-DenyProdAccountTrust` (which targeted a separate Prod account ID) is NOT applicable — intra-account Prod/PRE isolation is enforced via IAM permission boundaries, role trust policies, and resource-based DENY policies on PRE KMS keys and S3 buckets
    - Write Terraform for `PRE-DenyExternalVPCPeering` SCP: deny `ec2:AcceptVpcPeeringConnection` and `ec2:CreateVpcPeeringConnection` for any peering request from accounts outside the OU (protects all three accounts — A, B, and C)
    - Write Terraform for `PRE-RequireMFAForSensitiveActions` SCP (deny KMS key admin, IAM role mutation without MFA) — applies OU-wide to Account A, Account B, and Account C
    - Write Terraform for `PRE-DenyKMSKeyDeletion` SCP (deny `kms:ScheduleKeyDeletion` and `kms:DisableKey` for all principals except Organizations root) — applies OU-wide
    - Write Terraform for `PRE-AllowOnlyEUCentral1AndISORegion` SCP (region lock) — apply to Account B (IRE) **only**; Account A must remain multi-region since Prod operates in `eu-west-1` and PRE operates in `eu-central-1`
    - Attach SCPs to the `OU=CyberRecovery` OU; apply the region-lock SCP as an Account B-level attachment only
    - _Requirements: 3.4, 3.5, 3.6, 4.5_

  - [ ]* 1.3 Write property test for PRE role regional isolation
    - **Property 4: Intra-Account Role Trust Isolation**
    - For all PRE roles (`pre-*`) in Account A, simulate `sts:AssumeRole` and assert the resulting session cannot perform EC2 or IAM actions in `eu-west-1` (blocked by `PREPermissionBoundary` region lock to `eu-central-1`)
    - Also enumerate all `pre-*` role trust policies via boto3 and assert no trust policy lists any `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*` ARN, any Prod EC2 service principal (`ec2.amazonaws.com` without a PRE-scoped condition), or any Prod Lambda service principal
    - **Validates: Requirements 3.4, 3.5**

  - [ ]* 1.4 Write property test for SCP MFA enforcement
    - **Property 5: MFA Required for Sensitive API Actions**
    - Simulate `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `iam:AttachRolePolicy`, `iam:DeleteRole` without MFA context against the PRE account; assert all return `Deny`
    - **Validates: Requirements 3.6**

  - [ ] 1.5 Checkpoint — Foundation
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 2. Network — VPC, Subnets, NACLs, Security Groups, Route Tables
  - [ ] 2.1 Provision PRE VPC and subnet structure
    - Create `vpc-pre-eu-central-1` with CIDR `10.1.0.0/16`; enable DNS hostnames and DNS resolution
    - Create all eight subnets per design: `pre-mgmt-a` (`10.1.0.0/25`), `pre-mgmt-b` (`10.1.0.128/25`), `pre-workload-a` (`10.1.1.0/25`), `pre-workload-b` (`10.1.1.128/25`), `pre-scan-a` (`10.1.2.0/25`), `pre-scan-b` (`10.1.2.128/25`), `pre-egress-a` (`10.1.3.0/25`), `pre-tgw-attach` (`10.1.4.0/28`)
    - Create four dedicated route tables: `rt-pre-mgmt`, `rt-pre-workload`, `rt-pre-scan`, `rt-pre-egress`; associate each subnet with its correct route table
    - Create NAT Gateway in `pre-egress-a`; add default route `0.0.0.0/0 → nat-gw` to `rt-pre-workload` only
    - Add static route `10.2.0.0/16 → tgw-attach` to `rt-pre-mgmt` and `rt-pre-workload`
    - _Requirements: 2.1, 2.4, 2.5_

  - [ ] 2.2 Implement NACLs for all subnet categories
    - Create `nacl-pre-mgmt`: inbound DENY rule ≤ 50 for `10.0.0.0/16` (all protocols); outbound DENY rule ≤ 50 for `10.0.0.0/16`; ALLOW rules per design for ISO CIDR, ephemeral, SSH; associate with both management subnets
    - Create `nacl-pre-workload`: inbound DENY rule ≤ 50 for `10.0.0.0/16`; outbound DENY rule ≤ 50 for `10.0.0.0/16`; ALLOW SSH/RDP only from `10.1.0.0/24`; associate with both workload subnets
    - Create `nacl-pre-scan`: inbound/outbound DENY for `10.0.0.0/16`; associate with both scan subnets
    - Create `nacl-pre-egress`: outbound ALLOW `0.0.0.0/0` TCP 443; associate with egress subnet
    - _Requirements: 1.2, 1.3, 2.2_

  - [ ]* 2.3 Write property test for network isolation invariant
    - **Property 1: Network Isolation Invariant**
    - Enumerate all NACL rules across PRE subnets via boto3; assert no ALLOW rule exists for source/dest `10.0.0.0/16`; assert DENY rules are numbered ≤ 50 and evaluated before any ALLOW rule numbered > 50
    - **Validates: Requirements 1.2, 1.3, 1.4**

  - [ ] 2.4 Implement Security Groups
    - Create `sg-pre-workload`: inbound SSH/RDP/HTTPS from `sg-pre-mgmt-bastion`; inbound ALL from `sg-pre-scan-tools`; outbound TCP 443 and TCP 8732 and UDP 53
    - Create `sg-pre-mgmt-bastion`: inbound TCP 443 and TCP 22 from ISO CIDR `10.2.0.0/16`; outbound SSH/RDP to workload subnet; outbound HTTPS to ISO
    - Create `sg-pre-scan-tools`: inbound TCP 8732 and TCP 443 from ISO CIDR; outbound TCP 8732 and TCP 443 to `0.0.0.0/0`; outbound ALL to `sg-pre-workload`
    - Create `sg-pre-quarantine`: inbound NONE; outbound NONE — used for isolation of compromised instances
    - Create `sg-pre-vpc-endpoints`: inbound TCP 443 from `10.1.0.0/16`
    - _Requirements: 2.2, 2.3, 6.2, 13.1_

  - [ ]* 2.5 Write property test for TGW route config rule correctness
    - **Property 27: TGW Route Config Rule Correctness**
    - Enumerate PRE TGW route table entries; assert no entry with destination `10.0.0.0/16` has a target other than `blackhole`; assert any such blackhole route causes Config rule `tgw-no-prod-routes` to evaluate `COMPLIANT`
    - **Validates: Requirements 1.6, 12.4**

- [ ] 3. TGW Attachment, VPC Endpoints, Flow Logs, and Route 53 Resolver
  - [ ] 3.1 Configure Transit Gateway attachment and route tables
    - Accept the RAM resource share for the Transit Gateway (owned by Account C/ISO) in Account A (Prod+PRE account) — the TGW is shared via AWS RAM and Account A must accept the share before creating attachments
    - Accept the RAM resource share for the Transit Gateway in Account B (IRE account) as well (required for security tool callbacks to Account C ISO)
    - Create a NEW TGW attachment for the PRE VPC in Account A using subnet `pre-tgw-attach` (`10.1.4.0/28`); enable DNS support — NOTE: Account A already has an existing TGW attachment for the Prod VPC (`eu-west-1`); the PRE VPC gets a separate, additional attachment in the same account
    - Create isolated TGW route table `rt-pre-tgw-isolated` (managed by Account C); associate PRE VPC attachment; add static routes `10.1.0.0/16 → pre-vpc-attachment` and `10.2.0.0/16 → iso-attachment`
    - Add blackhole route `10.0.0.0/16 → blackhole` to `rt-pre-tgw-isolated` — this blackholes the Prod VPC CIDR (Account A, `eu-west-1`) within the same account to prevent any traffic path from PRE VPC to Prod VPC via TGW during an incident
    - Add `10.2.0.0/16 → tgw-attach` to `rt-pre-tgw` subnet route table in Account A
    - _Requirements: 1.1, 1.4, 11.1_

  - [ ] 3.2 Deploy VPC Interface and Gateway Endpoints
    - Create Gateway Endpoint for S3 (`vpce-pre-s3`); associate with all route tables
    - Create Interface Endpoints for SSM (`vpce-pre-ssm`), SSM Messages (`vpce-pre-ssmmessages`), EC2 Messages (`vpce-pre-ec2messages`), KMS (`vpce-pre-kms`), Secrets Manager (`vpce-pre-secretsmanager`), CloudTrail (`vpce-pre-cloudtrail`), Config (`vpce-pre-config`), ECR API (`vpce-pre-ecr-api`), ECR DKR (`vpce-pre-ecr-dkr`); deploy in management and workload subnets; attach `sg-pre-vpc-endpoints`
    - _Requirements: 1.7_

  - [ ] 3.3 Enable VPC Flow Logs
    - Create CloudWatch Log Group `/pre/vpc-flow-logs` with 90-day retention
    - Create S3 bucket `pre-vpc-flow-logs-<ACCOUNT_ID>` (Object Lock COMPLIANCE, 7-year retention, SSE-KMS with `alias/pre-s3`)
    - Enable VPC Flow Logs on `vpc-pre-eu-central-1` with traffic type ALL; deliver to both the CloudWatch Log Group and the S3 bucket
    - _Requirements: 1.5, 10.3_

  - [ ] 3.4 Configure Route 53 Resolver outbound endpoint and forwarding rules
    - Create Route 53 Resolver outbound endpoint `pre-resolver-outbound` with two IPs: `10.1.0.10` (mgmt-a) and `10.1.0.138` (mgmt-b); security group `sg-pre-mgmt-bastion`
    - Create Resolver forwarding rule for `corp.internal` → ISO DNS inbound endpoint IP
    - Create Resolver forwarding rule for `internal.aws` → ISO DNS inbound endpoint IP
    - Associate both rules with the PRE VPC
    - _Requirements: 1.8, 11.3_

  - [ ] 3.5 Checkpoint — Network layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 4. Identity — IAM Roles, Permission Boundaries, and SAML Federation
  - [ ] 4.1 Create PREPermissionBoundary policy
    - Write `PREPermissionBoundary` IAM managed policy in Terraform for Account A
    - **Region lock (primary intra-account isolation mechanism)**: allow all actions in `eu-central-1` only — since Prod VPC operates in `eu-west-1`, this region lock prevents PRE roles from taking any action against Prod VPC resources, Prod KMS keys, or Prod IAM roles in `eu-west-1`
    - **Remove** cross-account `sts:AssumeRole` deny (no longer applicable — Prod and PRE share Account A, so there is no separate "Prod account ID" to target)
    - Add: deny `ec2:CreateVpcPeeringConnection` targeting Prod VPC CIDR range (`10.0.0.0/16`) to prevent any PRE role from establishing a peering path to the Prod VPC
    - Add: deny all KMS actions (`kms:*`) on key ARNs NOT matching `alias/pre-*` (prevents PRE roles from using or administering Prod KMS keys that share Account A)
    - Keep: deny `kms:DisableKey`, `kms:ScheduleKeyDeletion`, `kms:DeleteImportedKeyMaterial`
    - Keep: deny IAM privilege-escalation actions unless principal tag `Role = pre-dr-admin`
    - Keep: deny all mutations to the `pre-break-glass` role (`iam:UpdateRole`, `iam:DeleteRole`, `iam:DetachRolePolicy`, `iam:DeleteRolePolicy`)
    - _Requirements: 3.3, 3.7, 3.8_

  - [ ] 4.2 Implement all eight PRE IAM roles
    - Create `pre-dr-admin` with SAML trust from `ISOADProvider` (Account A SAML provider), MFA condition, `PREPermissionBoundary`, `PREAdminPolicy`, and `ReadOnlyAccess`
    - Create `pre-dr-network-admin` with SAML trust, MFA condition, `PREPermissionBoundary`, and network-scoped policy
    - Create `pre-dr-kms-admin` with SAML trust, MFA condition, `PREPermissionBoundary`, and `PREKMSAdminPolicy` (key admin only, explicit deny data ops)
    - Create `pre-dr-readonly` with SAML trust, MFA condition, `PREPermissionBoundary`, and `ReadOnlyAccess`
    - Create `pre-break-glass` with dedicated `pre-break-glass-activator` Lambda ARN trust (Account A), MFA condition, `AdministratorAccess`, max session 3600 seconds, `PREPermissionBoundary`; additionally attach a resource-based DENY policy on the `pre-break-glass` role itself denying `sts:AssumeRole` from any principal matching `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*` — this prevents any Prod role in Account A from assuming the break-glass role
    - Create `pre-automation-deploy` with Azure DevOps OIDC trust (Account C ISO runner), no permission boundary, deploy-scoped policy (no data ops, no console)
    - Create `pre-workload-instance` as an EC2 instance profile role with SSM, S3 read for artifacts, CloudWatch Logs
    - Create `pre-scan-tool-access` as an EC2 instance profile role for security tool agents: `ssm:GetParameter` on `/pre/*/`, `s3:PutObject` on `pre-scan-results-*`, `cloudwatch:PutMetricData`
    - _Requirements: 3.1, 3.2, 3.3, 3.7, 3.8_

  - [ ]* 4.3 Write property test for IAM role MFA requirement
    - **Property 2: IAM Role MFA Requirement**
    - Enumerate all human-assumed PRE roles (all except `pre-automation-deploy` and `pre-workload-instance`); simulate `sts:AssumeRoleWithSAML` without MFA context; assert all simulations return `Deny`
    - **Validates: Requirements 3.2**

  - [ ]* 4.4 Write property test for permission boundary coverage
    - **Property 3: Permission Boundary Coverage**
    - Enumerate all IAM roles in PRE account via boto3; assert every human-assumed role has `PermissionsBoundary` ARN referencing `PREPermissionBoundary`; simulate IAM privilege-escalation actions (non-admin role) and assert `Deny`
    - **Validates: Requirements 3.3, 3.7**

  - [ ] 4.5 Configure SAML federation from ISO AD ADFS
    - Create SAML identity provider `ISOADProvider` in Account A (the Prod+PRE account) pointing to the ADFS federation metadata XML from the ISO environment (Account C)
    - Configure AWS IAM Identity Center with TWO distinct permission set assignments in Account A:
      - `DRAdminAccess` permission set → maps to `pre-*` IAM roles in `eu-central-1` (DR admins only)
      - `ProdAdminAccess` permission set → maps to Prod IAM roles in `eu-west-1` (Prod admins only); no overlap with DR admin permission sets
    - Verify AD group-to-permission-set mappings: `dr-pre-admins → DRAdminAccess`, `dr-break-glass → BreakGlassAccess`; ensure AD groups `dr-pre-admins` and `prod-admins` reside in separate AD OUs (`OU=PRE,OU=CyberRecovery` vs `OU=Production`) with no group membership overlap between them
    - Configure LDAPS connectivity: add ALLOW rule for port 636 from ISO CIDR `10.2.0.0/16` to management NACL; add DENY rule for port 389 from non-ISO sources
    - _Requirements: 3.2, 11.2, 11.4_

  - [ ] 4.6 Checkpoint — Identity layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. KMS — Independent PRE Key Hierarchy
  - [ ] 5.1 Provision all six PRE KMS keys with policies
    - Create six symmetric KMS keys: `alias/pre-ebs`, `alias/pre-s3`, `alias/pre-secrets`, `alias/pre-cloudtrail`, `alias/pre-rds`, `alias/pre-workload`; all in `eu-central-1` within Account A
    - Apply the KMS key policy template to each key: `EnableKeyAdministration` (pre-dr-kms-admin + account root); `AllowPREWorkloadUsage` (pre-dr-admin, pre-workload-instance, pre-automation-deploy, via-service condition)
    - **Replace** `DenyProductionAccountAccess` (which used cross-account syntax `arn:aws:iam::<PROD_ACCOUNT_ID>:*`) with the following intra-account deny statements, since Prod and PRE share Account A:
      - `DenyProdRoleAccess`: deny `kms:*` for any principal matching `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*` (intra-account role name prefix)
      - `DenyProdTaggedPrincipalAccess`: deny `kms:*` for any principal tagged `Environment=Prod` via `aws:PrincipalTag/Environment`
    - `DenyKeyDeletionByAll`: deny `kms:ScheduleKeyDeletion` and `kms:DisableKey` for all principals except account root — unchanged
    - Enable automatic annual rotation on all six keys
    - Set deletion window: 7 days for `alias/pre-workload`; 30 days for all others
    - _Requirements: 4.1, 4.2, 4.4, 4.5, 4.7_

  - [ ] 5.2 Configure cross-account KMS grant for IRE-to-PRE re-encryption
    - Create a KMS grant on `alias/pre-workload` scoped exclusively to the IRE account ID; grant operations: `Decrypt`, `ReEncryptFrom`, `ReEncryptTo`, `DescribeKey`, `CreateGrant`
    - Write a Lambda function `kms-grant-manager` (Python 3.12) that creates/revokes this grant at the start and end of an IRE-to-PRE transfer; store IRE account ID in SSM Parameter `/pre/kms/ire-account-id`
    - _Requirements: 4.6_

  - [ ]* 5.3 Write property test for KMS key rotation enabled
    - **Property 6: KMS Key Rotation Enabled**
    - Call `GetKeyRotationStatus` for all keys with alias prefix `alias/pre-*`; assert `KeyRotationEnabled = true` for every key
    - **Validates: Requirements 4.2**

  - [ ]* 5.4 Write property test for KMS admin separation of duties
    - **Property 7: KMS Admin Cannot Perform Data Operations**
    - Simulate `kms:Encrypt`, `kms:Decrypt`, `kms:GenerateDataKey*`, `kms:ReEncrypt*` using `pre-dr-kms-admin` as principal against each PRE KMS key; assert all simulations return `Deny`
    - **Validates: Requirements 4.3**

  - [ ]* 5.5 Write property test for KMS key policies denying Prod IAM roles (intra-account)
    - **Property 8: KMS Key Policies Deny Prod IAM Roles (Intra-Account)**
    - Parse JSON key policy for every key with alias prefix `alias/pre-*` in Account A; assert at least one `Deny` statement exists where `Action = kms:*` and `Principal` or `Condition` matches the intra-account Prod role ARN pattern `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*`
    - **Note**: Check for `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*` (intra-account role name prefix), NOT `arn:aws:iam::<PROD_ACCOUNT_ID>:*` (cross-account) — Prod and PRE share Account A, so the account ID in both patterns is identical
    - **Validates: Requirements 4.4, 4.5**

  - [ ] 5.6 Implement KMS policy validator Lambda and CloudWatch alarm
    - Write Python 3.12 Lambda `kms-policy-validator` triggered by CloudWatch Events (hourly schedule)
    - Lambda iterates all `alias/pre-*` keys in Account A; checks for the **intra-account** Prod role DENY statement targeting `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*` (not a cross-account account ID — Prod and PRE share Account A, so this is an intra-account role name prefix check); publishes a CloudWatch metric `KMSPolicyViolation` if any key is missing this DENY
    - Create CloudWatch alarm on `KMSPolicyViolation ≥ 1` → SNS → PagerDuty
    - _Requirements: 4.8_

  - [ ] 5.7 Checkpoint — KMS layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Break-Glass — Secrets Manager Vault, Lambda Orchestration, Alerting
  - [ ] 6.1 Provision Break-Glass Secrets Manager vault and SSM parameters
    - Create Secrets Manager secret `/pre/break-glass/activation-credentials`: type TOTP seed; KMS key `alias/pre-secrets`; rotation Lambda (see 6.2); retention 3 previous versions
    - Create SSM Parameter `/pre/break-glass/activation-request` (SecureString, `alias/pre-secrets`) — the write target for activation requests
    - Create SSM Parameter `/pre/break-glass/active-session-id` (SecureString) — written by activation Lambda; cleared on deactivation
    - _Requirements: 5.1, 5.8_

  - [ ] 6.2 Write Break-Glass activation and rotation Lambda functions
    - Write Python 3.12 Lambda `pre-break-glass-activator`:
      - Triggered by SSM Parameter Store change event on `/pre/break-glass/activation-request` via EventBridge
      - Parses `BreakGlassActivationRequest` from parameter value
      - Validates TOTP token against Secrets Manager; rejects already-used tokens (checks DynamoDB token-use log)
      - Asserts `approver_1_arn ≠ approver_2_arn`; rejects if equal
      - Opens 15-minute co-sign window; marks request `EXPIRED` if window lapses without both approvals
      - Grants temporary `sts:AssumeRole` permission scoped to requestor ARN with 3600s TTL
      - Writes activation record to DynamoDB table `pre-break-glass-audit`
      - Publishes alert to SNS topic `pre-break-glass-alerts`
    - Write Python 3.12 Lambda `pre-break-glass-token-rotator`:
      - Triggered by CloudWatch Events on CloudTrail `AssumeRole` event matching `pre-break-glass` ARN
      - Rotates secret in Secrets Manager within 60 seconds of session end
      - Marks consumed token in DynamoDB token-use log to prevent replay
    - _Requirements: 5.1, 5.2, 5.3, 5.6, 5.7_

  - [ ]* 6.3 Write property test for Break-Glass dual authorization
    - **Property 9: Break-Glass Dual Authorization**
    - Unit-test `pre-break-glass-activator` with mocked Secrets Manager and DynamoDB; assert request with `approver_1_arn = approver_2_arn` is rejected; assert request with two distinct ARNs and valid token is accepted
    - **Validates: Requirements 5.2, 5.3**

  - [ ]* 6.4 Write property test for Break-Glass token round-trip invalidation
    - **Property 10: Break-Glass Token Round-Trip Invalidation**
    - Unit-test `pre-break-glass-token-rotator` with mocked DynamoDB; use a token for activation; submit same token value again; assert second submission returns rejection with "token already consumed" error
    - **Validates: Requirements 5.6, 5.7**

  - [ ]* 6.5 Write property test for Break-Glass role self-modification denied
    - **Property 11: Break-Glass Role Self-Modification Denied**
    - Simulate `iam:UpdateRole`, `iam:DeleteRole`, `iam:DetachRolePolicy`, `iam:DeleteRolePolicy`, `iam:PutRolePolicy` with `pre-break-glass` as the requesting principal against the `pre-break-glass` role ARN; assert all return `Deny`
    - **Validates: Requirements 5.9, 3.8**

  - [ ] 6.6 Create Break-Glass CloudWatch alarms and SNS topics
    - Create SNS topic `pre-break-glass-alerts`; subscribe PagerDuty (P1) and CISO email
    - Create CloudWatch metric filter and alarm `pre-break-glass-role-assumed`: filter CloudTrail for `AssumeRole` matching `*pre-break-glass*`; threshold ≥ 1 within 1 minute; action → SNS P1
    - Create CloudWatch metric filter and alarm `pre-break-glass-no-valid-activation`: filter CloudTrail for `AssumeRole` on `pre-break-glass` with no matching activation record in DynamoDB; action → SNS P1 to CISO
    - Create EventBridge rule `pre-break-glass-high-risk-actions`: pattern matching IAM/KMS/EC2 events from `pre-break-glass` session; target → Lambda `security-incident-auto-responder` stub
    - Create CloudWatch Log Group `/pre/break-glass` with 7-year retention
    - _Requirements: 5.4, 5.5, 5.8, 13.4_

  - [ ] 6.7 Checkpoint — Break-Glass layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Security Tools — SSM Parameters, Deployment Automation, Scan Buckets
  - [ ] 7.1 Populate SSM Parameter Store for all three security tools
    - Create SecureString SSM parameters (encrypted with `alias/pre-secrets`): `/pre/tanium/registration-token`, `/pre/tanium/server-address`, `/pre/crowdstrike/cid`, `/pre/crowdstrike/approved-egress-ranges` (JSON array), `/pre/qualys/activation-key`, `/pre/qualys/server-address`, `/pre/approved-egress-ranges` (combined JSON array for NAT SG allow-listing)
    - Pin agent versions as String parameters: `/pre/tanium/agent-version`, `/pre/crowdstrike/sensor-version`, `/pre/qualys/agent-version`
    - _Requirements: 6.3, 6.7_

  - [ ] 7.2 Implement EC2 user-data scripts and SSM Run Command documents for agent deployment
    - Write a reusable Bash user-data script `pre-workload-launch.sh` that installs Tanium, CrowdStrike, and Qualys agents using versions and registration tokens read from SSM Parameter Store; agents are fetched from the internal S3 artifact bucket (not the internet)
    - Write an SSM Run Command document `PRE-InstallSecurityAgents` as a Terraform `aws_ssm_document` resource that invokes `pre-workload-launch.sh`; this document is the fallback for instances already running that require agent reinstall
    - Write Python 3.12 Lambda `pre-agent-health-monitor`:
      - Triggered every 5 minutes by CloudWatch Events
      - Queries Tanium, CrowdStrike, and Qualys APIs for heartbeat status per PRE instance
      - Instances missing heartbeat after 15-minute launch grace period are tagged `security-hold` and their security group is switched to `sg-pre-quarantine`
      - Publishes CloudWatch alarm `AgentHeartbeatMissing`
    - _Requirements: 6.1, 6.2, 6.5, 6.7, 6.8_

  - [ ]* 7.3 Write property test for security tool coverage on instance launch
    - **Property 12: Security Tool Coverage on Instance Launch**
    - Unit-test `pre-agent-health-monitor` with mocked boto3 EC2 and security tool API responses; assert that an instance with all three agents reporting heartbeat is left unchanged; assert that an instance missing any single agent heartbeat after the 15-minute window triggers `sg-pre-quarantine` assignment and `security-hold` tag
    - **Validates: Requirements 6.1, 6.2**

  - [ ] 7.4 Create scan results S3 buckets and finding-triggered isolation Lambda
    - Create S3 bucket `pre-scan-results-<ACCOUNT_ID>` with Object Lock COMPLIANCE mode, 7-year retention, SSE-KMS (`alias/pre-s3`), versioning enabled, public access blocked; set bucket policy to allow `s3:PutObject` only from `pre-scan-tool-access` role
    - Write Python 3.12 Lambda `pre-threat-isolation-handler`:
      - Triggered by S3 ObjectCreated event on `pre-scan-results-*`
      - Parses scan result JSON; checks severity threshold from SSM Parameter Store
      - If any CRITICAL or HIGH finding: tags instance `security-hold=true`, moves instance security group to `sg-pre-quarantine`, sets `WorkloadRecoveryRecord.PromotionStatus.blocked_reason`, publishes to SNS `pre-security-alerts`
    - _Requirements: 6.4, 6.6, 13.1_

  - [ ]* 7.5 Write property test for scan results encryption and destination invariant
    - **Property 13: Scan Results Encryption and Destination Invariant**
    - Enumerate all S3 objects in `pre-scan-results-*` buckets via boto3; assert each object's `ServerSideEncryption = aws:kms` and `SSEKMSKeyId` resolves to `alias/pre-s3`; assert no scan result object exists in any bucket not matching the `pre-scan-results-*` pattern
    - **Validates: Requirements 6.4, 10.4**

  - [ ]* 7.6 Write property test for threat detection triggers isolation
    - **Property 14: Threat Detection Triggers Isolation**
    - Unit-test `pre-threat-isolation-handler` with mocked S3 event and boto3 EC2; construct a scan result with one CRITICAL finding; assert that all three actions occur atomically: `sg-pre-quarantine` assignment, `security-hold=true` tag, and `PromotionStatus.blocked_reason` written; assert that a scan result with no high/critical findings leaves the instance unmodified
    - **Validates: Requirements 6.6, 13.1**

  - [ ] 7.7 Checkpoint — Security Tools layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Workload Promotion Pipeline — Transfer, Integrity, Hardening, Gate
  - [ ] 8.1 Implement IRE-to-PRE AMI transfer Lambda
    - Write Python 3.12 Lambda `pre-ire-to-pre-transfer`:
      - Accepts `WorkloadTransferRequest` (IRE AMI ID, IRE account ID, incident ID, workload name)
      - Calls `ec2:copy-image` with `--kms-key-id alias/pre-workload` and `--encrypted`; waits for `ImageAvailable` state
      - If `copy-image` fails or resulting AMI encryption key is not `alias/pre-workload`: deregisters partial AMI and snapshot; writes `PromotionStatus.current_phase = FAILED` with reason; halts
      - Revokes cross-account snapshot share from IRE side within the same execution (`ec2:modify-snapshot-attribute` removing PRE account from `createVolumePermission`)
      - Updates `WorkloadRecoveryRecord` with `pre_ami_id`, transfer timestamp, phase `IRE_TO_PRE`
    - _Requirements: 7.1, 7.2, 7.3, 7.6, 7.9_

  - [ ]* 8.2 Write property test for AMI re-encryption invariant on IRE-to-PRE transfer
    - **Property 15: AMI Re-Encryption Invariant on IRE-to-PRE Transfer**
    - Unit-test `pre-ire-to-pre-transfer` with mocked `ec2:copy-image` returning an AMI with wrong encryption key; assert Lambda deregisters AMI and halts; test with correct key and assert `WorkloadRecoveryRecord` is updated with `pre_ami_id`
    - **Validates: Requirements 7.2**

  - [ ] 8.3 Implement AMI integrity validation Lambda
    - Write Python 3.12 Lambda `pre-ami-integrity-validator`:
      - Triggered after `pre-ire-to-pre-transfer` completes successfully
      - Retrieves expected SHA-256 checksum from SSM Parameter `/pre/transfer/<incident_id>/expected-checksum`
      - Computes checksum of the copied AMI snapshot via EBS direct APIs
      - If mismatch: deregisters AMI, deletes snapshot, writes `PromotionStatus.current_phase = FAILED`, sends alert to DR team SNS topic within 5 minutes
      - If match: proceeds to instance launch
    - _Requirements: 7.4, 7.5, 7.10_

  - [ ]* 8.4 Write property test for AMI integrity gate on arrival
    - **Property 16: AMI Integrity Gate on Arrival**
    - Unit-test `pre-ami-integrity-validator` with mismatched checksum; assert Lambda deregisters AMI and deletes snapshot before any other action; assert no `ec2:run-instances` call is made; test with matching checksum and assert pipeline continues
    - **Validates: Requirements 7.3**

  - [ ]* 8.5 Write property test for snapshot share cleanup after transfer
    - **Property 17: Snapshot Share Cleanup After Transfer**
    - Unit-test `pre-ire-to-pre-transfer`; after successful copy, assert `ec2:modify-snapshot-attribute` is called to remove PRE account from `createVolumePermission` list of the IRE source snapshot within the same execution
    - **Validates: Requirements 7.4**

  - [ ] 8.6 Implement PRE instance launch with correct encryption and IMDSv2
    - Write Python 3.12 Lambda `pre-workload-launcher`:
      - Calls `ec2:run-instances` with AMI from integrity-validated transfer; `subnet-id = pre-workload-a`; `security-group-ids = sg-pre-workload`; `iam-instance-profile = pre-workload-instance`; EBS root encrypted with `alias/pre-ebs`; `MetadataOptions.HttpTokens = required`; `MetadataOptions.HttpPutResponseHopLimit = 1`
      - Attaches user-data script `pre-workload-launch.sh` for agent installation
      - Updates `WorkloadRecoveryRecord.pre_instance_id`
    - _Requirements: 7.7, 7.8, 8.3_

  - [ ]* 8.7 Write property test for workload instance encryption and IMDSv2 invariant
    - **Property 18: Workload Instance Encryption and IMDSv2 Invariant**
    - Enumerate all running EC2 instances in `pre-workload-*` subnets via boto3; assert root EBS volume `KmsKeyId` resolves to `alias/pre-ebs`; assert `MetadataOptions.HttpTokens = required` and `MetadataOptions.HttpPutResponseHopLimit = 1`; assert any non-compliant instance is flagged
    - **Validates: Requirements 7.5, 8.3**

  - [ ] 8.8 Implement hardening Terraform modules (sourced from ISO GitHub)
    - Write Terraform module `module/pre-os-baseline`: disable unused services, enforce SELinux/AppArmor, apply CIS Level 2 baseline via `aws_ssm_association` with document `AWS-RunInspecChecks`
    - Write Terraform module `module/pre-patch-management`: invoke SSM Patch Manager baseline; query compliance score via `ssm:DescribeInstancePatchStates`; halt pipeline if score < 95%
    - Write Terraform module `module/pre-iam-instance-hardening`: call `ec2:ModifyInstanceMetadataOptions` with `http-tokens=required` and `http-put-response-hop-limit=1`; verify instance profile is exactly `pre-workload-instance`; detach any other profiles via `iam:RemoveRoleFromInstanceProfile`
    - Write Terraform module `module/pre-network-hardening`: apply host firewall rules via SSM Run Command; disable IPv6 if unused; verify security group compliance via AWS Config snapshot
    - Write Terraform module `module/pre-security-tool-verification`: query Tanium, CrowdStrike, and Qualys APIs for agent health; fail if any agent is not registered
    - Write Terraform module `module/pre-compliance-scan`: invoke AWS Config evaluation; query Qualys compliance scan; halt if any critical Config rule is non-compliant; write `HardeningStatus` to `WorkloadRecoveryRecord`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [ ]* 8.9 Write property test for patch compliance gate
    - **Property 19: Patch Compliance Gate**
    - Unit-test `module/pre-patch-management` orchestration code with mocked `ssm:DescribeInstancePatchStates`; assert pipeline does not advance to next module when compliance score = 94.9%; assert pipeline advances when score = 95.0%
    - **Validates: Requirements 8.2**

  - [ ]* 8.10 Write property test for instance profile isolation after hardening
    - **Property 20: Instance Profile Isolation After Hardening**
    - Unit-test `module/pre-iam-instance-hardening` with mocked EC2 describing an instance with two profiles attached; assert `iam:RemoveRoleFromInstanceProfile` is called for the non-`pre-workload-instance` profile; assert final state has exactly one profile
    - **Validates: Requirements 8.4**

  - [ ]* 8.11 Write property test for compliance scan gate
    - **Property 21: Compliance Scan Gate**
    - Unit-test `module/pre-compliance-scan` orchestration code with mocked AWS Config response containing one non-compliant critical rule; assert pipeline halts and does not transition to `PRE_VALIDATION` phase; assert pipeline advances when critical non-compliant count = 0
    - **Validates: Requirements 8.5**

  - [ ] 8.12 Implement promotion gate Lambda and dual-approval workflow
    - Write Python 3.12 Lambda `pre-promotion-gate`:
      - Runs all six automated checks concurrently (Tanium ≥ 95%, CrowdStrike zero detections, Qualys zero Critical/High, AWS Config zero non-compliant, SSM Patch Compliant, IMDSv2 enforced)
      - If any check fails: writes `PromotionStatus.blocked_reason` and `gate_passed = false`; blocks approval gate from opening
      - If all pass: transitions record to `AWAITING_APPROVAL`; sends approval request to `pre-approval-requests` SNS topic
      - Accepts approval callbacks; validates `approver_role` is exactly `DR_LEAD` or `CISO`; rejects other roles
      - Opens gate only when one `DR_LEAD` APPROVED + one `CISO` APPROVED are both recorded
      - On gate open: invokes `pre-production-promoter` Lambda
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [ ]* 8.13 Write property test for promotion gate all-green precondition
    - **Property 23: Promotion Gate All-Green Precondition**
    - Unit-test `pre-promotion-gate` with mocked check results; test 63 combinations (each of 6 checks failing individually and together); assert gate remains closed unless all six checks pass simultaneously; assert `AWAITING_APPROVAL` is only reached when all six pass
    - **Validates: Requirements 9.1, 9.2**

  - [ ]* 8.14 Write property test for dual approval gate requirement
    - **Property 24: Dual Approval Gate Requirement**
    - Unit-test `pre-promotion-gate` approval handling; assert gate remains pending with zero approvals, one DR_LEAD only, one CISO only, two DR_LEADS, or two CISOs; assert gate opens only with exactly one DR_LEAD APPROVED + one CISO APPROVED; assert approval from any other role is rejected
    - **Validates: Requirements 9.3, 9.4**

  - [ ] 8.15 Implement PRE-to-Production promotion Lambda
    - Write Python 3.12 Lambda `pre-production-promoter`:
      - Creates final AMI from PRE instance (Account A, `eu-central-1`)
      - Re-encrypts AMI with a new Production KMS key (`alias/prod-*` or equivalent; key ID must differ from `alias/pre-workload` and from any `alias/pre-*` key) to break the key linkage to IRE and PRE
      - **Note**: Since Prod and PRE are in Account A (same account), this is an INTRA-account promotion — no `ec2:modify-image-attribute` cross-account AMI share step is needed; the AMI is copied directly within Account A from `eu-central-1` to the Prod VPC deployment in `eu-west-1`
      - Deploys or makes available the re-encrypted AMI to the Prod VPC (`eu-west-1`) within Account A directly (no cross-account sharing step)
      - Records `PromotionStatus.promoted_ami_id`, `promoted_at`, `gate_passed = true`, both approver ARNs in `WorkloadRecoveryRecord`
      - Logs promotion event to CloudTrail (Account A all-region trail)
    - _Requirements: 9.5, 9.6, 14.5_

  - [ ]* 8.16 Write property test for re-encryption on Production promotion
    - **Property 25: Re-Encryption on Production Promotion**
    - Unit-test `pre-production-promoter` with mocked `ec2:copy-image`; assert the KMS key ID passed to the Production AMI copy is not `alias/pre-workload` and not any `alias/pre-*` key; assert `production_ami_key_id ≠ pre_workload_key_id`
    - **Validates: Requirements 9.5**

  - [ ] 8.17 Implement WorkloadRecoveryRecord DynamoDB table and record management
    - Create DynamoDB table `pre-workload-recovery-records`: partition key `incident_id` (String), sort key `workload_name` (String); encryption with `alias/pre-s3`; point-in-time recovery enabled; TTL disabled (records are permanent audit artifacts)
    - Write Python helper module `recovery_record.py` (shared Lambda layer) implementing `create_record`, `update_phase`, `append_scan_result`, `append_approval`, `set_promotion_status`, `mark_failed` methods; all writes are conditional expressions to prevent overwrite races
    - Ensure all pipeline Lambdas import and use `recovery_record.py`; halt execution and emit error on any `update_item` failure
    - _Requirements: 7.9, 7.10, 14.1, 14.2, 14.3, 14.4, 14.5, 14.6_

  - [ ]* 8.18 Write property test for WorkloadRecoveryRecord completeness invariant
    - **Property 28: WorkloadRecoveryRecord Completeness Invariant**
    - Unit-test `recovery_record.py` using hypothesis `@given` strategies generating arbitrary phase transitions; assert that any record at or after `PRE_HARDENING` has non-null `incident_id`, `workload_name`, `source_backup_arn`, `ire_ami_id`, `pre_ami_id`, `restore_timestamp`, and at least one `ScanResult`; assert that any record at `PROMOTED` additionally has `promoted_ami_id`, `promoted_at`, and two `ApprovalRecord` entries with distinct `approver_role` values
    - **Validates: Requirements 7.6, 9.6, 14.1–14.6**

  - [ ] 8.19 Checkpoint — Workload Pipeline
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Audit Trail — CloudTrail, Object Lock Buckets, Config Recording
  - [ ] 9.1 Create all audit S3 buckets with Object Lock
    - Create S3 bucket `pre-cloudtrail-logs-<ACCOUNT_ID>`: Object Lock COMPLIANCE mode, 7-year retention, SSE-KMS (`alias/pre-cloudtrail`), versioning, public access blocked; bucket policy denies `s3:DeleteObject` and `s3:PutBucketPolicy` from all principals except the CloudTrail service
    - Create S3 bucket `pre-vpc-flow-logs-<ACCOUNT_ID>`: Object Lock COMPLIANCE mode, 7-year retention, SSE-KMS (`alias/pre-s3`)
    - Create S3 bucket `pre-config-logs-<ACCOUNT_ID>`: Object Lock COMPLIANCE mode, versioning, SSE-KMS (`alias/pre-s3`)
    - _Requirements: 10.1, 10.3, 12.1_

  - [ ] 9.2 Enable CloudTrail trail with log file validation
    - Create multi-region CloudTrail trail `pre-audit-trail` in Account A covering ALL regions — including `eu-central-1` (PRE) and `eu-west-1` (Prod) — to capture a complete audit record of all activity in Account A; deliver to `pre-cloudtrail-logs-<ACCOUNT_A_ID>`; enable global service events; enable log file validation (SHA-256 digest files); KMS key `alias/pre-cloudtrail`; enable CloudWatch Logs delivery to Log Group `/pre/cloudtrail`
    - Add CloudWatch metric filter to separate PRE events from Prod events within the shared trail: filter on `sourceIPAddress` matching PRE VPC endpoint IPs OR `requestParameters.vpcId = vpc-pre-eu-central-1` OR resource ARN matching the `eu-central-1` region string; tag resulting filtered log streams with `Environment=PRE`
    - Create CloudWatch Log Group `/pre/cloudtrail` with 365-day retention
    - _Requirements: 10.1, 10.2, 10.6_

  - [ ]* 9.3 Write property test for audit log encryption invariant
    - **Property 26: Audit Log Encryption Invariant**
    - Enumerate all objects in `pre-cloudtrail-logs-*` via boto3; assert `SSEKMSKeyId` resolves to `alias/pre-cloudtrail`; enumerate objects in `pre-vpc-flow-logs-*` and `pre-scan-results-*`; assert `SSEKMSKeyId` resolves to `alias/pre-s3`
    - **Validates: Requirements 10.6, 10.4**

  - [ ] 9.4 Enable AWS Config recording for all PRE resource types
    - Create Config recorder for all resource types in `eu-central-1`; delivery channel targeting `pre-config-logs-<ACCOUNT_ID>`; IAM role `pre-config-recorder` with AWS managed policy `AWSConfigRoleForOrganizations`
    - Create SNS topic `pre-cloudtrail-alerts`; configure Config delivery channel to publish to this topic
    - _Requirements: 12.1, 12.3_

  - [ ] 9.5 Checkpoint — Audit Trail layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 10. Config Rules — Managed Rules and Custom Rules
  - [ ] 10.1 Deploy all AWS Config managed rules
    - Create Terraform `aws_config_config_rule` resources for all nine managed rules: `encrypted-volumes`, `restricted-ssh`, `restricted-common-ports`, `iam-no-inline-policies`, `root-account-mfa-enabled`, `s3-bucket-server-side-encryption-enabled`, `vpc-flow-logs-enabled`, `cloud-trail-encryption-enabled`, `kms-key-rotation-enabled`
    - Add `s3-bucket-object-lock-enabled` managed rule and alarm: on non-compliant state → CloudWatch P1 alarm
    - Create EventBridge rule to capture all Config rule `NON_COMPLIANT` transitions; target Lambda `pre-config-alert-handler` that publishes to `pre-cloudtrail-alerts` SNS topic within 5 minutes
    - _Requirements: 12.2, 12.3, 10.5_

  - [ ] 10.2 Implement custom Config rule `tgw-no-prod-routes`
    - Write Python 3.12 Lambda `pre-config-tgw-route-evaluator`:
      - Evaluates all TGW route tables associated with PRE VPC attachment
      - Flags `NON_COMPLIANT` if any route with destination `10.0.0.0/16` has a target other than `blackhole`
      - Flags `COMPLIANT` if `10.0.0.0/16` is absent or blackholed
    - Register Lambda as a Config custom rule `tgw-no-prod-routes` with change-triggered evaluation on `AWS::EC2::TransitGatewayRouteTable`
    - Create EventBridge rule on `NON_COMPLIANT` transition: trigger `pre-config-alert-handler` → SNS P1 PagerDuty + capture VPC Flow Logs from `10.0.0.0/16` for forensic review
    - _Requirements: 1.6, 12.4, 13.2_

  - [ ]* 10.3 Write property test for TGW route config rule correctness (evaluator logic)
    - **Property 27: TGW Route Config Rule Correctness (evaluator)**
    - Unit-test `pre-config-tgw-route-evaluator` with mocked `ec2:DescribeTransitGatewayRouteTables`; construct route table with `10.0.0.0/16 → production-attachment`; assert evaluator returns `NON_COMPLIANT`; construct route table with `10.0.0.0/16 → blackhole`; assert evaluator returns `COMPLIANT`; construct route table with no `10.0.0.0/16` entry; assert `COMPLIANT`
    - **Validates: Requirements 1.6, 12.4**

  - [ ] 10.4 Implement custom Config rule `iam-no-prod-role-trust-in-pre`
    - Write Python 3.12 Lambda `pre-config-iam-trust-evaluator`:
      - Evaluates all IAM roles in Account A with the `pre-` prefix
      - Parses `AssumeRolePolicyDocument`; flags `NON_COMPLIANT` if any `Principal` contains `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*` (intra-account Prod role ARN pattern — Prod and PRE share Account A, so this is an intra-account trust check, not cross-account)
      - Also flags `NON_COMPLIANT` if any `Principal` contains a Prod EC2 or Lambda service principal (`ec2.amazonaws.com`, `lambda.amazonaws.com`) without a PRE-scoped condition key limiting the trust to `eu-central-1` resources
    - Register as Config custom rule `iam-no-prod-role-trust-in-pre` (renamed from `iam-no-cross-account-trust-prod-pre`) with periodic and change-triggered evaluation on `AWS::IAM::Role`
    - _Requirements: 12.5_

  - [ ] 10.5 Checkpoint — Config Rules layer
    - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. ISO Environment Connectivity — TGW Routes, DNS, LDAPS, Private CA
  - [ ] 11.1 Configure LDAPS connectivity and deny plain LDAP
    - Add NACL rule to `nacl-pre-mgmt`: ALLOW inbound TCP 636 from `10.2.0.0/16` (LDAPS from ISO AD)
    - Add NACL rule to `nacl-pre-mgmt`: DENY inbound TCP 389 from all sources except `10.2.0.0/16` (block plain LDAP)
    - Verify security group `sg-pre-mgmt-bastion` allows TCP 636 outbound to ISO CIDR
    - _Requirements: 11.4_

  - [ ] 11.2 Configure Private CA integration for TLS certificate issuance
    - Create Terraform data source referencing the ISO-hosted AWS Private CA ARN (stored in SSM Parameter `/pre/iso/private-ca-arn`)
    - Write Python 3.12 Lambda `pre-cert-requester`:
      - Called by `pre-workload-launcher` after instance is running
      - Requests a TLS certificate from the ISO Private CA via `acm-pca:IssueCertificate` over the TGW path
      - Stores issued certificate in Secrets Manager (`/pre/certs/<workload_name>`) encrypted with `alias/pre-secrets`
    - _Requirements: 11.5_

  - [ ]* 11.3 Write property test for Terraform state externality
    - **Property 22: Terraform State Externality**
    - Enumerate all IAM policies attached to PRE-account roles via boto3; simulate `s3:PutObject` against the ISO account's Terraform state S3 bucket ARN (from SSM Parameter `/pre/iso/tf-state-bucket-arn`) for each PRE role; assert all simulations return `Deny`
    - **Validates: Requirements 8.6, 11.6**

  - [ ] 11.4 Final Checkpoint — Full Stack
    - Ensure all tests pass across all epics. Verify complete TGW routing (PRE ↔ ISO, PRE ↛ Prod). Run `terraform validate` and `terraform plan` on all modules. Ask the user if any questions arise before marking implementation complete.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP; core security controls remain mandatory
- All Terraform modules are executed via the Azure DevOps pipeline runner in Account C (ISO Environment) — no Terraform state is stored in Account A (Prod+PRE)
- Property-based tests use **pytest-hypothesis** (Python) and are run in the ISO Terraform runner; boto3 calls are mocked using `moto` for unit tests and use real AWS API calls for integration property tests
- Each property test references its Property number from `design.md` and the requirement clauses it validates
- Checkpoints are human verification gates — confirm all automated tests pass before proceeding to the next epic
- The `pre-quarantine` security group (`sg-pre-quarantine`) must be created in task 2.4 before it is referenced by agent health monitoring (task 7.2) and threat isolation (task 7.4)
- `recovery_record.py` Lambda layer (task 8.17) must be deployed before any pipeline Lambda (tasks 8.1, 8.3, 8.6, 8.12, 8.15) is deployed, as all Lambdas import it
- **Account model clarification**:
  - `<ACCOUNT_A_ID>` and `<PROD_ACCOUNT_ID>` are **THE SAME value** — Prod VPC (`eu-west-1`, `10.0.0.0/16`) and PRE/DR VPC (`eu-central-1`, `10.1.0.0/16`) both reside in Account A; there is no separate "PRE account"
  - `<IRE_ACCOUNT_ID>` = Account B (Isolated Recovery Environment — separate AWS account)
  - `<ISO_ACCOUNT_ID>` = Account C (ISO shared services — separate AWS account; owns the Transit Gateway)
  - `<ACCOUNT_B_ID>` = `<IRE_ACCOUNT_ID>`; `<ACCOUNT_C_ID>` = `<ISO_ACCOUNT_ID>`
  - All references to "PRE account" in this document mean "Account A (Prod+PRE)" — the same account that hosts the Production VPC
  - All references to "cross-account Prod→PRE isolation" mean **intra-account IAM and resource-policy isolation**: `PREPermissionBoundary` region-lock to `eu-central-1`, `pre-*` role trust policies (SAML only, no Prod service principals), and resource-based DENY policies on PRE KMS keys and S3 buckets targeting `arn:aws:iam::<ACCOUNT_A_ID>:role/prod-*`
  - The IRE-to-PRE AMI transfer (task 8.1) remains a genuine **cross-account** operation: Account B (IRE) → Account A (Prod+PRE); all cross-account copy and re-encryption logic is unchanged
  - The PRE-to-Production promotion (task 8.15) is an **intra-account** operation within Account A (`eu-central-1` → `eu-west-1`); no AMI sharing step is needed

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "5.1"] },
    { "id": 2, "tasks": ["1.3", "1.4", "2.1", "4.1", "5.3"] },
    { "id": 3, "tasks": ["2.2", "2.4", "3.1", "4.2", "5.2", "5.4", "5.5", "5.6"] },
    { "id": 4, "tasks": ["2.3", "2.5", "3.2", "3.3", "3.4", "4.3", "4.4", "4.5"] },
    { "id": 5, "tasks": ["6.1", "7.1", "9.1"] },
    { "id": 6, "tasks": ["6.2", "6.6", "7.2", "9.2", "9.4", "11.1"] },
    { "id": 7, "tasks": ["6.3", "6.4", "6.5", "7.3", "7.4", "8.17", "9.3", "10.1", "11.2"] },
    { "id": 8, "tasks": ["7.5", "7.6", "8.1", "8.3", "9.5", "10.2", "10.4", "11.3"] },
    { "id": 9, "tasks": ["8.2", "8.4", "8.5", "8.6", "10.3"] },
    { "id": 10, "tasks": ["8.7", "8.8", "8.12"] },
    { "id": 11, "tasks": ["8.9", "8.10", "8.11", "8.13", "8.14"] },
    { "id": 12, "tasks": ["8.15"] },
    { "id": 13, "tasks": ["8.16", "8.18"] }
  ]
}
```
