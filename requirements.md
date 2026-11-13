# Requirements Document

## Introduction

This document defines the requirements for the AWS Cyber Recovery — Protected Recovery Environment (PRE). The PRE transforms the existing Disaster Recovery VPC in `eu-central-1` into a hardened, trust-verified staging environment. During a cyber incident, workloads backed up via Rubrik are restored into an Isolated Recovery Environment (IRE), cleansed and scanned, then transferred to the PRE for final validation and hardening before promotion back to production.

The PRE is an air-gapped, independently administered environment that shares no credential, key, or network trust chain with the potentially compromised production environment. Requirements are derived from the approved design and cover three core security objectives: stopping attacker access to the DR VPC, establishing clean workload provenance, and preventing attacker re-entry.

## Glossary

- **PRE**: Protected Recovery Environment — the hardened DR VPC in `eu-central-1` used as the trusted staging environment during cyber recovery.
- **IRE**: Isolated Recovery Environment — the quarantine AWS account where workloads are initially restored from Rubrik and scanned before transfer to PRE.
- **PRE_VPC**: The AWS VPC (`10.1.0.0/16`) in `eu-central-1` that serves as the PRE network boundary.
- **Production_VPC**: The AWS VPC (`10.0.0.0/16`) in `eu-west-1`, considered potentially compromised during an incident.
- **ISO_Environment**: The separate, trusted AWS account hosting shared services including Microsoft AD, DNS, Terraform runners, GitHub, and Azure DevOps.
- **TGW**: Transit Gateway — the central AWS networking hub connecting PRE, Production, and ISO accounts.
- **PRE_IAM_Layer**: The set of dedicated IAM roles, permission boundaries, and SCPs that govern identity and access in the PRE account.
- **PRE_KMS_Layer**: The independent KMS key ring in `eu-central-1` used exclusively by PRE resources.
- **Break_Glass_Mechanism**: The out-of-band emergency access path using dual-person authorization, independent of the AD/SAML federation chain.
- **Security_Tool_Layer**: The integration layer for Tanium, CrowdStrike, and Qualys agents deployed to PRE workload instances.
- **Promotion_Pipeline**: The orchestrated workflow that transfers cleansed workloads from IRE to PRE and from PRE to Production after all gates are passed.
- **DR_Admin**: A member of the DR team holding the `pre-dr-admin` or equivalent IAM role.
- **CISO**: Chief Information Security Officer or nominated delegate; required co-approver for workload promotion.
- **Approval_Gate**: The combined automated compliance checks and mandatory dual human sign-off that must be satisfied before workload promotion.
- **SCP**: Service Control Policy — an AWS Organizations policy applied to the PRE Organizational Unit to enforce account-wide restrictions.
- **NACL**: Network Access Control List — a stateless packet filter applied at the subnet boundary.
- **VPC_Endpoint**: An AWS PrivateLink or gateway endpoint that allows PRE resources to reach AWS services without traversing the public internet.
- **Object_Lock**: An S3 feature that enforces write-once-read-many (WORM) semantics on stored objects.
- **IMDSv2**: Instance Metadata Service version 2 — a session-oriented metadata API that prevents SSRF-based credential theft.
- **AMI**: Amazon Machine Image — the artifact unit transferred between accounts during workload promotion.
- **HardeningStatus**: A data record tracking the state and compliance score of hardening playbooks applied to a PRE workload instance.
- **WorkloadRecoveryRecord**: The authoritative data record tracking a single workload through all phases from IRE restore to Production promotion.

---

## Requirements

### Requirement 1: PRE Network Isolation from Production

**User Story:** As a DR Admin, I want the PRE VPC to have no active network path to the Production VPC during a cyber incident, so that a compromised Production environment cannot reach, pivot into, or contaminate the recovery environment.

#### Acceptance Criteria

1. WHEN an authorised DR Admin or an automated runbook invokes the isolation procedure by updating the PRE-isolated TGW route table, THE PRE_IAM_Layer SHALL set the route entry for the Production CIDR (`10.0.0.0/16`) to a BLACKHOLE target type, replacing any active attachment target, within 30 seconds of invocation.
2. THE PRE_VPC NACL SHALL contain an explicit DENY rule for all inbound traffic sourced from `10.0.0.0/16` on all protocols and ports, assigned a rule number no greater than 50, evaluated before any ALLOW rule whose rule number is greater than 50.
3. THE PRE_VPC NACL SHALL contain an explicit DENY rule for all outbound traffic destined to `10.0.0.0/16` on all protocols and ports, assigned a rule number no greater than 50, evaluated before any ALLOW rule whose rule number is greater than 50.
4. THE TGW SHALL route all traffic destined for `10.0.0.0/16` received on the PRE attachment to a BLACKHOLE target, resulting in silent discard without returning an ICMP unreachable message.
5. THE PRE_VPC SHALL log all accepted and rejected traffic using VPC Flow Logs with traffic type ALL, delivering records to both CloudWatch Logs and an S3 bucket, with a minimum retention period of 365 days in each destination.
6. IF an AWS Config evaluation detects a TGW route entry in the PRE route table with a non-BLACKHOLE target for `10.0.0.0/16`, THEN THE PRE_VPC SHALL raise an AWS Config rule violation and deliver a P1 PagerDuty alert within 60 seconds of the Config evaluation completing.
7. THE PRE_VPC SHALL provide VPC Interface Endpoints for SSM, KMS, Secrets Manager, CloudTrail, and Config so that AWS API calls do not traverse the public internet.
8. WHEN DNS queries are issued from PRE instances for domain suffixes designated as internal (defined in the ISO Environment DNS resolver configuration), THE PRE_VPC SHALL forward those queries to the ISO Environment DNS resolver via a Route 53 Resolver outbound endpoint over the TGW path, without routing the query through a public DNS resolver.

---

### Requirement 2: PRE Network Segmentation

**User Story:** As a DR Admin, I want the PRE VPC divided into isolated subnets with layered controls, so that management traffic, recovered workloads, security tooling, and egress paths are strictly separated.

#### Acceptance Criteria

1. THE PRE_VPC SHALL contain at minimum four subnet categories: management (`10.1.0.0/25` and `10.1.0.128/25`), workload (`10.1.1.0/25` and `10.1.1.128/25`), security scan (`10.1.2.0/25` and `10.1.2.128/25`), and egress/NAT (`10.1.3.0/25`).
2. WHEN a workload instance receives an inbound SSH (TCP port 22) or RDP (TCP port 3389) connection, THE PRE_VPC NACL SHALL permit that traffic only if the source IP falls within `10.1.0.0/24`, and SHALL deny that traffic if the source IP falls outside `10.1.0.0/24`.
3. WHILE a workload instance is running in the workload subnet, THE Security_Tool_Layer SHALL be permitted TCP-based inbound and outbound access to that instance exclusively from and to the security scan subnet CIDR (`10.1.2.0/24`) via the `sg-pre-scan-tools` security group association.
4. THE PRE_VPC SHALL route outbound internet traffic from workload instances exclusively through the NAT Gateway in the egress subnet (`10.1.3.0/25`), and SHALL NOT attach an Internet Gateway inbound route to the management, workload, or security scan subnets.
5. THE PRE_VPC SHALL associate each subnet category with a dedicated route table, where the route tables for the management, workload, and security scan subnets do not contain a default route (`0.0.0.0/0`) pointing to an Internet Gateway.

---

### Requirement 3: Dedicated PRE Identity and Access Management

**User Story:** As a DR Admin, I want all PRE administrative identities to be sourced from a dedicated AD Organizational Unit in the ISO Environment with no credential overlap with Production, so that a compromise of Production credentials cannot grant access to the recovery environment.

#### Acceptance Criteria

1. THE PRE_IAM_Layer SHALL provide eight named IAM roles: `pre-dr-admin`, `pre-dr-network-admin`, `pre-dr-kms-admin`, `pre-dr-readonly`, `pre-break-glass`, `pre-automation-deploy`, `pre-workload-instance`, and `pre-scan-tool-access`.
2. WHEN a DR Admin authenticates to a PRE IAM role, THE PRE_IAM_Layer SHALL require the SAML assertion to originate from the dedicated ISO AD OU (`OU=PRE,OU=CyberRecovery`) and SHALL enforce MFA presence via a SAML condition, and IF either condition is not satisfied, THEN THE PRE_IAM_Layer SHALL deny the authentication attempt and return an error indicating the failed condition.
3. THE PRE_IAM_Layer SHALL attach the `PREPermissionBoundary` policy to every human-assumed PRE role (`pre-dr-admin`, `pre-dr-network-admin`, `pre-dr-kms-admin`, `pre-dr-readonly`, and `pre-break-glass`), restricting all allowed actions to the `eu-central-1` region.
4. IF any PRE IAM principal attempts `sts:AssumeRole` targeting any role in the Production account, THEN THE PRE_IAM_Layer SHALL deny the call, enforced via both the `PREPermissionBoundary` and the `PRE-DenyProdAccountTrust` SCP.
5. IF any Production account principal attempts to assume any role in the PRE account, THEN THE PRE_IAM_Layer SHALL deny the call, enforced via the `PRE-DenyProdAccountTrust` SCP applied to the PRE Organizational Unit.
6. WHEN any IAM API call invokes `kms:PutKeyPolicy`, `kms:ScheduleKeyDeletion`, `iam:UpdateAssumeRolePolicy`, or any action that modifies IAM role trust relationships, THE PRE_IAM_Layer SHALL deny the call IF `aws:MultiFactorAuthPresent` is false, enforced by the `PRE-RequireMFAForSensitiveActions` SCP.
7. IF any principal other than `pre-dr-admin` attempts `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, or `iam:PassRole`, THEN THE PRE_IAM_Layer SHALL deny the call via the permission boundary.
8. IF any principal attempts `iam:UpdateRole`, `iam:DeleteRole`, `iam:DetachRolePolicy`, `iam:DeleteRolePolicy`, or `iam:UpdateAssumeRolePolicy` targeting the `pre-break-glass` role, THEN THE PRE_IAM_Layer SHALL deny the call for all principals via the permission boundary.

---

### Requirement 4: Independent KMS Key Hierarchy

**User Story:** As a Security Administrator, I want PRE encryption keys to be completely independent from Production KMS keys and administered by a dedicated role that cannot perform data operations, so that key compromise or deletion cannot bridge the trust boundary or allow an attacker to access recovery data.

#### Acceptance Criteria

1. THE PRE_KMS_Layer SHALL provision six KMS keys with aliases: `alias/pre-ebs`, `alias/pre-s3`, `alias/pre-secrets`, `alias/pre-cloudtrail`, `alias/pre-rds`, and `alias/pre-workload`, all residing in `eu-central-1`.
2. THE PRE_KMS_Layer SHALL enable automatic annual key rotation on all six PRE KMS keys.
3. WHEN any principal attempts a KMS data operation (`kms:Encrypt`, `kms:Decrypt`, `kms:ReEncrypt*`, `kms:GenerateDataKey*`) using the `pre-dr-kms-admin` role, THE PRE_KMS_Layer SHALL deny the operation, enforcing separation of duties between key administration and key usage.
4. FOR every KMS key in the PRE account, THE PRE_KMS_Layer SHALL include a key policy statement with `Effect: Deny` covering all KMS actions for any principal matching `arn:aws:iam::<PROD_ACCOUNT_ID>:*`.
5. WHEN any principal attempts `kms:ScheduleKeyDeletion` or `kms:DisableKey` for a PRE KMS key, THE PRE_KMS_Layer SHALL deny the call unless the principal is the AWS Organizations root, enforced by both the key policy and the `PRE-DenyKMSKeyDeletion` SCP.
6. THE PRE_KMS_Layer SHALL grant cross-account usage of `alias/pre-workload` exclusively to the IRE account via a KMS grant, to enable IRE-to-PRE AMI re-encryption.
7. THE PRE_KMS_Layer SHALL set a deletion window of 7 days for `alias/pre-workload` and 30 days for all other PRE KMS keys.
8. WHEN a Lambda function (`kms-policy-validator`) scans PRE KMS key policies, THE PRE_KMS_Layer SHALL generate a CloudWatch alert if any key is found to be missing the Production account DENY statement. The scan SHALL occur at minimum hourly.

---

### Requirement 5: Break-Glass Emergency Access

**User Story:** As an Incident Commander, I want an out-of-band emergency access path that does not depend on the AD/SAML federation chain, so that DR operations can continue even if the identity federation infrastructure is unavailable or compromised.

#### Acceptance Criteria

1. THE Break_Glass_Mechanism SHALL store the break-glass activation credential as a single-use TOTP token in AWS Secrets Manager at path `/pre/break-glass/activation-credentials`, encrypted with `alias/pre-secrets`, rotated within 60 seconds of each use and subject to a maximum validity period of 24 hours from creation.
2. WHEN a break-glass activation is initiated, THE Break_Glass_Mechanism SHALL require exactly two distinct IAM principals to co-sign the activation request within a 15-minute window; IF the co-sign window expires before both approvals are received, THEN THE Break_Glass_Mechanism SHALL mark the request as expired and require a new activation request.
3. IF a break-glass activation request is submitted with `approver_1_arn` equal to `approver_2_arn`, THEN THE Break_Glass_Mechanism SHALL reject the request with an error indicating distinct approvers are required.
4. THE Break_Glass_Mechanism SHALL limit the `pre-break-glass` role session duration to a maximum of 3600 seconds (one hour).
5. WHEN the `pre-break-glass` role is assumed, THE Break_Glass_Mechanism SHALL publish a P1 alert to PagerDuty and an email notification to the CISO and security team within 60 seconds, via CloudWatch alarm and SNS topic.
6. WHEN a break-glass session ends, THE Break_Glass_Mechanism SHALL automatically rotate the activation token in Secrets Manager via a Lambda function within 60 seconds of session termination, ensuring the new token is available before any subsequent activation can be initiated.
7. IF a break-glass activation token that has already been used in a prior session is submitted, THEN THE Break_Glass_Mechanism SHALL reject the activation request with an error indicating the token has already been consumed.
8. THE Break_Glass_Mechanism SHALL record the following events in the immutable CloudTrail S3 bucket with Object Lock enabled, with a minimum retention period of 365 days: activation request submission, co-sign completion, role assumption, every AWS API call made during the session, session termination, and token rotation completion.
9. IF the `pre-break-glass` role attempts `iam:UpdateRole`, `iam:DeleteRole`, `iam:DetachRolePolicy`, `iam:DeleteRolePolicy`, `iam:AttachRolePolicy`, or `iam:UpdateAssumeRolePolicy` targeting the `pre-break-glass` role itself, THEN THE Break_Glass_Mechanism SHALL deny the call, enforced via the `PREPermissionBoundary` and SCPs.
10. IF a co-sign request is not completed within the 15-minute window, THEN THE Break_Glass_Mechanism SHALL automatically mark the request as expired, discard all co-sign submissions, and require the requestor to initiate a new activation request.

---

### Requirement 6: Security Tool Integration and Coverage

**User Story:** As a Security Operations Engineer, I want Tanium, CrowdStrike, and Qualys agents to be automatically deployed to every recovered workload instance in the PRE, so that all workloads receive immediate and continuous threat detection, vulnerability scanning, and compliance enforcement from the moment they enter the PRE.

#### Acceptance Criteria

1. WHEN an EC2 instance is launched in the PRE workload subnet, THE Security_Tool_Layer SHALL install and register the Tanium agent, CrowdStrike sensor, and Qualys cloud agent on that instance within 15 minutes of launch, where registration is confirmed by a successful heartbeat response from each tool's management API.
2. IF a Tanium agent, CrowdStrike sensor, or Qualys cloud agent does not achieve a confirmed heartbeat with its management API within 15 minutes of instance launch, THEN THE Security_Tool_Layer SHALL trigger a CloudWatch alarm, tag the instance with `security-hold`, and move the instance security group to `sg-pre-quarantine` to prevent progression to the validation phase.
3. THE Security_Tool_Layer SHALL retrieve agent registration tokens and server addresses exclusively from SSM Parameter Store, using the `pre-scan-tool-access` IAM role.
4. WHEN a Tanium, CrowdStrike, or Qualys scan completes on a PRE workload instance, THE Security_Tool_Layer SHALL write the resulting scan findings to the `pre-scan-results-*` S3 bucket, encrypted with `alias/pre-s3`.
5. WHILE a workload instance is in the PRE validation phase, THE Security_Tool_Layer SHALL enforce continuous monitoring via Tanium Detect, CrowdStrike EDR, and Qualys cloud agent concurrently, where each agent must produce a heartbeat or telemetry event no less frequently than every 5 minutes; IF an agent exceeds this interval without a heartbeat, THEN THE Security_Tool_Layer SHALL trigger a CloudWatch alarm.
6. WHEN any security tool reports a finding at or above the critical or high severity threshold as defined in the tool's severity taxonomy referenced in SSM Parameter Store, THE Security_Tool_Layer SHALL automatically tag the instance with `security-hold`, block promotion pipeline progression, and move the instance security group to `sg-pre-quarantine`.
7. THE Security_Tool_Layer SHALL use agent versions pinned to the ISO-approved version referenced in SSM Parameter Store; the instances SHALL NOT pull agent installers directly from the internet.
8. THE Security_Tool_Layer SHALL route Tanium server communications over TCP 8732 via the TGW to the ISO Environment, and CrowdStrike and Qualys cloud callbacks via TCP 443 through the NAT Gateway exclusively to the IP ranges stored in SSM Parameter Store under the `pre-approved-egress-ranges` parameter.

---

### Requirement 7: Workload Transfer from IRE to PRE

**User Story:** As a DR Admin, I want workloads to be transferred from the IRE to the PRE exclusively via encrypted artifact copy (not a live network path), so that there is no channel through which malware or an attacker present in the IRE can propagate into the PRE.

#### Acceptance Criteria

1. THE Promotion_Pipeline SHALL transfer workloads from IRE to PRE exclusively by cross-account AMI copy, with no live network path established between the IRE VPC and the PRE VPC at any time.
2. WHEN an AMI is copied from the IRE account into the PRE account, THE Promotion_Pipeline SHALL re-encrypt the copied AMI using `alias/pre-workload` as part of the `ec2:copy-image` operation.
3. IF the `ec2:copy-image` operation fails or the resulting AMI is not encrypted with `alias/pre-workload`, THEN THE Promotion_Pipeline SHALL abort the transfer, deregister any partially created AMI and its snapshot in the PRE account, and emit an error record to the WorkloadRecoveryRecord indicating copy failure before halting the pipeline execution.
4. WHEN an AMI arrives in the PRE account, THE Promotion_Pipeline SHALL run a checksum integrity validation Lambda before permitting instance launch.
5. IF the checksum integrity validation fails, THEN THE Promotion_Pipeline SHALL deregister the copied AMI, delete its snapshot, and send an alert to the DR team notification channel within 5 minutes of validation completion.
6. WHEN the IRE-to-PRE AMI transfer completes successfully, THE Promotion_Pipeline SHALL remove the cross-account snapshot share permission from the IRE side within the same pipeline execution.
7. WHEN a workload instance is launched from the transferred AMI in the PRE workload subnet, THE Promotion_Pipeline SHALL attach the EBS root volume encrypted with `alias/pre-ebs`.
8. WHEN a workload instance is launched from the transferred AMI in the PRE workload subnet, THE Promotion_Pipeline SHALL enforce IMDSv2 with a hop limit of 1 and tokens required on the instance metadata configuration.
9. THE Promotion_Pipeline SHALL record each transfer in a WorkloadRecoveryRecord with the IRE AMI ID, PRE AMI ID, transfer timestamp, and integrity validation status before proceeding to the hardening phase.
10. IF the WorkloadRecoveryRecord write fails, THEN THE Promotion_Pipeline SHALL halt execution and emit an error indicating audit record failure without proceeding to the hardening phase.

---

### Requirement 8: Workload Hardening in PRE

**User Story:** As a DR Admin, I want automated hardening playbooks to be applied to every recovered workload before it enters the validation phase, so that workloads meet a known-good security baseline before human reviewers assess them.

#### Acceptance Criteria

1. THE Promotion_Pipeline SHALL apply hardening Terraform modules in the following order: OS baseline (CIS Level 2), patch management, IAM instance hardening, network hardening, security tool verification, and compliance scan.
2. WHEN the patch management module is applied, THE Promotion_Pipeline SHALL verify that the SSM Patch Manager compliance score for the instance is at minimum 95% before proceeding to the next module.
3. WHEN the IAM instance hardening module is applied, THE Promotion_Pipeline SHALL enforce IMDSv2 by calling `ec2:ModifyInstanceMetadataOptions` with `http-tokens=required` and `http-put-response-hop-limit=1`.
4. WHEN the IAM instance hardening module is applied, THE Promotion_Pipeline SHALL verify that the instance profile is `pre-workload-instance` and SHALL terminate any other attached instance profiles.
5. WHEN the compliance scan module completes, THE Promotion_Pipeline SHALL record the AWS Config compliance score and the Qualys scan findings in the WorkloadRecoveryRecord; IF any critical AWS Config rules are non-compliant, THEN the pipeline SHALL halt and alert the DR team.
6. THE Promotion_Pipeline SHALL source all hardening Terraform modules from the ISO Environment GitHub repository and execute them via the Azure DevOps pipeline runner in the ISO Environment; no Terraform state SHALL be stored in the PRE account.

---

### Requirement 9: Workload Validation and Promotion Gate

**User Story:** As a CISO, I want a formal multi-step promotion gate that requires both zero critical/high security findings and dual human approval before any workload is promoted to Production, so that no workload enters Production without verified cleanliness and accountable human authorization.

#### Acceptance Criteria

1. WHEN the automated validation phase begins, THE Promotion_Pipeline SHALL evaluate all of the following checks concurrently: Tanium Comply CIS Level 2 score ≥ 95%, CrowdStrike zero active detections, Qualys zero Critical or High CVEs, AWS Config zero non-compliant rules, SSM Patch Manager status Compliant, and IMDSv2 enforced.
2. IF any automated check in the validation phase returns a non-passing result, THEN THE Promotion_Pipeline SHALL block the approval gate from opening and SHALL update the WorkloadRecoveryRecord with the blocked reason and finding details.
3. WHEN all automated checks pass, THE Promotion_Pipeline SHALL require sign-off from exactly one principal holding the `DR_LEAD` approver role and exactly one principal holding the `CISO` approver role, recorded as ApprovalRecords in the WorkloadRecoveryRecord.
4. IF the promotion gate receives an approval from a principal where `approver_role` is not `DR_LEAD` or `CISO`, THEN THE Promotion_Pipeline SHALL reject the approval and maintain the gate in a pending state.
5. WHEN both approvals are received and all automated checks have passed, THE Promotion_Pipeline SHALL create a new AMI from the PRE instance, re-encrypt it with a new Production KMS key (not the PRE workload key), and share the AMI with the Production account.
6. WHEN a workload is promoted from PRE to Production, THE Promotion_Pipeline SHALL record the promoted AMI ID, promotion timestamp, and both approver ARNs in the WorkloadRecoveryRecord with `PromotionStatus.current_phase = PROMOTED`.
7. WHEN any manual override of the promotion gate is recorded, THE Promotion_Pipeline SHALL log the override in CloudTrail and SHALL send a P1 alert to the CISO.

---

### Requirement 10: Immutable Audit Trail

**User Story:** As a Compliance Officer, I want all audit logs, VPC flow logs, and security tool reports to be stored in write-once S3 buckets with a minimum 7-year retention, so that the complete record of all actions taken during a cyber recovery event is preserved and tamper-proof for forensic and regulatory purposes.

#### Acceptance Criteria

1. THE PRE_VPC SHALL write CloudTrail logs to an S3 bucket (`pre-cloudtrail-logs-<ACCOUNT_ID>`) with S3 Object Lock in COMPLIANCE mode and a retention period of 7 years.
2. THE PRE_VPC SHALL enable CloudTrail log file validation (SHA-256 digest files) on the `pre-audit-trail` trail to allow integrity verification of log contents.
3. THE PRE_VPC SHALL write VPC Flow Logs to both a CloudWatch Log Group (`/pre/vpc-flow-logs`, retained 90 days) and an S3 archive bucket with Object Lock in COMPLIANCE mode and a retention period of 7 years.
4. THE Security_Tool_Layer SHALL write scan results to `pre-scan-results-*` S3 buckets configured with Object Lock in COMPLIANCE mode and a 7-year retention period.
5. WHEN any S3 bucket used for audit logs is evaluated by AWS Config rule `s3-bucket-object-lock-enabled`, THE PRE_VPC SHALL report compliant status; IF the rule reports non-compliant, THEN THE PRE_VPC SHALL trigger a P1 CloudWatch alarm.
6. THE PRE_VPC SHALL encrypt all CloudTrail logs with `alias/pre-cloudtrail` and all S3 audit logs with `alias/pre-s3` using SSE-KMS.
7. THE Break_Glass_Mechanism SHALL store break-glass session logs in a dedicated CloudWatch Log Group (`/pre/break-glass`) with a retention period of 7 years.

---

### Requirement 11: ISO Environment Shared Services Connectivity

**User Story:** As a DR Admin, I want the PRE VPC to consume shared services (AD authentication, DNS, certificate authority, Terraform pipelines) from the trusted ISO Environment over a controlled TGW path, so that PRE administration relies on a trusted foundation without requiring a separate, independently managed shared services stack.

#### Acceptance Criteria

1. THE PRE_VPC SHALL attach to the central Transit Gateway using a dedicated TGW attachment in a `/28` subnet (`10.1.4.0/28`), associated with an isolated PRE route table that contains no route to the Production VPC.
2. WHEN PRE admin identities authenticate, THE PRE_IAM_Layer SHALL federate via SAML from the ISO Microsoft AD ADFS, using a dedicated AD OU (`OU=PRE,OU=CyberRecovery,DC=corp,DC=internal`) with no group membership overlap with Production admin groups.
3. THE PRE_VPC SHALL forward DNS queries for `corp.internal` and `internal.aws` domains to the ISO DNS resolver inbound endpoint via a Route 53 Resolver outbound endpoint, with outbound endpoint IPs residing in the management subnets.
4. THE PRE_VPC SHALL allow LDAPS (port 636) inbound from the ISO CIDR (`10.2.0.0/16`) in the management subnet NACL and SHALL deny plain LDAP (port 389) from all sources other than the ISO CIDR.
5. WHEN PRE workloads require TLS certificates, THE Promotion_Pipeline SHALL request certificates from the AWS Private CA hosted in the ISO Environment via the TGW path; certificates SHALL be stored in PRE Secrets Manager encrypted with `alias/pre-secrets`.
6. THE Promotion_Pipeline SHALL store Terraform state exclusively in an S3 bucket in the ISO account; no PRE IAM principal SHALL have `s3:PutObject` permission on that state bucket.

---

### Requirement 12: AWS Config Compliance Monitoring

**User Story:** As a Security Operations Engineer, I want continuous AWS Config rule evaluation across all PRE resources, so that any configuration drift from the security baseline is detected automatically and immediately surfaced for remediation.

#### Acceptance Criteria

1. THE PRE_VPC SHALL enable AWS Config recording for all resource types in `eu-central-1` with delivery to a dedicated S3 bucket (`pre-config-logs`) protected by Object Lock in COMPLIANCE mode.
2. THE PRE_VPC SHALL enforce the following AWS Config managed rules: `encrypted-volumes`, `restricted-ssh`, `restricted-common-ports`, `iam-no-inline-policies`, `root-account-mfa-enabled`, `s3-bucket-server-side-encryption-enabled`, `vpc-flow-logs-enabled`, `cloud-trail-encryption-enabled`, and `kms-key-rotation-enabled`.
3. WHEN any AWS Config rule transitions to a non-compliant state for a PRE resource, THE PRE_VPC SHALL publish a notification to the `pre-cloudtrail-alerts` SNS topic within 5 minutes of the state change.
4. THE PRE_VPC SHALL enforce the custom Config rule `tgw-no-prod-routes` that evaluates whether the PRE TGW attachment route table contains any route targeting the Production VPC attachment; a matching route SHALL be reported as NON_COMPLIANT.
5. THE PRE_IAM_Layer SHALL enforce the custom Config rule `iam-no-cross-account-trust-prod-pre` that evaluates all IAM roles for trust relationships referencing the Production account ARN; any such trust SHALL be reported as NON_COMPLIANT.

---

### Requirement 13: Incident Response and Error Handling

**User Story:** As a Security Operations Engineer, I want automated detection and containment responses for critical error conditions during cyber recovery operations, so that security violations are contained rapidly and the recovery operation is not silently compromised.

#### Acceptance Criteria

1. WHEN CrowdStrike, Tanium, or Qualys detects an active threat on a PRE workload instance, THE Security_Tool_Layer SHALL automatically isolate the instance by moving it to security group `sg-pre-quarantine` with no outbound routes, tag it with `security-hold=true`, and alert the DR team within 5 minutes.
2. WHEN the AWS Config rule `tgw-no-prod-routes` detects a route to the Production VPC in the PRE TGW route table, THE PRE_VPC SHALL trigger a P1 PagerDuty alert and an EventBridge rule SHALL capture VPC Flow Log traffic from `10.0.0.0/16` for forensic review.
3. WHEN a KMS key deletion attempt (`kms:ScheduleKeyDeletion`) for a PRE key is blocked by the `PRE-DenyKMSKeyDeletion` SCP, THE PRE_KMS_Layer SHALL log the denied API call to CloudTrail and SHALL trigger a CloudWatch alarm notifying the security team.
4. WHEN the `pre-break-glass` role is assumed without a matching valid activation record, THE Break_Glass_Mechanism SHALL generate a P1 CloudWatch alarm to the CISO and security operations team within 60 seconds of role assumption.
5. WHEN an IRE-to-PRE AMI transfer integrity check fails, THE Promotion_Pipeline SHALL deregister the copied AMI, delete its associated snapshots, and require re-initiation of the transfer from the IRE source AMI.
6. WHEN a PRE workload instance fails any automated validation check after hardening, THE Promotion_Pipeline SHALL allow re-hardening and re-validation up to three times before escalating to the DR Lead for manual review.

---

### Requirement 14: Workload Recovery Record Integrity

**User Story:** As a DR Admin, I want every workload's recovery journey to be tracked in a structured, authoritative record from IRE restore through to Production promotion, so that the status and provenance of each workload are always auditable and unambiguous.

#### Acceptance Criteria

1. THE Promotion_Pipeline SHALL create a WorkloadRecoveryRecord at the start of each workload recovery operation containing the incident ID, workload name, source backup ARN, and restore timestamp.
2. WHEN any phase of the workload recovery workflow transitions (IRE_RESTORE, IRE_SCAN, IRE_TO_PRE, PRE_HARDENING, PRE_VALIDATION, AWAITING_APPROVAL, PROMOTING, PROMOTED, FAILED), THE Promotion_Pipeline SHALL update the `PromotionStatus.current_phase` field in the WorkloadRecoveryRecord.
3. THE Promotion_Pipeline SHALL record each ScanResult with tool name, scan type, timestamp, status, finding counts by severity, and report S3 URI in the WorkloadRecoveryRecord before the approval gate opens.
4. THE Promotion_Pipeline SHALL record each ApprovalRecord with the approver ARN, approver role, decision, timestamp, comments, and incident ticket reference in the WorkloadRecoveryRecord.
5. WHEN a workload is promoted to Production, THE Promotion_Pipeline SHALL record the promoted AMI ID and promotion timestamp in the WorkloadRecoveryRecord and SHALL set `PromotionStatus.gate_passed = true`.
6. IF the promotion is blocked or fails at any gate, THEN THE Promotion_Pipeline SHALL record the blocked reason in `PromotionStatus.blocked_reason` and SHALL set `PromotionStatus.gate_passed = false`.
