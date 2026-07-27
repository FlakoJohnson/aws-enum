# aws-enum

Red team AWS credential enumerator. Given AWS access key pairs, performs full identity, privilege, resource enumeration, and cross-account role assumption.

## What it enumerates

### Identity & Privilege

| Check | Details |
|---|---|
| **STS Identity** | ARN, account ID, alias, key type (AKIA/ASIA), root detection, AWS China/GovCloud auto-detection |
| **IAM User** | Username, groups, policies (attached + inline), access keys, creation date |
| **IAM Visibility** | Visible users, visible roles across the account |
| **Privilege Simulation** | 60+ IAM actions tested via `SimulatePrincipalPolicy`, high-value permissions flagged. Auto-converts session ARNs to role ARNs for assumed roles |

### Resources (multi-region)

| Service | Details |
|---|---|
| **S3** | All buckets, categorized (terraform, backup, logs) |
| **EC2** | Running instances, VPCs, IAM profiles, public IPs |
| **EKS** | Clusters with version, endpoint, role ARN, network config |
| **ECR** | Container image repositories |
| **SSM** | Managed instances (RCE targets), parameters (with SecureString count), SendCommand access test |
| **Secrets Manager** | Secret names and metadata, optional value extraction |
| **RDS** | DB instances and clusters, engine, endpoint, public accessibility |
| **Lambda** | Functions with runtime and execution role, environment variable extraction |
| **ECS** | Task definition environment variable extraction |
| **CloudWatch Logs** | Log groups |
| **Organizations** | Org structure, master account, all member accounts |

### Role Trust Analysis

- Enumerates all IAM role trust policies in the account
- Flags wildcard trusts and external (cross-account) trust relationships

### Environment Variable Extraction

- Pulls environment variables from Lambda function configurations and ECS task definitions
- Surfaces credentials, API keys, and connection strings embedded in runtime config

### Loot Generation

- Auto-generates actionable command lists based on enumeration results
- Includes S3 access commands, SSM session/RCE commands, terraform state pulls
- Saved as `loot_<account>.txt` in the output directory

### Role Assumption & Privilege Escalation

- Auto-assumes configurable role across own account or user-provided accounts
- With `--org-enum`, discovers all org accounts and assumes into each child account
- Full sub-enumeration (EKS, S3, SSM, Secrets Manager) in each assumed account
- Priv simulation auto-converts session ARNs to role ARNs for assumed roles

## Usage

```bash
# Single credential
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey

# With session token
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey:sessiontoken

# Batch from file
python3 aws_enum.py -f creds.txt

# Pull actual secret values from SSM + Secrets Manager
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey --pull-secrets

# Try role in specific accounts
python3 aws_enum.py -f creds.txt --accounts 123456789012:prod,987654321098:staging

# Load target accounts from file
python3 aws_enum.py -f creds.txt --accounts-file accounts.txt

# Custom role name
python3 aws_enum.py -f creds.txt --role-name my-admin-role

# All AWS regions
python3 aws_enum.py -f creds.txt --all-regions

# Skip role assumption
python3 aws_enum.py -f creds.txt --no-assume

# Fast mode (skip priv simulation)
python3 aws_enum.py -f creds.txt --fast

# Stealth mode (skip noisy checks, add jitter)
python3 aws_enum.py -f creds.txt --stealth

# Load creds from AWS CLI profile
python3 aws_enum.py --profile my-profile

# Organization-wide enumeration (discovers + assumes into all child accounts)
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey --org-enum

# Org enum with custom role name per account
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey --org-enum --org-role CustomAdminRole

# Only pull secrets, skip all other enumeration
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey --pull-secrets-only

# Only check identity + try role assumption, skip all other enumeration
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey --role-name my-admin-role --assume-only

# Assume-only across multiple candidate accounts (tries all, doesn't stop at first success)
python3 aws_enum.py -c AKIAXXXXXXXX:secretkey --role-name my-admin-role --accounts 123456789012,987654321098 --assume-only

# Via proxychains
proxychains python3 aws_enum.py -f creds.txt -o results.json
```

### Input file format

```
# Comments ignored
AKIAXXXXXXXXXXXXXXXX:secretkeyhere
AKIAXXXXXXXXXXXXXXXX:secretkeyhere:optionalsessiontoken
```

### Options

| Flag | Description |
|---|---|
| `-c`, `--cred` | Single credential (`KEY:SECRET` or `KEY:SECRET:TOKEN`) |
| `-f`, `--file` | File with credentials (one per line) |
| `--profile` | Load credentials from an AWS CLI profile (`~/.aws/credentials`) |
| `-a`, `--all` | Run all credentials from file without interactive selection |
| `-r`, `--region` | Anchor region for STS calls (default: `us-east-1`) |
| `--all-regions` | Check all AWS regions (slower) |
| `--fast` | Skip IAM privilege simulation |
| `--stealth` | Skip `SimulatePrincipalPolicy`/`SendCommand` test, jitter every check/region/resource boundary |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--no-assume` | Skip role assumption |
| `--role-name` | Role to attempt assumption (default: `atmos-bootstrap-role`) |
| `--accounts` | Comma-separated account IDs (or `ID:alias`). Only tries these accounts (does not auto-add own) |
| `--accounts-file` | File with account IDs |
| `--assume-only` | Check identity, try assuming `--role-name`, then stop — skips all other enumeration. Requires `--role-name`, incompatible with `--no-assume` |
| `--org-enum` | Discover all org accounts and assume into each child account for full enumeration |
| `--org-role` | Role to assume per org account (default: `OrganizationAccountAccessRole`) |
| `--pull-secrets` | Pull actual SSM/SM secret values (default: names only) |
| `--pull-secrets-only` | Skip all enumeration — only pull SSM params and SM secrets across all regions |
| `-o`, `--output` | JSON output path (auto-names if omitted) |
| `--out-dir` | Output directory |

## Output

Results auto-save to a timestamped directory:

```
aws_enum_YYYYMMDD_HHMMSS/
  AKIAXXXXXXXXXXXXXXXX.json       # Full JSON results
  ssm_params_<account>_<region>.txt    # SSM parameter names
  ssm_secrets_<account>_<region>.txt   # SSM values (if --pull-secrets)
  sm_names_<account>_<region>.txt      # Secrets Manager names
  sm_secrets_<account>_<region>.txt    # SM values (if --pull-secrets)
  loot_<account>.txt                   # Actionable exploit commands
```

## OPSEC

- **Read-only by default** — enumeration only, no modifications
- `--pull-secrets` reads SSM/SM values (generates `GetParameter`/`GetSecretValue` CloudTrail events)
- `--stealth` mode skips `SimulatePrincipalPolicy` and the `SendCommand` RCE test outright, and adds random jitter at every check/region/account boundary (0.5-2.5s) plus every per-resource call — S3 buckets, SSM params, SM secrets, ECS task defs, role-assumption attempts (0.1-0.4s) — to break up the single-principal CloudTrail call-volume burst that GuardDuty's anomaly-detection models (`CredentialAccess:IAMUser/AnomalousBehavior`, `Recon:IAMUser/*`) and velocity-based CloudWatch alarms key off of. It throttles requested cross-account role assumption (`--accounts`/`--org-enum`) rather than skipping it, and does not reduce enumeration scope — same coverage, slower and spread out
- `--no-assume` avoids `AssumeRole` CloudTrail events entirely
- `SendCommand` test uses a fake instance ID — will show as `InvalidInstanceId` in CloudTrail, not actual command execution
- AWS China (`aws-cn`) and GovCloud (`aws-us-gov`) keys are auto-detected — on `InvalidClientTokenId`/`SignatureDoesNotMatch`, retries against `cn-northwest-1`/`us-gov-west-1` and switches to the matching partition endpoints
- Works with `proxychains` out of the box

## Requirements

```bash
pip install boto3
```

## Disclaimer

For authorized security testing and red team engagements only. Ensure you have proper authorization before enumerating any AWS resources.
