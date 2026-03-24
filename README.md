# aws-enum

Red team AWS credential enumerator. Given AWS access key pairs, performs full identity, privilege, resource enumeration, and cross-account role assumption.

## What it enumerates

### Identity & Privilege

| Check | Details |
|---|---|
| **STS Identity** | ARN, account ID, alias, key type (AKIA/ASIA), root detection |
| **IAM User** | Username, groups, policies (attached + inline), access keys, creation date |
| **IAM Visibility** | Visible users, visible roles across the account |
| **Privilege Simulation** | 60+ IAM actions tested via `SimulatePrincipalPolicy`, high-value permissions flagged |

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
| **Lambda** | Functions with runtime and execution role |
| **CloudWatch Logs** | Log groups |
| **Organizations** | Org structure, master account, all member accounts |

### Role Assumption & Privilege Escalation

- Auto-assumes configurable role across own account + discovered org accounts + user-provided accounts
- Compares privilege levels between base credential and assumed roles
- Automatically uses the most privileged credential for enumeration
- Full sub-enumeration (EKS, S3, SSM, Secrets Manager) in each assumed account

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
| `-r`, `--region` | Anchor region for STS calls (default: `us-east-1`) |
| `--all-regions` | Check all 14 AWS regions (slower) |
| `--fast` | Skip IAM privilege simulation |
| `--stealth` | Skip noisy checks, add random jitter, limit cross-account |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--no-assume` | Skip role assumption |
| `--role-name` | Role to attempt assumption (default: `atmos-bootstrap-role`) |
| `--accounts` | Comma-separated account IDs (or `ID:alias`) |
| `--accounts-file` | File with account IDs |
| `--pull-secrets` | Pull actual SSM/SM secret values (default: names only) |
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
```

## OPSEC

- **Read-only by default** — enumeration only, no modifications
- `--pull-secrets` reads SSM/SM values (generates `GetParameter`/`GetSecretValue` CloudTrail events)
- `--stealth` mode skips `SimulatePrincipalPolicy`, `SendCommand` tests, and cross-account role attempts; adds random jitter
- `--no-assume` avoids `AssumeRole` CloudTrail events entirely
- `SendCommand` test uses a fake instance ID — will show as `InvalidInstanceId` in CloudTrail, not actual command execution
- Works with `proxychains` out of the box

## Requirements

```bash
pip install boto3
```

## Disclaimer

For authorized security testing and red team engagements only. Ensure you have proper authorization before enumerating any AWS resources.
