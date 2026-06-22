#!/usr/bin/env python3
"""Seed LocalStack with IAM roles that mirror the AcmeTech breach scenario.

Run this once after `docker compose -f docker-compose.localstack.yml up -d`
to create the roles that TrustField's policy deployer will attach deny policies to.

Usage:
    AWS_ENDPOINT_URL=http://localhost:4566 python scripts/seed_localstack.py
"""
from __future__ import annotations

import json
import os
import sys

# Allow running from repo root without installing the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from trustfield.cloud.aws_client import get_iam_client, get_sts_client

TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "sts:AssumeRole",
    }],
})

# Roles in the AcmeTech demo org graph (mirrors state/org_graph.json node IDs)
ROLES = [
    "dev-alice",
    "ci-runner",
    "deploy-bot",
    "data-pipeline",
    "secrets-access-role",
    "admin-escalation-role",
    "prod-db-access",
    "audit-logger",
    "billing-reader",
    "infra-provisioner",
]


def main() -> None:
    endpoint = os.getenv("AWS_ENDPOINT_URL")
    if not endpoint:
        print("ERROR: AWS_ENDPOINT_URL not set.  "
              "Example: AWS_ENDPOINT_URL=http://localhost:4566")
        sys.exit(1)

    iam = get_iam_client()
    sts = get_sts_client()

    # Verify LocalStack is reachable
    try:
        identity = sts.get_caller_identity()
        print(f"Connected to: {endpoint}")
        print(f"  Account : {identity['Account']}")
        print(f"  UserId  : {identity['UserId']}")
    except Exception as exc:
        print(f"ERROR: Cannot reach LocalStack at {endpoint}: {exc}")
        sys.exit(1)

    print(f"\nSeeding {len(ROLES)} IAM roles...\n")
    created = 0
    skipped = 0

    for role in ROLES:
        try:
            iam.create_role(
                RoleName=role,
                AssumeRolePolicyDocument=TRUST_POLICY,
                Description=f"TrustField seed role: {role}",
            )
            print(f"  [+] Created  {role}")
            created += 1
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"  [~] Skipped  {role}  (already exists)")
            skipped += 1

    print(f"\nDone.  {created} created, {skipped} already existed.")
    print("\nNext step:")
    print("  AWS_ENDPOINT_URL=http://localhost:4566 python demos/demo_localstack.py")


if __name__ == "__main__":
    main()
