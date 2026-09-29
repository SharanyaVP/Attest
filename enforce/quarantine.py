#!/usr/bin/env python3
"""Quarantine a shadow agent instance: show its LIVE IAM permission envelope, then isolate it.

Usage (dry run, default; prints what WOULD happen and exits 0):
    python3 quarantine.py --instance-id i-0abc123
    python3 quarantine.py --instance-id i-0abc123 --role ShadowAgentRole

Usage (actually quarantine):
    python3 quarantine.py --instance-id i-0abc123 --enforce
    python3 quarantine.py --instance-id i-0abc123 --enforce --stop

No em dashes anywhere in this file, per demo style rules.
"""
import argparse
import json
import os
import sys

import boto3

QUARANTINE_SG_NAME = "shadowdemo-quarantine-sg"
QUARANTINE_SG_DESC = "Quarantine: no ingress, no egress"


def resolve_role(ec2, iam, instance_id):
    """Resolve the IAM role name attached to an instance via its instance profile."""
    resp = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [instance_id]}]
    )
    assocs = resp.get("IamInstanceProfileAssociations", [])
    if not assocs:
        raise SystemExit("ERROR: no IAM instance profile association found for %s" % instance_id)
    profile_arn = assocs[0]["IamInstanceProfile"]["Arn"]
    profile_name = profile_arn.split("/")[-1]
    profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    roles = profile.get("Roles", [])
    if not roles:
        raise SystemExit("ERROR: instance profile %s has no roles" % profile_name)
    return roles[0]["RoleName"]


def compact_statement_lines(policy_doc):
    """Return compact 'Effect:Action on Resource' lines from a policy document.

    Handles Statement as dict or list, Action as str or list.
    """
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    lines = []
    for s in stmts:
        effect = s.get("Effect", "?")
        actions = s.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = s.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        resource = ",".join(resources) if resources else "*"
        for a in actions:
            lines.append("%s:%s on %s" % (effect, a, resource))
    return lines


def allow_actions(policy_doc):
    """Return the set of Allow actions in a policy document."""
    actions = set()
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        a = s.get("Action", [])
        if isinstance(a, str):
            a = [a]
        actions.update(a)
    return actions


def print_permission_envelope(iam, role):
    """Step 1: read and print the role's LIVE permission envelope from IAM."""
    print("=== LIVE permission envelope for role: %s ===" % role)

    attached = iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
    print("Managed (attached) policies:")
    for p in attached:
        print("  - %s (%s)" % (p["PolicyName"], p["PolicyArn"]))
    if not attached:
        print("  (none)")

    inline_names = iam.list_role_policies(RoleName=role).get("PolicyNames", [])
    print("Inline policies:")
    for name in inline_names:
        doc = iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]
        print("  - %s" % name)
        for line in compact_statement_lines(doc):
            print("      %s" % line)
    if not inline_names:
        print("  (none)")

    # Scary one-line summary: count distinct Allow actions across inline
    # policies AND attached managed policies (expanded live).
    distinct_actions = set()
    for name in inline_names:
        doc = iam.get_role_policy(RoleName=role, PolicyName=name)["PolicyDocument"]
        distinct_actions.update(allow_actions(doc))
    for p in attached:
        try:
            pol = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]
            ver = iam.get_policy_version(
                PolicyArn=p["PolicyArn"], VersionId=pol["DefaultVersionId"]
            )["PolicyVersion"]["Document"]
            distinct_actions.update(allow_actions(ver))
        except Exception as e:  # managed doc unreadable, note and continue
            print("  (could not expand %s: %s)" % (p["PolicyName"], e))

    if distinct_actions:
        sample = sorted(distinct_actions)[0]
        print(
            "SUMMARY: role %s grants %d distinct actions including %s"
            % (role, len(distinct_actions), sample)
        )
    else:
        print("SUMMARY: role %s grants no Allow actions via inline policies" % role)


def find_or_create_quarantine_sg(ec2, vpc_id, dry_run):
    """Return the quarantine SG id, creating it (no rules) if needed."""
    resp = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    sgs = resp.get("SecurityGroups", [])
    if sgs:
        sg_id = sgs[0]["GroupId"]
        print("Found existing quarantine SG %s (%s)" % (QUARANTINE_SG_NAME, sg_id))
        return sg_id

    if dry_run:
        print("WOULD create security group '%s' in %s (no ingress, no egress)" % (QUARANTINE_SG_NAME, vpc_id))
        return "<new-quarantine-sg-id>"
    sg_id = ec2.create_security_group(
        GroupName=QUARANTINE_SG_NAME,
        Description=QUARANTINE_SG_DESC,
        VpcId=vpc_id,
    )["GroupId"]
    # Deliberately: no authorize_security_group_ingress/egress calls.
    print("Created quarantine SG %s (%s): no ingress, no egress" % (QUARANTINE_SG_NAME, sg_id))
    return sg_id


def main():
    default_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo-config.json")
    ap = argparse.ArgumentParser(description="Show a shadow agent's live IAM envelope, then quarantine it.")
    ap.add_argument("--instance-id", required=True)
    ap.add_argument("--role", default=None, help="IAM role name; if omitted, resolved from the instance profile")
    ap.add_argument("--config", default=default_config)
    ap.add_argument("--dry-run", dest="dry_run", action="store_true", default=True,
                    help="print what WOULD happen (default)")
    ap.add_argument("--enforce", dest="dry_run", action="store_false",
                    help="actually quarantine the instance")
    ap.add_argument("--stop", action="store_true",
                    help="also stop the instance (only meaningful with --enforce)")
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)
    region = cfg["region"]
    vpc_id = cfg["vpc_id"]

    ec2 = boto3.client("ec2", region_name=region)
    iam = boto3.client("iam", region_name=region)

    role = args.role or resolve_role(ec2, iam, args.instance_id)

    # Step 1: always show the live permission envelope, even in dry run.
    print_permission_envelope(iam, role)

    # Step 2: quarantine.
    sg_id = find_or_create_quarantine_sg(ec2, vpc_id, args.dry_run)

    if args.dry_run:
        print("WOULD quarantine instance %s: set security groups to [%s]" % (args.instance_id, sg_id))
        if args.stop:
            print("WOULD stop instance %s" % args.instance_id)
        print("Dry run complete. Re-run with --enforce to actually quarantine.")
        sys.exit(0)

    ec2.modify_instance_attribute(InstanceId=args.instance_id, Groups=[sg_id])
    print("Quarantined instance %s: security groups now [%s]" % (args.instance_id, sg_id))
    if args.stop:
        ec2.stop_instances(InstanceIds=[args.instance_id])
        print("Stopped instance %s" % args.instance_id)


if __name__ == "__main__":
    main()
