#!/usr/bin/env python3
"""
Shadow agent correlator (hackathon prototype).

Detection rule: observed AI workloads minus registered runtime bindings
= shadow agent candidates.

Pipeline:
  1. Read VPC Flow Logs from S3, keep ACCEPTed flows to the AI stub.
  2. Group flows by source ENI, resolve each ENI to an EC2 instance.
  3. Check the DynamoDB agent registry for each instance.
  4. Resolve the instance IAM role.
  5. Pull a CloudTrail timeline per role/instance.
  6. Emit findings.json.

No em dashes used anywhere in this file by design.
"""

import argparse
import gzip
import io
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

OBJECT_CAP = 2000
TIMELINE_CAP = 25
MAX_RESULTS = 50
ATTRIBUTION_DAYS = 7

# VPC flow log default format, positional fields.
FLOW_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status",
]


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_args():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Correlate VPC flow logs with the agent registry "
                    "to find shadow AI agents."
    )
    parser.add_argument(
        "--config",
        default=os.path.join(script_dir, "..", "demo-config.json"),
        help="Path to demo-config.json",
    )
    parser.add_argument(
        "--hours",
        type=float,
        default=3,
        help="Lookback window in hours for flow logs and CloudTrail",
    )
    parser.add_argument(
        "--out",
        default=os.path.join(script_dir, "..", "findings.json"),
        help="Where to write findings JSON",
    )
    return parser.parse_args()


def load_config(path):
    with open(path) as fh:
        return json.load(fh)


def iter_flow_records(s3, bucket, prefix, stub_ip, stub_port, window_start):
    """Yield dicts for ACCEPTed flow records aimed at the AI stub."""
    paginator = s3.get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)
    # S3 lists oldest-first; with OBJECT_CAP that keeps only stale files.
    # Read newest-first so recent windows are actually covered.
    _objs = [o for _pg in pages for o in _pg.get("Contents", [])]
    _objs.sort(key=lambda o: o.get("Key", ""), reverse=True)
    pages = [{"Contents": _objs}]
    seen = 0
    for page in pages:
        for obj in page.get("Contents", []):
            key = obj.get("Key", "")
            if not key.endswith(".gz"):
                continue
            seen += 1
            if seen > OBJECT_CAP:
                return
            try:
                body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                text = gzip.decompress(body).decode("utf-8", errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < len(FLOW_FIELDS):
                    continue  # malformed line
                rec = dict(zip(FLOW_FIELDS, parts))
                if (
                    rec["dstaddr"] != stub_ip
                    or rec["dstport"] != stub_port
                    or rec["action"] != "ACCEPT"
                ):
                    continue
                try:
                    start = datetime.fromtimestamp(int(rec["start"]), tz=timezone.utc)
                    end = datetime.fromtimestamp(int(rec["end"]), tz=timezone.utc)
                except ValueError:
                    continue
                if end < window_start:
                    continue
                rec["_start"] = start
                rec["_end"] = end
                yield rec


def resolve_eni(ec2, eni_id):
    """Return (instance_id, instance_name or None) for an ENI."""
    try:
        resp = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        ifaces = resp.get("NetworkInterfaces", [])
        if not ifaces:
            return None, None
        attachment = ifaces[0].get("Attachment") or {}
        instance_id = attachment.get("InstanceId")
    except ClientError:
        return None, None
    if not instance_id:
        return None, None
    name = None
    try:
        desc = ec2.describe_instances(InstanceIds=[instance_id])
        for reservation in desc.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                for tag in inst.get("Tags", []) or []:
                    if tag.get("Key") == "Name":
                        name = tag.get("Value")
    except ClientError:
        pass
    return instance_id, name


def registry_lookup(dynamodb, table_name, instance_id):
    """Return the registry item dict (plain python values) or None."""
    try:
        resp = dynamodb.get_item(
            TableName=table_name,
            Key={"agent_id": {"S": instance_id}},
        )
    except ClientError:
        return None
    item = resp.get("Item")
    if not item:
        return None
    return {k: v.get("S", "") for k, v in item.items()}


def resolve_iam_role(ec2, iam, instance_id, registry_item):
    """Return the IAM role name for the instance."""
    if registry_item and registry_item.get("iam_role"):
        return registry_item["iam_role"]
    try:
        assoc = ec2.describe_iam_instance_profile_associations(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]
        )
        assocs = assoc.get("IamInstanceProfileAssociations", [])
        if not assocs:
            return "unknown"
        profile = assocs[0].get("IamInstanceProfile") or {}
        profile_arn = profile.get("Arn", "")
        profile_name = profile.get("Name") or profile_arn.split("/")[-1]
        if not profile_name:
            return "unknown"
        ip = iam.get_instance_profile(InstanceProfileName=profile_name)
        roles = ip.get("InstanceProfile", {}).get("Roles", [])
        if roles:
            return roles[0].get("RoleName", "unknown")
    except ClientError:
        pass
    return "unknown"


def cloudtrail_timeline(cloudtrail, role_name, instance_id, start, end):
    """Return a chronological list of downstream action dicts."""
    entries = []
    if not role_name or role_name == "unknown":
        return entries
    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "Username", "AttributeValue": role_name}
            ],
            StartTime=start,
            EndTime=end,
            MaxResults=MAX_RESULTS,
        )
    except ClientError:
        return entries
    for event in reversed(resp.get("Events", [])):
        raw = event.get("CloudTrailEvent", "") or ""
        username = event.get("Username", "")
        keep = False
        if username == role_name and instance_id in raw:
            keep = True
        else:
            try:
                parsed = json.loads(raw)
                identity = parsed.get("userIdentity", {}) or {}
                principal = identity.get("principalId", "") or ""
                if principal.endswith(":" + instance_id):
                    keep = True
                elif identity.get("userName") == role_name and instance_id in raw:
                    keep = True
            except (ValueError, AttributeError):
                pass
        if not keep:
            continue
        detail = ""
        resources = event.get("Resources", []) or []
        if resources:
            detail = resources[0].get("ResourceName", "") or ""
        entries.append(
            {
                "time": iso(event["EventTime"]),
                "event": event.get("EventName", ""),
                "detail": detail,
            }
        )
        if len(entries) >= TIMELINE_CAP:
            break
    return entries



def describe_identity(user_identity):
    """Turn a CloudTrail userIdentity dict into a short human string."""
    if not user_identity:
        return "unknown"
    id_type = user_identity.get("type", "")
    if id_type == "IAMUser":
        return "IAM user " + user_identity.get("userName", "unknown")
    if id_type == "AssumedRole":
        arn = user_identity.get("arn", "")
        parts = arn.split("/")
        role = parts[1] if len(parts) > 2 else arn
        session = parts[2] if len(parts) > 2 else ""
        label = "assumed role " + role
        if session:
            label = label + " (session " + session + ")"
        return label
    if id_type == "Root":
        return "root account"
    if id_type == "FederatedUser":
        return "federated user " + user_identity.get("userName", "")
    return user_identity.get("arn", "") or id_type or "unknown"


def lookup_who(cloudtrail, resource_name, event_name, start, end):
    """Find who performed event_name on resource_name via CloudTrail.

    Returns (who_string, event_time_iso) or (None, None).
    """
    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": event_name},
                {"AttributeKey": "ResourceName", "AttributeValue": resource_name},
            ],
            StartTime=start,
            EndTime=end,
            MaxResults=MAX_RESULTS,
        )
    except ClientError:
        return None, None
    for event in resp.get("Events", []):
        if event.get("EventName") != event_name:
            continue
        raw = event.get("CloudTrailEvent", "") or ""
        try:
            parsed = json.loads(raw)
        except ValueError:
            continue
        who = describe_identity(parsed.get("userIdentity") or {})
        return who, iso(event["EventTime"])
    return None, None


def attribute_owner(cloudtrail, cloudtrail_global, instance_id, role_name,
                    start, end):
    """Attribute a shadow workload to a human owner via CloudTrail.

    Follows the chain: who launched the instance, who created its IAM role.
    IAM is a global service, so role events are read from us-east-1.
    The chain can honestly stop at a shared role, a team, or automation;
    that outcome is reported, not hidden.
    """
    launched_by, launched_at = lookup_who(
        cloudtrail, instance_id, "RunInstances", start, end)
    role_by, role_at = None, None
    if role_name and role_name != "unknown":
        # IAM control-plane events land in us-east-1, not the local region.
        role_by, role_at = lookup_who(
            cloudtrail_global, role_name, "CreateRole", start, end)

    attribution = {
        "instance_launched_by": launched_by,
        "instance_launched_at": launched_at,
        "role_created_by": role_by,
        "role_created_at": role_at,
    }

    notes = []
    if launched_by:
        when = " at " + launched_at if launched_at else ""
        notes.append("instance launched by " + launched_by + when)
    else:
        notes.append("no RunInstances event in window; launcher unknown "
                     "(launch may predate the window)")
    if role_name and role_name != "unknown":
        if role_by:
            when = " at " + role_at if role_at else ""
            notes.append("IAM role " + role_name + " created by " + role_by + when)
        else:
            notes.append("no CreateRole event for " + role_name + " in window; "
                         "role creator unknown")
    low = " ".join(notes).lower()
    if "assumed role" in low or "federated" in low:
        notes.append("chain stops at a shared role or automation; "
                     "no single human identified")
    attribution["notes"] = notes
    return attribution


def fmt_ts(dt):
    return dt.strftime("%H:%M:%SZ")


def build_finding(eni_id, flows, instance_id, instance_name, registry_item,
                  role_name, timeline, stub_ip, stub_port, attribution=None):
    count = len(flows)
    first = min(f["_start"] for f in flows)
    last = max(f["_end"] for f in flows)
    registered = registry_item is not None
    status = "registered" if registered else "shadow-candidate"
    owner = registry_item.get("owner", "") if registered else "unknown"
    owner_attribution = attribution or {}
    if not registered and attribution:
        launched_by = attribution.get("instance_launched_by")
        if launched_by:
            owner = launched_by

    evidence = [
        "%d ACCEPTed flows to %s:%s between %s and %s"
        % (count, stub_ip, stub_port, fmt_ts(first), fmt_ts(last)),
        "ENI %s attached to %s (Name=%s)" % (eni_id, instance_id, instance_name),
    ]
    if registered:
        evidence.append(
            "registry binding found: owner=%s" % registry_item.get("owner", "")
        )
    else:
        evidence.append("no registry binding for %s" % instance_id)
    for note in owner_attribution.get("notes", []):
        evidence.append("owner attribution: %s" % note)

    if registered or count >= 1:
        confidence = "high"
    else:
        confidence = "medium"

    return {
        "instance_id": instance_id,
        "instance_name": instance_name,
        "ai_destination": "%s:%s" % (stub_ip, stub_port),
        "status": status,
        "owner": owner,
        "confidence": confidence,
        "evidence": evidence,
        "iam_role": role_name,
        "owner_attribution": owner_attribution,
        "downstream_actions": timeline,
    }


def main():
    args = parse_args()
    config = load_config(args.config)

    region = config["region"]
    account_id = config["account_id"]
    stub_ip = config["private_ips"]["ai-stub"]
    stub_port = str(config["stub_port"])
    registry_table = config["registry_table"]
    logs_bucket = config["logs_bucket"]
    window_start = utcnow() - timedelta(hours=args.hours)
    window_end = utcnow()

    session = boto3.Session(region_name=region)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    dynamodb = session.client("dynamodb")
    iam = session.client("iam")
    cloudtrail = session.client("cloudtrail")
    cloudtrail_global = session.client("cloudtrail", region_name="us-east-1")

    flow_prefix = config.get("flow_log_prefix", "")
    prefix = "%sAWSLogs/%s/vpcflowlogs/%s/" % (flow_prefix, account_id, region)
    by_eni = defaultdict(list)
    for rec in iter_flow_records(s3, logs_bucket, prefix, stub_ip, stub_port,
                                 window_start):
        by_eni[rec["interface-id"]].append(rec)

    if not by_eni:
        print("no AI-stub flows found in window")
        payload = {"generated_at": iso(window_end), "findings": []}
        with open(args.out, "w") as fh:
            json.dump(payload, fh, indent=2)
        print("wrote %s" % args.out)
        return

    findings = []
    for eni_id, flows in sorted(by_eni.items()):
        instance_id, instance_name = resolve_eni(ec2, eni_id)
        if not instance_id:
            continue
        registry_item = registry_lookup(dynamodb, registry_table, instance_id)
        role_name = resolve_iam_role(ec2, iam, instance_id, registry_item)
        timeline = cloudtrail_timeline(cloudtrail, role_name, instance_id,
                                       window_start, window_end)
        attribution = None
        if registry_item is None:
            # Attribution is historical: the launch/role events long predate
            # the detection window, so it gets its own lookback.
            attribution_start = window_end - timedelta(days=ATTRIBUTION_DAYS)
            attribution = attribute_owner(cloudtrail, cloudtrail_global,
                                          instance_id, role_name,
                                          attribution_start, window_end)
        findings.append(
            build_finding(eni_id, flows, instance_id, instance_name,
                          registry_item, role_name, timeline, stub_ip, stub_port,
                          attribution)
        )

    payload = {"generated_at": iso(window_end), "findings": findings}
    with open(args.out, "w") as fh:
        json.dump(payload, fh, indent=2)

    # Human-readable summary.
    print("Shadow agent correlation run")
    print("window: last %.1f hours, AI stub %s:%s" % (args.hours, stub_ip, stub_port))
    print("ENIs with stub traffic: %d" % len(by_eni))
    for f in findings:
        print("")
        print("%s (%s) -> %s" % (f["instance_name"], f["instance_id"], f["status"]))
        print("  owner: %s | confidence: %s | role: %s"
              % (f["owner"], f["confidence"], f["iam_role"]))
        for ev in f["evidence"]:
            print("  - %s" % ev)
        if f["downstream_actions"]:
            print("  downstream actions (%d):" % len(f["downstream_actions"]))
            for a in f["downstream_actions"]:
                detail = " (%s)" % a["detail"] if a["detail"] else ""
                print("    %s %s%s" % (a["time"], a["event"], detail))
    print("")
    print("wrote %d findings to %s" % (len(findings), args.out))


if __name__ == "__main__":
    main()
