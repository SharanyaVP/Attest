#!/usr/bin/env python3
"""Register this EC2 workload in the shadow-demo agent registry (DynamoDB).

Reads /etc/shadowdemo/config.json, resolves this host's instance ID and
primary ENI via IMDS, then put_item into the configured DynamoDB table.
"""
import json
import os
import sys
from datetime import datetime, timezone

import boto3
import urllib.request

CONFIG_PATH = "/etc/shadowdemo/config.json"
IMDS_BASE = "http://169.254.169.254"
TOKEN_URL = IMDS_BASE + "/latest/api/token"
TOKEN_HEADER = "X-aws-ec2-metadata-token"
TOKEN_TTL_HEADER = "X-aws-ec2-metadata-token-ttl-seconds"


def imds_get(path):
    """GET an IMDS metadata path, trying IMDSv2 first then IMDSv1."""
    token = None
    try:
        req = urllib.request.Request(
            TOKEN_URL,
            data=b"",
            method="PUT",
            headers={TOKEN_TTL_HEADER: "21600"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            token = resp.read().decode("utf-8")
    except Exception:
        token = None  # fall back to IMDSv1

    headers = {TOKEN_HEADER: token} if token else {}
    req = urllib.request.Request(IMDS_BASE + path, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8").strip()


def main():
    if not os.path.exists(CONFIG_PATH):
        print("ERROR: config missing: %s" % CONFIG_PATH, file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    instance_id = imds_get("/latest/meta-data/instance-id")
    mac = imds_get("/latest/meta-data/mac")

    ec2 = boto3.client("ec2", region_name=config["region"])
    resp = ec2.describe_network_interfaces(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    )
    ifaces = resp.get("NetworkInterfaces", [])
    if not ifaces:
        print("ERROR: no network interfaces found for %s" % instance_id, file=sys.stderr)
        sys.exit(1)
    eni = ifaces[0]["NetworkInterfaceId"]

    dynamodb = boto3.client("dynamodb", region_name=config["region"])
    dynamodb.put_item(
        TableName=config["table"],
        Item={
            "agent_id": {"S": instance_id},
            "agent_name": {"S": config["agent_name"]},
            "instance_id": {"S": instance_id},
            "eni": {"S": eni},
            "iam_role": {"S": config["role_name"]},
            "owner": {"S": config["owner"]},
            "intent": {"S": config["intent"]},
            "registered_at": {"S": datetime.now(timezone.utc).isoformat()},
        },
    )

    print("registered agent %s instance %s eni %s mac %s" % (config["agent_name"], instance_id, eni, mac))


if __name__ == "__main__":
    main()
