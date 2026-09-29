#!/usr/bin/env python3
"""Demo agent workload: register (optional), call the AI stub, touch S3,
optionally read a canary secret. Fails loudly on any error.
"""
import json
import os
import subprocess
import sys
import traceback
import urllib.request

import boto3

CONFIG_PATH = "/etc/shadowdemo/config.json"
REGISTER_SCRIPT = "/opt/shadowdemo/register.py"


def main():
    if not os.path.exists(CONFIG_PATH):
        print("ERROR: config missing: %s" % CONFIG_PATH, file=sys.stderr)
        sys.exit(1)

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    try:
        # Step 1: self-registration (only if the config says to register).
        if config.get("register"):
            result = subprocess.run(
                [sys.executable, REGISTER_SCRIPT],
                capture_output=True,
                text=True,
            )
            if result.stdout:
                print(result.stdout, end="")
            if result.returncode != 0:
                print("ERROR: register.py failed:\n%s" % result.stderr, file=sys.stderr)
                sys.exit(result.returncode)

        # Step 2: POST to the controlled AI stub.
        url = config["stub_url"].rstrip("/") + "/v1/chat"
        payload = json.dumps(
            {"prompt": "summarize today's feed", "agent": config["agent_name"]}
        ).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print("stub POST status %s" % resp.status)
            print("stub reply: %s" % body)

        # Step 3: S3 list and read.
        s3 = boto3.client("s3", region_name=config["region"])
        listing = s3.list_objects_v2(Bucket=config["bucket"], Prefix="digest-input/")
        keys = [o["Key"] for o in listing.get("Contents", [])]
        print("s3 objects under digest-input/: %s" % ", ".join(keys))
        obj = s3.get_object(Bucket=config["bucket"], Key="digest-input/notes.txt")
        text = obj["Body"].read().decode("utf-8", errors="replace")
        print("notes.txt preview: %s" % text[:120])

        # Step 4: optional canary secret read.
        if config.get("read_secret"):
            secrets = boto3.client("secretsmanager", region_name=config["region"])
            secrets.get_secret_value(SecretId="shadowdemo/canary-db-password")
            print("secret retrieved (value hidden from logs)")

        print("agent run complete")

    except Exception as exc:
        print("ERROR: agent run failed: %s" % exc, file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
