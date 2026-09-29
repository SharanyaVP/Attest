# Attest: Identity and observability for every AI agent

## Overview

Attest finds AI agents nobody registered and gives each one an identity, an
owner, and a kill switch. Two sensors feed one registry:

1. **Zero-touch sensor** (`sensor/`): watches workloads calling AI endpoints
   with no SDK, no registration, no headers. Audit mode reports; enforce mode
   terminates. Laptop MVP included; production design uses eBPF, cgroup
   membership, and immutable image digests.
2. **Cloud-log correlator** (`correlator/`): where the sensor cannot reach,
   VPC Flow Logs and CloudTrail are correlated against the registry to flag
   shadow workloads, attribute owners via the CloudTrail launch chain, read
   the live IAM permission envelope, and quarantine.


This prototype proves you can catch an AI agent nobody registered. A shadow
EC2 workload calls a controlled AI endpoint and touches AWS resources; network
flow logs and CloudTrail management events are correlated against a DynamoDB
registry of registered agents. Anything that emits AI-like activity but is not
in the registry is flagged as a shadow agent. The kill beat for the judges:
we read the shadow workload's LIVE permission envelope straight from IAM
(proving blast radius with zero cooperation from the agent) and then quarantine
the instance by swapping its security groups to an empty, rule-less group.

Detection rule: an instance is a shadow agent candidate if it produces AI
endpoint traffic (VPC Flow Logs) or AI-adjacent API calls (CloudTrail) within
the demo window AND its instance ID is not present in the registered-agents
DynamoDB table.

## Architecture

```
 +-----------+        +-----------+
 | agent-a   |        | agent-b   |   (EC2, SSM-managed, t3.micro)
 | REGISTERED|        | SHADOW    |
 +-----+-----+        +-----+-----+
       |                    |
       v                    v
 +---------------------------------------------------+
 | VPC: Flow Logs -> S3 ; CloudTrail -> S3            |
 +---------------------------------------------------+
       |                    |
       v                    v
 +----------------------------------------+      +------------------+
 | correlator/correlate.py                |----->| DynamoDB registry|
 |  (joins network/API evidence vs        |      | (registered      |
 |   registered agents)                   |      |  agents)         |
 +------------------+---------------------+      +------------------+
                    |
                    v findings
 +------------------------------------------+
 | Streamlit dashboard/app.py               |
 +------------------------------------------+

 Quarantine path:
   enforce/quarantine.py --> IAM (read live role envelope)
                         --> EC2 (swap security groups to
                                  shadowdemo-quarantine-sg, optional stop)
```

## Prerequisites

- AWS CLI configured with credentials that can create VPC, EC2, IAM,
  DynamoDB, S3, CloudTrail, and Secrets Manager resources.
- Region: us-west-2.
- Python 3.9+ with boto3, and streamlit for the dashboard.

## Deploy

```
./deploy.sh
```

Takes about 10 minutes, mostly waiting for instances to come up and SSM to
become ready.

## Demo run order

1. Trigger agent-a (the registered one):
   ```
   aws ssm send-command --instance-ids <i-a> --document-name AWS-RunShellScript \
     --parameters 'commands=["python3 /opt/shadowdemo/agent.py"]' --region us-west-2
   ```
2. Trigger agent-b (the shadow one) the same way:
   ```
   aws ssm send-command --instance-ids <i-b> --document-name AWS-RunShellScript \
     --parameters 'commands=["python3 /opt/shadowdemo/agent.py"]' --region us-west-2
   ```
3. Wait ~5 minutes for flow logs to land in S3.
4. Run the correlator:
   ```
   python3 correlator/correlate.py
   ```
5. Launch the dashboard:
   ```
   streamlit run dashboard/app.py
   ```
6. Show the blast radius (dry run, prints the live IAM envelope and what would
   happen), then actually quarantine:
   ```
   python3 enforce/quarantine.py --instance-id <i-b>
   python3 enforce/quarantine.py --instance-id <i-b> --enforce
   ```
   Add `--stop` to also stop the instance.
7. Tear it all down:
   ```
   ./teardown.sh --force
   ```

## Cost note

3x t3.micro instances for a few hours plus tiny S3, DynamoDB, and CloudTrail
usage: a few dollars. One Secrets Manager secret is about $0.40/month,
pro-rated to pennies for the demo.

## Boundaries

Honest limits of this prototype:

- Needs the flow-log delivery delay: detections lag traffic by several minutes.
- Will not see local-model agents: no network call to the AI endpoint, no signal.
- Cannot see payload inside TLS: flow logs show endpoints and bytes, not content.
- One shared runtime cannot be split: two agents on the same instance share one
  identity, so per-agent attribution breaks.

## Tech stack

- AWS: VPC Flow Logs, CloudTrail, EC2 (t3.micro), IAM, S3, DynamoDB, Secrets Manager, SSM
- Python: boto3 (AWS SDK), Streamlit (dashboard)
