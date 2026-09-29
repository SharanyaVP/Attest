# Attest zero-touch sensor (laptop MVP)

Finds AI-calling workloads with zero cooperation: no SDK, no registration,
no headers. It watches process-level network connections via psutil and
checks each AI caller's script identity against the whitelist in policy.json.

Run order: 1) sensor/ai_stub.py  2) sensor/nhi_monitor.py
3) sensor/bots/sanctioned/sanctioned_bot.py (authorized)
4) sensor/bots/rogue/rogue_bot.py (shadow candidate)

Flip "mode" in policy.json from "audit" to "enforce" and restart the sensor
to watch it terminate the rogue bot.

Honest limitation: the laptop MVP identifies a workload by script path and
file hash, which is spoofable. It proves the workflow, not production-grade
identity. Production uses eBPF, cgroup membership, Kubernetes metadata, and
immutable image digests.
