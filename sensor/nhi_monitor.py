#!/usr/bin/env python3
"""
Attest zero-touch sensor (laptop MVP).

Watches for processes calling AI endpoints with zero cooperation from the
workloads: no SDK, no registration, no headers.

MVP identity: script path + file hash. This is spoofable; it proves the
workflow, not production-grade identity. Production uses eBPF, cgroup
membership, and immutable image digests (see sensor/README.md).

Modes (policy.json): "audit" reports only; "enforce" terminates.
"""

import hashlib
import json
import os
import sys
import time

try:
    import psutil
except ImportError:
    print("psutil is required: pip3 install psutil")
    sys.exit(1)

HERE = os.path.dirname(os.path.abspath(__file__))


def load_policy():
    with open(os.path.join(HERE, "policy.json")) as fh:
        return json.load(fh)


def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return "unreadable"


def script_of(proc):
    """Absolute script path for a python process, or None."""
    try:
        cmd = proc.cmdline()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    if not cmd:
        return None
    for arg in cmd[1:]:
        if arg.endswith(".py") and os.path.isfile(arg):
            return os.path.abspath(arg)
    return None


def is_python(proc):
    try:
        name = proc.name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False
    return "python" in name


def ai_connections(proc, ai_host, ai_port):
    try:
        try:
            conns = proc.net_connections(kind="inet")
        except AttributeError:
            conns = proc.connections(kind="inet")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []
    hits = []
    for c in conns:
        if not c.raddr:
            continue
        rhost, rport = c.raddr[0], c.raddr[1]
        if rport == ai_port and (ai_host == "0.0.0.0" or rhost == ai_host):
            hits.append(c)
    return hits


def whitelisted(script_path, policy):
    rp = os.path.realpath(script_path)
    for d in policy.get("whitelisted_dirs", []):
        ad = os.path.realpath(os.path.join(HERE, d))
        if rp == ad or rp.startswith(ad + os.sep):
            return True
    return False


def main():
    policy = load_policy()
    mode = policy.get("mode", "audit")
    ai_host = policy.get("ai_host", "127.0.0.1")
    ai_port = policy.get("ai_port", 18080)
    poll = policy.get("poll_seconds", 2)
    registry = policy.get("registry", {})
    me = os.getpid()

    print("[ATTEST] zero-touch sensor starting")
    print("[ATTEST] mode=%s ai_endpoint=%s:%s" % (mode, ai_host, ai_port))
    print("[ATTEST] watching for unregistered AI callers (no SDK required)")
    seen = {}
    try:
        while True:
            for proc in psutil.process_iter(["pid", "name"]):
                pid = proc.info["pid"]
                if pid == me or pid in seen:
                    continue
                if not is_python(proc):
                    continue
                hits = ai_connections(proc, ai_host, ai_port)
                if not hits:
                    continue
                script = script_of(proc)
                ident = script or "<unknown script>"
                fp = file_hash(script) if script else "-"
                if script and whitelisted(script, policy):
                    reg = registry.get(os.path.relpath(script, HERE), {})
                    owner = reg.get("owner", "unknown")
                    print("[ATTEST] authorized: %s owner=%s fp=%s"
                          % (ident, owner, fp))
                else:
                    print("[ATTEST] SHADOW CANDIDATE: %s fp=%s called %s:%s"
                          % (ident, fp, ai_host, ai_port))
                    if mode == "enforce":
                        try:
                            proc.terminate()
                            print("[ATTEST] enforced: terminated pid %d (%s)"
                                  % (pid, ident))
                        except (psutil.NoSuchProcess,
                                psutil.AccessDenied) as e:
                            print("[ATTEST] enforce failed for pid %d: %s"
                                  % (pid, e))
                    else:
                        print("[ATTEST] audit mode: no action taken")
                seen[pid] = True
            for pid in list(seen):
                if not psutil.pid_exists(pid):
                    del seen[pid]
            time.sleep(poll)
    except KeyboardInterrupt:
        print("\n[ATTEST] sensor stopped")


if __name__ == "__main__":
    main()
