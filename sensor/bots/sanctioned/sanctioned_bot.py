#!/usr/bin/env python3
"""Sanctioned demo bot: registered in policy.json, lives in the whitelisted dir."""
import http.client
import json
import time


def main():
    print("[BOT] sanctioned bot starting (registered, owner=platform-team)")
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
    for i in range(1, 241):
        body = json.dumps({"prompt": "draft marketing copy"}).encode()
        try:
            conn.request("POST", "/v1/chat", body,
                         {"Content-Type": "application/json"})
            r = conn.getresponse()
            r.read()
            print("[BOT] sanctioned call %d ok" % i)
        except Exception as e:
            print("[BOT] call failed: %s" % e)
            conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
        time.sleep(1)


if __name__ == "__main__":
    main()
