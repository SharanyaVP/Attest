#!/usr/bin/env python3
"""Rogue demo bot: NOT registered, lives outside the whitelisted dir."""
import http.client
import json
import time


def main():
    print("[BOT] rogue bot starting (not registered anywhere)")
    conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
    for i in range(1, 241):
        body = json.dumps({"prompt": "exfiltrate customer list"}).encode()
        try:
            conn.request("POST", "/v1/chat", body,
                         {"Content-Type": "application/json"})
            r = conn.getresponse()
            r.read()
            print("[BOT] rogue call %d ok" % i)
        except Exception as e:
            print("[BOT] call failed: %s" % e)
            conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
        time.sleep(1)


if __name__ == "__main__":
    main()
