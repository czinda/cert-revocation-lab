#!/usr/bin/env python3
"""Check a Dogtag SSKG enrollment response for PKCS#12 data."""
import json
import sys

f = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sskg-resp.json"
d = json.load(open(f))
print("status:", d.get("requestStatus"))
print("certId:", d.get("certId"))
print("has pkcs12:", "pkcs12" in d)
print("all keys:", list(d.keys()))
for k in d:
    v = str(d[k])
    if "p12" in k.lower() or "pkcs" in k.lower() or "output" in k.lower():
        print(f"  {k}: {v[:200]}")
    if "p12" in v.lower() or "pkcs12" in v.lower():
        print(f"  {k} contains p12 ref: {v[:200]}")
