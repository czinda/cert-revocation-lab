#!/usr/bin/env python3
"""
KMIP Key Management CLI

Command-line tool for managing cryptographic keys via the KMIP server's
FastAPI management API. Supports key creation, activation, revocation,
destruction, rotation, and lifecycle reporting.

Usage:
    python scripts/kmip-manage.py list
    python scripts/kmip-manage.py create --name "key-name" --algorithm RSA --length 4096
    python scripts/kmip-manage.py get --uid <uid>
    python scripts/kmip-manage.py activate --uid <uid>
    python scripts/kmip-manage.py revoke --uid <uid> --reason key_compromise
    python scripts/kmip-manage.py destroy --uid <uid>
    python scripts/kmip-manage.py rotate --uid <uid> --name "new-key-name"
    python scripts/kmip-manage.py lifecycle
    python scripts/kmip-manage.py health

Environment:
    KMIP_API_URL  Base URL for the KMIP management API (default: http://localhost:8092)
"""

import argparse
import json
import os
import sys

import httpx

KMIP_API_URL = os.environ.get("KMIP_API_URL", "http://localhost:8092")


def _url(path: str) -> str:
    return f"{KMIP_API_URL}{path}"


def _print_json(data: dict) -> None:
    """Pretty-print JSON response."""
    print(json.dumps(data, indent=2))


def _handle_response(resp: httpx.Response) -> dict:
    """Check HTTP response and return parsed JSON."""
    if resp.status_code >= 400:
        print(f"Error {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(args: argparse.Namespace) -> None:
    """List all managed keys."""
    resp = httpx.get(_url("/keys"), timeout=10)
    data = _handle_response(resp)
    keys = data.get("keys", [])
    print(f"Total keys: {data.get('total', len(keys))}\n")
    for k in keys:
        uid = k.get("uid", "?")
        name = k.get("Name", k.get("name", "unnamed"))
        state = k.get("State", "unknown")
        algo = k.get("Cryptographic Algorithm", k.get("algorithm", "?"))
        print(f"  {uid}  {name:<40s}  state={state}  algo={algo}")
    if not keys:
        print("  (no keys)")


def cmd_create(args: argparse.Namespace) -> None:
    """Create a new managed key."""
    body = {
        "name": args.name,
        "algorithm": args.algorithm,
        "length": args.length,
        "usage_mask": args.usage_mask.split(",") if args.usage_mask else ["Sign", "Verify"],
    }
    if args.pki_type:
        body["pki_type"] = args.pki_type
    if args.ca_level:
        body["ca_level"] = args.ca_level

    resp = httpx.post(_url("/keys"), json=body, timeout=10)
    data = _handle_response(resp)
    print(f"Key created: uid={data['uid']}")
    _print_json(data)


def cmd_get(args: argparse.Namespace) -> None:
    """Get key details."""
    resp = httpx.get(_url(f"/keys/{args.uid}"), timeout=10)
    _print_json(_handle_response(resp))


def cmd_activate(args: argparse.Namespace) -> None:
    """Activate a key."""
    resp = httpx.post(_url(f"/keys/{args.uid}/activate"), timeout=10)
    data = _handle_response(resp)
    print(f"Key {args.uid}: {data.get('message', 'activated')}")


def cmd_revoke(args: argparse.Namespace) -> None:
    """Revoke a key."""
    body = {"reason": args.reason}
    resp = httpx.post(_url(f"/keys/{args.uid}/revoke"), json=body, timeout=10)
    data = _handle_response(resp)
    print(f"Key {args.uid}: {data.get('message', 'revoked')} (reason={args.reason})")


def cmd_destroy(args: argparse.Namespace) -> None:
    """Destroy a key."""
    resp = httpx.post(_url(f"/keys/{args.uid}/destroy"), timeout=10)
    data = _handle_response(resp)
    print(f"Key {args.uid}: {data.get('message', 'destroyed')}")


def cmd_rotate(args: argparse.Namespace) -> None:
    """Rotate a key (create new, deactivate old)."""
    body = {
        "old_key_uid": args.uid,
        "name": args.name or f"rotated-{args.uid}",
        "algorithm": args.algorithm,
        "length": args.length,
    }
    resp = httpx.post(_url("/keys/rotate"), json=body, timeout=10)
    data = _handle_response(resp)
    new_uid = data.get("new_key", {}).get("uid", "?")
    print(f"Rotation complete: old={args.uid} -> new={new_uid}")
    _print_json(data)


def cmd_lifecycle(args: argparse.Namespace) -> None:
    """Show key lifecycle summary."""
    resp = httpx.get(_url("/lifecycle"), timeout=10)
    data = _handle_response(resp)
    print(f"Key Lifecycle Summary (total: {data.get('total_keys', 0)})")
    print(f"Timestamp: {data.get('timestamp', '?')}\n")
    for state, count in data.get("lifecycle", {}).items():
        bar = "#" * count
        print(f"  {state:<25s} {count:3d}  {bar}")


def cmd_health(args: argparse.Namespace) -> None:
    """Check KMIP server health."""
    try:
        resp = httpx.get(_url("/health"), timeout=10)
        data = _handle_response(resp)
        status = data.get("status", "unknown")
        kmip = data.get("kmip_server", "unknown")
        total = data.get("total_keys", 0)
        print(f"Status: {status}")
        print(f"KMIP Server: {kmip}")
        print(f"Total Keys: {total}")
    except httpx.ConnectError:
        print("Error: Cannot connect to KMIP management API at", KMIP_API_URL, file=sys.stderr)
        sys.exit(1)


def cmd_attributes(args: argparse.Namespace) -> None:
    """Get all KMIP attributes for a key."""
    resp = httpx.get(_url(f"/keys/{args.uid}/attributes"), timeout=10)
    _print_json(_handle_response(resp))


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="KMIP Key Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list
    sub.add_parser("list", help="List all managed keys")

    # create
    p_create = sub.add_parser("create", help="Create a new managed key")
    p_create.add_argument("--name", required=True, help="Key name")
    p_create.add_argument("--algorithm", default="RSA", choices=["RSA", "AES", "ECDSA", "HMAC-SHA256"])
    p_create.add_argument("--length", type=int, default=4096, help="Key length in bits")
    p_create.add_argument("--usage-mask", default="Sign,Verify", help="Comma-separated usage masks")
    p_create.add_argument("--pki-type", help="PKI type (rsa, ecc, pq)")
    p_create.add_argument("--ca-level", help="CA level (root, intermediate, iot)")

    # get
    p_get = sub.add_parser("get", help="Get key details")
    p_get.add_argument("--uid", required=True, help="Key UID")

    # activate
    p_act = sub.add_parser("activate", help="Activate a key")
    p_act.add_argument("--uid", required=True, help="Key UID")

    # revoke
    p_rev = sub.add_parser("revoke", help="Revoke a key")
    p_rev.add_argument("--uid", required=True, help="Key UID")
    p_rev.add_argument("--reason", default="key_compromise",
                       choices=["key_compromise", "ca_compromise", "affiliation_changed",
                                "superseded", "cessation_of_operation", "privilege_withdrawn"],
                       help="Revocation reason")

    # destroy
    p_des = sub.add_parser("destroy", help="Destroy a key")
    p_des.add_argument("--uid", required=True, help="Key UID")

    # rotate
    p_rot = sub.add_parser("rotate", help="Rotate a key")
    p_rot.add_argument("--uid", required=True, help="Old key UID to rotate")
    p_rot.add_argument("--name", help="New key name (default: rotated-<uid>)")
    p_rot.add_argument("--algorithm", default="RSA", choices=["RSA", "AES", "ECDSA", "HMAC-SHA256"])
    p_rot.add_argument("--length", type=int, default=4096, help="New key length in bits")

    # attributes
    p_attr = sub.add_parser("attributes", help="Get KMIP attributes for a key")
    p_attr.add_argument("--uid", required=True, help="Key UID")

    # lifecycle
    sub.add_parser("lifecycle", help="Show key lifecycle summary")

    # health
    sub.add_parser("health", help="Check KMIP server health")

    args = parser.parse_args()

    # Dispatch to command handler
    dispatch = {
        "list": cmd_list,
        "create": cmd_create,
        "get": cmd_get,
        "activate": cmd_activate,
        "revoke": cmd_revoke,
        "destroy": cmd_destroy,
        "rotate": cmd_rotate,
        "attributes": cmd_attributes,
        "lifecycle": cmd_lifecycle,
        "health": cmd_health,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
