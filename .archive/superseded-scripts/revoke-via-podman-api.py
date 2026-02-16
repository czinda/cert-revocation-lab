#!/usr/bin/env python3
"""
Revoke certificate using Dogtag pki CLI via podman socket API.

This script is designed to run inside the EDA container which has access
to the podman socket but not the podman CLI. It uses the podman REST API
to execute the pki command inside the Dogtag CA container.

Usage:
    python3 revoke-via-podman-api.py <serial> [--ca iot] [--pki rsa] [--reason Key_Compromise]
"""

import argparse
import json
import socket
import sys


def podman_api_request(method: str, path: str, body: dict = None) -> dict:
    """Make a request to the podman socket API."""
    sock_path = "/run/podman/podman.sock"

    # Build HTTP request
    body_bytes = json.dumps(body).encode() if body else b""

    request_line = f"{method} {path} HTTP/1.1\r\n"
    headers = [
        "Host: localhost",
        "Accept: application/json",
    ]
    if body:
        headers.append("Content-Type: application/json")
        headers.append(f"Content-Length: {len(body_bytes)}")

    request = request_line + "\r\n".join(headers) + "\r\n\r\n"

    # Connect to socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)

    # Send request
    sock.sendall(request.encode() + body_bytes)

    # Read response
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        # Check if we have complete response
        if b"\r\n\r\n" in response:
            header_end = response.index(b"\r\n\r\n")
            headers_str = response[:header_end].decode()
            if "Transfer-Encoding: chunked" not in headers_str:
                # Simple response, check content-length
                for line in headers_str.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        content_length = int(line.split(":")[1].strip())
                        body_start = header_end + 4
                        if len(response) >= body_start + content_length:
                            break

    sock.close()

    # Parse response
    parts = response.split(b"\r\n\r\n", 1)
    if len(parts) < 2:
        return {"error": "Invalid response"}

    body_data = parts[1]

    # Handle chunked encoding
    if b"Transfer-Encoding: chunked" in parts[0]:
        # Simple chunked decode
        decoded = b""
        idx = 0
        while idx < len(body_data):
            line_end = body_data.find(b"\r\n", idx)
            if line_end == -1:
                break
            chunk_size = int(body_data[idx:line_end], 16)
            if chunk_size == 0:
                break
            decoded += body_data[line_end+2:line_end+2+chunk_size]
            idx = line_end + 2 + chunk_size + 2
        body_data = decoded

    try:
        return json.loads(body_data.decode())
    except json.JSONDecodeError:
        return {"raw": body_data.decode()}


def exec_in_container(container: str, command: list) -> tuple:
    """Execute a command in a container via podman API. Returns (exit_code, output)."""
    # Create exec instance
    exec_config = {
        "AttachStdout": True,
        "AttachStderr": True,
        "Cmd": command,
    }

    create_resp = podman_api_request(
        "POST",
        f"/v4.0.0/containers/{container}/exec",
        exec_config
    )

    if "Id" not in create_resp:
        return 1, f"Failed to create exec: {create_resp}"

    exec_id = create_resp["Id"]

    # Start exec
    start_resp = podman_api_request(
        "POST",
        f"/v4.0.0/exec/{exec_id}/start",
        {"Detach": False}
    )

    output = start_resp.get("raw", str(start_resp))

    # Get exec inspect for exit code
    inspect_resp = podman_api_request("GET", f"/v4.0.0/exec/{exec_id}/json")
    exit_code = inspect_resp.get("ExitCode", 1)

    return exit_code, output


def revoke_certificate(serial: str, ca_level: str = "iot", pki_type: str = "rsa",
                       reason: str = "Key_Compromise") -> bool:
    """Revoke a certificate using the pki CLI inside the Dogtag container."""

    # Map container names
    container_map = {
        "rsa": {"root": "dogtag-root-ca", "intermediate": "dogtag-intermediate-ca", "iot": "dogtag-iot-ca"},
        "ecc": {"root": "dogtag-ecc-root-ca", "intermediate": "dogtag-ecc-intermediate-ca", "iot": "dogtag-ecc-iot-ca"},
        "pqc": {"root": "dogtag-pq-root-ca", "intermediate": "dogtag-pq-intermediate-ca", "iot": "dogtag-pq-iot-ca"},
    }

    container = container_map.get(pki_type, {}).get(ca_level)
    if not container:
        print(f"ERROR: Unknown PKI type/CA level: {pki_type}/{ca_level}")
        return False

    # Normalize serial
    serial_clean = serial.lower().lstrip("0x")

    # Build the revocation command
    command = [
        "bash", "-c",
        f'''
        set -e
        CLIENT_DB=/root/.dogtag/nssdb
        CA_URL=https://localhost:8443

        ADMIN_NICK=$(certutil -L -d $CLIENT_DB 2>/dev/null | grep -i admin | head -1 | awk '{{for(i=1;i<=NF-1;i++) printf $i" "; print ""}}' | sed 's/ *$//')
        if [ -z "$ADMIN_NICK" ]; then
            echo "ERROR: Admin certificate not found"
            exit 1
        fi

        echo "Using admin cert: $ADMIN_NICK"

        pki -d $CLIENT_DB -c '' -n "$ADMIN_NICK" -U "$CA_URL" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            ca-cert-revoke 0x{serial_clean} --reason {reason} --force
        '''
    ]

    print(f"Revoking certificate 0x{serial_clean} on {container}...")
    exit_code, output = exec_in_container(container, command)

    print(output)

    if exit_code == 0:
        print("SUCCESS: Certificate revoked")
        return True
    else:
        print(f"FAILED: Exit code {exit_code}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Revoke certificate via podman API")
    parser.add_argument("serial", help="Certificate serial number (hex)")
    parser.add_argument("--ca", default="iot", choices=["root", "intermediate", "iot"],
                        help="CA level (default: iot)")
    parser.add_argument("--pki", default="rsa", choices=["rsa", "ecc", "pqc"],
                        help="PKI type (default: rsa)")
    parser.add_argument("--reason", default="Key_Compromise",
                        help="Revocation reason (default: Key_Compromise)")

    args = parser.parse_args()

    success = revoke_certificate(args.serial, args.ca, args.pki, args.reason)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
