#!/bin/bash

echo "========================================================================"
echo "  Stopping Certificate Revocation Lab"
echo "========================================================================"
echo

podman-compose down

if [ "$1" == "--clean" ]; then
    echo
    read -p "Remove all data volumes? This will delete all certificates and data [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing volumes..."
        podman volume prune -f
        echo "✓ Volumes removed"
    fi
fi

echo
echo "✓ Lab stopped successfully"
