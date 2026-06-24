#!/bin/bash
# =============================================================================
# Deploy cert-revocation-lab and run validation on a provisioned machine
# =============================================================================
# Usage: ./scripts/run-tests.sh
#   env: PKI_MODE=all|rsa|ecc|pqc|dual (default: all)
#   env: GIT_BRANCH=main (default: main)
#   env: BUILD_DOGTAG=true|false (default: false) — build Dogtag from main for ML-KEM KRA
#   env: RUN_FULL_TESTS=true|false (default: false)
#
# Requires prepare-hosts.sh to have run first (needs .mrack/ansible-inventory.yaml).

set -euo pipefail
cd "$(dirname "$0")/.."

PKI_MODE="${PKI_MODE:-all}"
GIT_BRANCH="${GIT_BRANCH:-main}"
BUILD_DOGTAG="${BUILD_DOGTAG:-false}"
RUN_FULL_TESTS="${RUN_FULL_TESTS:-false}"
INVENTORY=".mrack/ansible-inventory.yaml"

if [ ! -f "$INVENTORY" ]; then
    echo "ERROR: $INVENTORY not found. Run prepare-hosts.sh first."
    exit 1
fi

echo "=== Deploying cert-revocation-lab ==="
echo "  PKI Mode:      $PKI_MODE"
echo "  Branch:        $GIT_BRANCH"
echo "  Build Dogtag:  $BUILD_DOGTAG"
echo "  Full tests:    $RUN_FULL_TESTS"
echo ""

ansible-playbook -i "$INVENTORY" \
    ansible/prepare-certlab.yml \
    -e "cert_lab_pki_mode=$PKI_MODE" \
    -e "cert_lab_repo_branch=$GIT_BRANCH" \
    -e "cert_lab_build_dogtag=$BUILD_DOGTAG"

if [ "$RUN_FULL_TESTS" = "true" ]; then
    echo ""
    echo "=== Running full test suites ==="
    # Extract the host from the mrack inventory
    CERTLAB_HOST=$(ansible-inventory -i "$INVENTORY" --list 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('certlab',{}).get('hosts',[''])[0])" 2>/dev/null || echo "")

    if [ -n "$CERTLAB_HOST" ]; then
        # RSA tests (always run)
        ssh -o StrictHostKeyChecking=no "root@$CERTLAB_HOST" \
            "cd /opt/cert-revocation-lab && sudo -u certlab ./lab test --all --pki-type rsa"
        ssh -o StrictHostKeyChecking=no "root@$CERTLAB_HOST" \
            "cd /opt/cert-revocation-lab && sudo -u certlab ./lab test-advanced --suite lifecycle --pki-type rsa"

        # PQ tests (when deployed with pqc or all mode)
        if [ "$PKI_MODE" = "pqc" ] || [ "$PKI_MODE" = "all" ] || [ "$PKI_MODE" = "dual" ]; then
            echo "=== Running PQ (ML-DSA-87) tests ==="
            if ! ssh -o StrictHostKeyChecking=no "root@$CERTLAB_HOST" \
                "cd /opt/cert-revocation-lab && sudo -u certlab ./lab test --pki-type pqc --scenario 'Certificate Private Key Compromise'"; then
                echo "WARNING: PQ test failed (exit code $?)"
            fi
        fi
    else
        echo "WARNING: Could not determine host from inventory, skipping full tests"
    fi
fi

echo ""
echo "=== Deployment complete ==="
